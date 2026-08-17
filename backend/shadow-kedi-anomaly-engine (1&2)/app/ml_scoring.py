# app/ml_scoring.py
"""
ML pipeline scoring integration -- bridges the ML/Data Engineering
pipeline (repo root: pipeline/) into this service's own event/scoring
tables, so the trained, real-data-validated day-level model contributes
alongside (not instead of) orchestrator.py's own per-event heuristic
detectors.

WHY THIS FILE EXISTS, AND TWO DECISIONS MADE WITHOUT TEAM REVIEW

Written with both other roles unavailable. Two real design decisions
were made unilaterally here that would normally go back to the team
first (matching this codebase's own stated norm in orchestrator.py:
"IMPORTANT, flagging per 'tell me before changing shape'") -- flagged
clearly rather than silently baked in, so they're easy to revisit:

1. WHERE RESULTS GET WRITTEN: into the SAME anomaly_scores table
   orchestrator.py already writes to (AnomalyScoreRow), not a separate
   table. Reasoning: api.py's every read path (_load_score_map,
   _event_to_alert_dict, and everything that calls them -- overview,
   alerts, alert detail, user detail, leaderboard) already keys off this
   ONE table by event_id. A separate table would need every one of
   those call sites modified to merge a second lookup; writing into the
   existing table means every endpoint picks up ML-pipeline results
   automatically, with zero changes to api.py. The trade-off this
   creates: see point 2.

2. WHAT HAPPENS TO THE DRIVER EVENT'S EXISTING SCORE: this pipeline
   scores per (user, day), not per event -- same mismatch already
   diagnosed in this project's own risk_engine.py, solved there via a
   "driver event" concept (the single event that most drove that day's
   score). Applied the same way here: for each scored user-day, ONE
   event (the day's Wazuh-highest-rule_level event -- see
   _pick_driver_event) gets its AnomalyScoreRow OVERWRITTEN with the ML
   pipeline's day-level result. Every OTHER event that day keeps
   orchestrator.py's own per-event heuristic score untouched. This is a
   deliberate choice, not an accident of write ordering: the driver
   event is by definition the day's most significant one, and this
   project's own real-data validation (F1=0.9653 on held-out users,
   documented in Shadow_Kedi_ML_Methodology_Professional.md) is a
   substantially more validated signal than a single per-event heuristic
   score for that specific event. Non-driver events are deliberately
   left alone -- most of a day's events genuinely are mundane, which is
   the exact finding (window-based-label dilution) this whole pipeline
   was built to address; overwriting every event that day would
   reintroduce the problem this design already solved.

WHAT THIS FILE DOES NOT DO

Does not touch baselines.py, detectors.py, or event_adapter.py -- same
"don't touch the internals" boundary orchestrator.py itself observes.
Does not modify api.py -- not needed, per decision 1 above. Does not
change wazuh_connector.py's metadata_json shape beyond what's already
been added there (win_eventdata) -- see that file's own inline note.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import AnomalyScoreRow, CanonicalEventRow

logger = logging.getLogger("shadow_kedi.ml_scoring")

# --- making the repo-root pipeline package importable from here ------------
# pipeline/ lives at the repo root, a sibling of this file's own
# backend/<...>/app/ directory, not an installed package. Configurable via
# env var rather than a hardcoded relative path, since the exact nesting
# depends on how this service is actually deployed (bare checkout vs
# Docker image layout) -- default assumes app/ -> <anomaly-engine dir> ->
# backend/ -> repo root (3 levels up). VERIFY THIS against your actual
# deployment before relying on it; adjust SHADOW_KEDI_PIPELINE_ROOT if
# your layout differs.
import os

_PIPELINE_ROOT = os.environ.get(
    "SHADOW_KEDI_PIPELINE_ROOT",
    str(Path(__file__).resolve().parents[3]),
)
if _PIPELINE_ROOT not in sys.path:
    sys.path.insert(0, _PIPELINE_ROOT)

try:
    from pipeline.scorer import ShadowKediScorer
    from pipeline.recommendation_tier import recommend_tier
except ImportError as exc:
    raise ImportError(
        f"Could not import the ML pipeline from SHADOW_KEDI_PIPELINE_ROOT="
        f"{_PIPELINE_ROOT!r}. Set that env var to your actual repo root, "
        f"or verify pipeline/ is present there. Original error: {exc}"
    ) from exc

from shadow_kedi_adapter import canonical_rows_to_daily_features  # repo root, not app/ -- see its own module docstring

# Model path is similarly configurable -- the trained .joblib must be
# present wherever this service actually runs (committed to the repo
# under data/models/, or mounted in). VERIFY this file exists in your
# deployment; ShadowKediScorer raises a clear FileNotFoundError if not.
_MODEL_PATH = os.environ.get(
    "SHADOW_KEDI_MODEL_PATH",
    str(Path(_PIPELINE_ROOT) / "data" / "models" / "ga_optimized_classifier.joblib"),
)

# risk_category (Informational/Low/Medium/High/Critical) has no
# "informational" slot in this service's own 4-value severity type (see
# orchestrator.py's _severity docstring: "the dashboard's TYPE SHAPE...
# requires exactly the 4-value vocabulary"). Informational days are
# SKIPPED entirely (see recompute_shadow_kedi_scores below) rather than
# force-mapped -- same exclusion this project's own
# export_alerts_for_dashboard.py already applies for the same reason.
_SEVERITY_MAP = {"Low": "low", "Medium": "medium", "High": "high", "Critical": "critical"}


def _pick_driver_event(rows: list[CanonicalEventRow]) -> CanonicalEventRow:
    """The event this day's ML score gets attached to (see module
    docstring, decision 2). Picks the row with the highest Wazuh
    rule_level as the best available proxy for "most significant event
    that day" -- Wazuh's own severity opinion, already present on every
    row, rather than inventing a new heuristic. Ties broken by most
    recent occurred_at (arbitrary but deterministic)."""
    def sort_key(row):
        level = (row.metadata_json or {}).get("rule_level") or 0
        return (level, row.occurred_at)
    return max(rows, key=sort_key)


def _group_by_user_day(rows: list[CanonicalEventRow]) -> dict:
    groups: dict[tuple[str, object], list[CanonicalEventRow]] = {}
    for row in rows:
        key = (row.user_id, row.occurred_at.date())
        groups.setdefault(key, []).append(row)
    return groups


def score_user_day(scorer: "ShadowKediScorer", rows: list[CanonicalEventRow]) -> dict | None:
    """Scores one user's one day of events. Returns None for a day the
    model scores Informational (deliberately not written -- see
    _SEVERITY_MAP note above), otherwise a dict ready for
    save_ml_result()."""
    daily_features = canonical_rows_to_daily_features(rows, scorer.feature_cols)
    result = scorer.score_daily_features(daily_features)
    risk_category = result["risk_category"]

    if risk_category not in _SEVERITY_MAP:
        return None  # Informational -- not worth surfacing, matches export_alerts_for_dashboard.py's own exclusion

    tier_result = recommend_tier(risk_category=risk_category)
    driver = _pick_driver_event(rows)
    score_0_100 = round(result["risk_score"] * 100)

    finding = {
        # Matches app/models.py's Anomaly shape exactly (signal/score/
        # severity/explanation/evidence) so api.py's existing
        # evidence-building code (finding["signal"], finding["explanation"])
        # renders this correctly without any api.py changes.
        "signal": "ml_pipeline_daily_risk",
        "score": score_0_100,
        "severity": _SEVERITY_MAP[risk_category],
        "explanation": (
            f"ML pipeline day-level risk assessment: {risk_category} "
            f"({len(rows)} events this day, driver event {driver.event_id}). "
            f"{tier_result['label']}."
        ),
        "evidence": {
            "daily_event_count": len(rows),
            "driver_event_id": driver.event_id,
            "raw_model_probability": round(result["risk_score"], 4),
        },
    }

    return {
        "event_id": driver.event_id,
        "score": score_0_100,
        "severity": _SEVERITY_MAP[risk_category],
        "tier": tier_result["tier"],
        "recommendation": f"{tier_result['label']}. {tier_result['explanation']}",
        "findings_json": [finding],
        "confidence": 1.0,  # this model's validation is population-level (F1=0.9653 held-out), not a per-user warm-up concept like sample_days below
        "sample_days": None,  # not applicable to this model -- see confidence note
        "computed_at": datetime.now(UTC),
    }


def save_ml_result(session: Session, result: dict) -> None:
    """Same upsert pattern as orchestrator.py's save_result() -- get-or-
    create by event_id, overwrite fields, commit. DELIBERATELY overwrites
    whatever orchestrator.py's own per-event scoring already wrote for
    this specific event_id -- see module docstring, decision 2, for why
    this is intentional and scoped to only the driver event."""
    row = session.get(AnomalyScoreRow, result["event_id"]) or AnomalyScoreRow(event_id=result["event_id"])
    row.score = result["score"]
    row.severity = result["severity"]
    row.tier = result["tier"]
    row.recommendation = result["recommendation"]
    row.findings_json = result["findings_json"]
    row.confidence = result["confidence"]
    row.sample_days = result["sample_days"]
    row.computed_at = result["computed_at"]
    session.add(row)
    session.commit()


def recompute_shadow_kedi_scores(session: Session, window_days: int = 7) -> dict[str, int]:
    """Real entry point -- query the trailing window of canonical_events,
    group by (user_id, day), score each group, write results. Mirrors
    event_adapter.py's recompute_baselines_from_canonical_events()
    structure and window_days default deliberately, for the same
    reasoning it already documents (a 7-day window means one missed/
    delayed beat tick doesn't meaningfully skew anything)."""
    cutoff = datetime.now(UTC) - timedelta(days=window_days)
    rows = session.execute(
        select(CanonicalEventRow).where(CanonicalEventRow.occurred_at >= cutoff)
    ).scalars().all()

    if not rows:
        return {"events_considered": 0, "user_days_scored": 0, "user_days_informational_skipped": 0}

    scorer = ShadowKediScorer(model_path=_MODEL_PATH)
    groups = _group_by_user_day(rows)

    scored, skipped = 0, 0
    for (user_id, day), day_rows in groups.items():
        try:
            result = score_user_day(scorer, day_rows)
        except ValueError as exc:
            # Missing-feature error from ShadowKediScorer -- logged, not
            # raised, so one malformed user-day doesn't abort the whole run.
            logger.warning("Skipping user_id=%s day=%s: %s", user_id, day, exc)
            continue

        if result is None:
            skipped += 1
            continue
        save_ml_result(session, result)
        scored += 1

    return {
        "events_considered": len(rows),
        "user_days_scored": scored,
        "user_days_informational_skipped": skipped,
    }
