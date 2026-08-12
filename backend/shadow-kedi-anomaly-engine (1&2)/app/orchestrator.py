"""Orchestrator: combines detect()'s per-signal Anomaly findings into a single
0-100 risk score + human-readable explanation, and persists the result.

Pipeline shape, per the project brief: Event -> Baseline -> [Time + Volume +
Domain + Peer] -> Orchestrator -> Anomaly Score + Explanation. This module is
the last box. build_baselines()/detect() (baselines.py/detectors.py) and the
CanonicalEventRow -> SecurityEvent bridge (event_adapter.py) are untouched --
same "don't touch the internals" boundary as Step 1.

This replaces api.py's old _derive_severity_and_score, which derived
severity/score purely from Wazuh's own rule_level -- a heuristic, not real
behavioral anomaly detection. This module is the real thing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .config import Settings
from .database import AnomalyScoreRow, CanonicalEventRow
from .detectors import detect
from .event_adapter import TENANT_DEFAULT_DEPARTMENT, to_security_event
from .models import Anomaly
from .repository import get_peer_baseline, get_user_baseline

# --- combining multiple simultaneously-fired signals into one score --------
# max() across fired signals' scores -- not a weighted sum, not an average.
#
# Why: with only Time Anomaly realistically live today (Volume/New-Domain are
# dormant per Step 1's adapter decisions; Peer Comparison is real but
# single-cohort), max() degrades perfectly to "just surface the one real
# signal cleanly" -- it's a no-op when there's exactly one finding. A sum or
# weighted average would need a calibrated weighting scheme we have no
# multi-signal data to tune, and risks a misleadingly inflated score from
# several weak signals piling up (e.g. new_domain's flat 35 stacking with a
# borderline peer_comparison into a number neither alone would justify).
# max() is also the most transparent choice to explain to a human reviewer:
# "the score IS the strongest single piece of evidence, here's what it was" --
# consistent with the dashboard's own framing that signals support a human
# decision rather than accumulate into a verdict. Revisit this once multiple
# signals routinely co-fire and independent corroboration should count for
# something.
def _combine(anomalies: list[Anomaly]) -> tuple[int, Anomaly | None]:
    if not anomalies:
        return 0, None
    primary = max(anomalies, key=lambda a: a.score)
    return primary.score, primary


# --- confidence dampening for limited baseline history ---------------------
# UserBaseline.sample_days was already computed and stored in Step 1 but never
# consumed anywhere -- this is the confidence gate explicitly deferred from
# Step 1 to here.
#
# Linear ramp from a 0.4 floor (not 0.0) up to 1.0 at sample_days >= 7 (a full
# rolling window). Reasoning: a 1-day-old baseline is still real signal, not
# nothing -- suppressing it to a 0 score would make Time Anomaly invisible for
# every new user's first week, which is useless for triage. But it also
# shouldn't be trusted exactly as much as a mature week of history --
# overclaiming certainty is its own failure mode. The 0.4 floor means even a
# brand-new baseline's finding is visible (never fully zeroed while genuinely
# anomalous), just visibly discounted. No baseline at all (true cold start)
# returns confidence 0, which is moot in practice since detect() already
# returns no findings for a user with no baseline at all.
def _confidence(sample_days: int | None) -> float:
    if not sample_days or sample_days <= 0:
        return 0.0
    return round(min(1.0, 0.4 + 0.6 * min(sample_days, 7) / 7), 2)


# --- 0-100 score -> severity/tier vocabulary --------------------------------
# IMPORTANT, flagging per "tell me before changing shape": these are NEW
# boundaries, not the old rule_level-based _derive_severity_and_score's
# numbers, and not the same thresholds as detectors.py's own internal
# _severity() (which only labels individual signals -- high/medium/low, no
# "critical" -- and stays untouched, used only for that narrower per-signal
# purpose inside detectors.py/Anomaly.severity). The dashboard's TYPE SHAPE is
# unchanged: it requires exactly the 4-value vocabulary {low, medium, high,
# critical} (CSS classes, the critical-pulse animation, severity-mix charts),
# and that vocabulary is preserved here. The boundaries are new because the
# entire scoring mechanism is new -- there was no way to keep the old
# thresholds meaningful against a completely different scoring method. Tune
# these if the resulting alert mix doesn't match expectations.
def _severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# Mirrors the old scheme's intent (low->R2, medium->R3, high->R4,
# critical->R6, R5 unused) without inheriting its rule_level arithmetic. R1 is
# reserved for "genuinely no signal fired" (score == 0) specifically, kept
# distinct from R2 ("something fired, but minor") -- same distinction the old
# scheme drew between its unmatched-event-type fallback and a real low tier.
_TIER_BY_SEVERITY = {"critical": "R6", "high": "R4", "medium": "R3", "low": "R2"}

_ACTION_BY_SEVERITY = {
    "critical": "Escalate to security for human review. Do not take automated enforcement action.",
    "high": "Flag for analyst review.",
    "medium": "Review when convenient.",
    "low": "No action required; retained for context.",
}


def _recommendation(severity: str, primary: Anomaly | None, confidence: float) -> str:
    """Human-readable, references the actual fired signal's own explanation
    text (per your instruction: surface detect()'s explanation, don't
    regenerate it) rather than a generic "review manually" placeholder."""
    if primary is None:
        return "No anomaly signals identified for this event. Review manually if warranted."
    note = f" (baseline confidence {confidence:.0%} -- limited history, treat with extra caution)" if confidence < 0.9 else ""
    return f"{_ACTION_BY_SEVERITY[severity]} {primary.explanation}{note}"


@dataclass(frozen=True)
class OrchestratorResult:
    event_id: str
    score: int
    severity: str
    tier: str
    recommendation: str
    findings: list[Anomaly]
    confidence: float
    sample_days: int | None
    computed_at: datetime


def score_event(session: Session, row: CanonicalEventRow, cfg: Settings) -> OrchestratorResult:
    """Run Event -> Baseline -> Detectors -> Orchestrator for one already-
    persisted CanonicalEventRow. Pure computation -- does not persist; see
    save_result()/score_and_persist() below. May raise pydantic's
    ValidationError from the adapter (e.g. a too-short user_id) -- same
    tolerance contract as event_adapter.py, callers should catch per-event."""
    security_event = to_security_event(row)
    user_baseline = get_user_baseline(session, row.user_id)
    peer_baseline = get_peer_baseline(session, TENANT_DEFAULT_DEPARTMENT)
    findings = detect(security_event, user_baseline, peer_baseline, cfg)

    raw_score, primary = _combine(findings)
    sample_days = user_baseline.sample_days if user_baseline else None
    confidence = _confidence(sample_days)
    # Severity/tier are derived from the DAMPENED score, not the raw one --
    # showing e.g. "49/100" next to a "critical" badge would look like a bug.
    # Confidence dampening has to be visible in both fields consistently.
    score = round(raw_score * confidence)
    severity = _severity(score)
    tier = _TIER_BY_SEVERITY[severity] if score > 0 else "R1"

    return OrchestratorResult(
        event_id=row.event_id,
        score=score,
        severity=severity,
        tier=tier,
        recommendation=_recommendation(severity, primary, confidence),
        findings=findings,
        confidence=confidence,
        sample_days=sample_days,
        computed_at=datetime.now(UTC),
    )


def save_result(session: Session, result: OrchestratorResult) -> None:
    row = session.get(AnomalyScoreRow, result.event_id) or AnomalyScoreRow(event_id=result.event_id)
    row.score, row.severity, row.tier = result.score, result.severity, result.tier
    row.recommendation = result.recommendation
    row.findings_json = [f.model_dump() for f in result.findings]
    row.confidence, row.sample_days, row.computed_at = result.confidence, result.sample_days, result.computed_at
    session.add(row)
    session.commit()


def get_result(session: Session, event_id: str) -> AnomalyScoreRow | None:
    return session.get(AnomalyScoreRow, event_id)


def score_and_persist(session: Session, row: CanonicalEventRow, cfg: Settings) -> OrchestratorResult:
    """Convenience wrapper used by both ingest-time scoring (api.py) and the
    backfill script (scripts/backfill_anomaly_scores.py) so there's exactly
    one score-then-save code path."""
    result = score_event(session, row, cfg)
    save_result(session, result)
    return result
