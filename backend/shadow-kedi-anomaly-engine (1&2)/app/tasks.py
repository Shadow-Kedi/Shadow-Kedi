"""Celery entry point. Feed this from an OpenSearch/Wazuh adapter, not directly from the UI."""
import logging
from celery import Celery
from celery.schedules import crontab

# Explicit rather than relying on Celery's own root-logger hijacking (which is
# a `--loglevel` side effect, not guaranteed): makes shadow_kedi.adapter's
# warnings (skipped rows during SecurityEvent adaptation) visible in
# `docker compose logs worker`/`beat` regardless of Celery CLI flags.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
from .baselines import build_baselines
from .config import settings
from .event_adapter import recompute_baselines_from_canonical_events
from .models import SecurityEvent
from .database import SessionLocal
from .repository import save_baselines

celery_app = Celery("shadow_kedi", broker=settings().celery_broker_url, backend=settings().celery_result_backend)
celery_app.conf.timezone = "UTC"

# Daily cadence matches settings().baseline_window_days (7): a 7-day window
# means one missed/delayed beat tick doesn't meaningfully skew anything, and
# daily is frequent enough to keep baselines current without recomputing on
# every event. 02:00 UTC is arbitrary but fixed -- celery beat's default
# PersistentScheduler just tracks last-run time, so a fixed hour keeps "when
# did this last run" predictable across restarts rather than drifting.
celery_app.conf.beat_schedule = {
    "recompute-baselines-daily": {
        "task": "app.tasks.recompute_baselines_from_live_data",
        "schedule": crontab(hour=2, minute=0),
    },
    # Offset from baselines (02:00) so the two don't contend for the same
    # DB rows/CPU at once -- no dependency between them either way.
    "recompute-shadow-kedi-ml-scores-daily": {
        "task": "app.tasks.recompute_shadow_kedi_ml_scores",
        "schedule": crontab(hour=3, minute=0),
    },
}


@celery_app.task
def recompute_baselines(normalized_events: list[dict]) -> dict[str, int]:
    """Manual/backfill path: the caller already has trailing-window data
    normalized into SecurityEvent shape and passes it directly. Not on any
    schedule and not currently called by anything in this repo (confirmed
    during the Step 0 inspection) -- kept for manual/backfill use. See
    recompute_baselines_from_live_data below for the real, schedule-driven
    path that reads canonical_events itself and needs no caller-supplied data.
    """
    cfg = settings()
    events = [SecurityEvent.model_validate(event) for event in normalized_events]
    users, peers = build_baselines(events, cfg.domain_hash_key)
    with SessionLocal() as session:
        save_baselines(session, users, peers)
    return {"users_recomputed": len(users), "departments_recomputed": len(peers)}


@celery_app.task
def recompute_baselines_from_live_data() -> dict[str, int]:
    """Scheduled daily via beat_schedule above. Reads real canonical_events
    through event_adapter's CanonicalEventRow -> SecurityEvent bridge -- no
    caller needs to supply events. This is the task that actually keeps
    user_baselines/peer_baselines up to date against live Wazuh data.
    """
    cfg = settings()
    with SessionLocal() as session:
        return recompute_baselines_from_canonical_events(session, cfg.domain_hash_key, cfg.baseline_window_days)


@celery_app.task
def recompute_shadow_kedi_ml_scores() -> dict[str, int]:
    """Scheduled daily via beat_schedule above (offset to 03:00, after
    baselines). Runs the ML/Data-Engineering pipeline's trained day-level
    classifier (repo root: pipeline/, bridged via app/ml_scoring.py and
    shadow_kedi_adapter.py) against the trailing window of
    canonical_events, alongside -- not instead of -- this task's own
    per-event heuristic detectors (orchestrator.py). See
    app/ml_scoring.py's module docstring for exactly how the two are
    combined (same anomaly_scores table, one "driver event" per user-day
    overwritten, every other event untouched).

    Import is INSIDE the task body, not at module top, deliberately: the
    ML bridge needs pipeline/ (repo root, outside this service's own
    package) plus joblib/pandas/scikit-learn importable, and neither is
    guaranteed in every environment this module gets imported in (see
    ml_scoring.py's own SHADOW_KEDI_PIPELINE_ROOT handling). A bad import
    here must not be able to crash Celery worker/beat STARTUP -- which
    would also kill recompute_baselines_from_live_data above, a task with
    no relationship to the ML pipeline at all. Deferring the import to
    call time means that failure mode is scoped to just this one task.

    Also requires a trained model file at SHADOW_KEDI_MODEL_PATH (default
    <repo root>/data/models/ga_optimized_classifier.joblib). That file is
    NOT part of this repo -- it's produced by pipeline/genetic_optimizer.py
    from the ML/Data Engineering role's own CERT r4.2 + CASB training run,
    and has to be supplied (committed under data/models/, or mounted in)
    before this task can score anything. Until it's present, this logs a
    clear warning and returns without touching anomaly_scores, rather than
    raise and crash-loop every beat tick.
    """
    logger = logging.getLogger("shadow_kedi.ml_scoring")
    try:
        from .ml_scoring import recompute_shadow_kedi_scores
    except ImportError as exc:
        logger.warning(
            "Skipping ML pipeline scoring -- pipeline/ (repo root) or one of "
            "its dependencies (joblib/pandas/scikit-learn) isn't importable "
            "in this environment: %s", exc,
        )
        return {"skipped": "pipeline_not_importable"}

    try:
        with SessionLocal() as session:
            return recompute_shadow_kedi_scores(session)
    except FileNotFoundError as exc:
        logger.warning(
            "Skipping ML pipeline scoring -- no trained model found: %s. "
            "Expected until the trained .joblib is supplied.", exc,
        )
        return {"skipped": "model_not_found"}
