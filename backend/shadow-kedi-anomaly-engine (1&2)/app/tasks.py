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
