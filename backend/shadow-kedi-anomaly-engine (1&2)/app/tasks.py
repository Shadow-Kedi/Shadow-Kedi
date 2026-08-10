"""Celery entry point. Feed this from an OpenSearch/Wazuh adapter, not directly from the UI."""
from celery import Celery
from .baselines import build_baselines
from .config import settings
from .models import SecurityEvent
from .database import SessionLocal
from .repository import save_baselines

celery_app = Celery("shadow_kedi", broker=settings().celery_broker_url, backend=settings().celery_result_backend)


@celery_app.task
def recompute_baselines(normalized_events: list[dict]) -> dict[str, int]:
    """Nightly task. The caller queries trailing-window Wazuh data and passes normalized events."""
    cfg = settings()
    events = [SecurityEvent.model_validate(event) for event in normalized_events]
    users, peers = build_baselines(events, cfg.domain_hash_key)
    with SessionLocal() as session:
        save_baselines(session, users, peers)
    return {"users_recomputed": len(users), "departments_recomputed": len(peers)}
