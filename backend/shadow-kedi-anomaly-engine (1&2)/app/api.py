from datetime import UTC, datetime, timedelta
from fastapi import FastAPI, Header, HTTPException, status
from .baselines import build_baselines
from .config import settings
from .database import SessionLocal, initialise_database
from .detectors import detect
from .models import BaselineRequest, EvaluationResponse, SecurityEvent
from .repository import get_peer_baseline, get_user_baseline, save_baselines
from .ingest import ingest_event
from .platform_models import CanonicalEvent, IngestResult
from .redaction import redact_log_value
import logging

app = FastAPI(title="Shadow Kedi anomaly engine", version="0.1.0")
logger = logging.getLogger("shadow_kedi.ingest")


@app.on_event("startup")
def startup() -> None:
    initialise_database()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/events", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
def receive_event(
    event: CanonicalEvent,
    x_ingest_key: str = Header(default=""),
    x_tenant_id: str = Header(default=""),
) -> IngestResult:
    """Service-only intake endpoint; browser clients must not call it."""
    cfg = settings()
    if x_ingest_key != cfg.ingest_api_key:
        raise HTTPException(status_code=401, detail="Invalid ingest credential")
    if x_tenant_id != event.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant header does not match payload")
    with SessionLocal() as session:
        result = ingest_event(session, event)
    logger.info("ingest status=%s event_id=%s tenant=%s", result.status, event.event_id, redact_log_value(event.tenant_id))
    return result


@app.post("/baselines/recompute")
def recompute(request: BaselineRequest) -> dict[str, int]:
    cfg = settings()
    cutoff = datetime.now(UTC) - timedelta(days=cfg.baseline_window_days)
    events = [event for event in request.events if event.occurred_at >= cutoff]
    if not events:
        raise HTTPException(422, "No events inside the configured baseline window")
    users, peers = build_baselines(events, cfg.domain_hash_key)
    with SessionLocal() as session:
        save_baselines(session, users, peers)
    return {"users_recomputed": len(users), "departments_recomputed": len(peers)}


@app.post("/anomalies/evaluate", response_model=EvaluationResponse)
def evaluate(event: SecurityEvent) -> EvaluationResponse:
    cfg = settings()
    with SessionLocal() as session:
        user = get_user_baseline(session, event.user_id)
        peer = get_peer_baseline(session, event.department)
    return EvaluationResponse(user_id=event.user_id, anomalies=detect(event, user, peer, cfg))
