from datetime import UTC, datetime, timedelta
from fastapi import FastAPI, HTTPException
from .baselines import build_baselines
from .config import settings
from .database import SessionLocal, initialise_database
from .detectors import detect
from .models import BaselineRequest, EvaluationResponse, SecurityEvent
from .repository import get_peer_baseline, get_user_baseline, save_baselines

app = FastAPI(title="Shadow Kedi anomaly engine", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    initialise_database()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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
