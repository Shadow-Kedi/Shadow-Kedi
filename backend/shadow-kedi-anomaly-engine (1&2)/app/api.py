from datetime import UTC, datetime, timedelta
from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from pydantic import ValidationError
from .baselines import build_baselines
from .config import settings
from .database import AlertStatusRow, AnomalyScoreRow, CanonicalEventRow, ConnectorHeartbeatRow, SessionLocal, initialise_database
from .detectors import detect
from .models import BaselineRequest, EvaluationResponse, SecurityEvent
from .orchestrator import score_and_persist
from .repository import get_peer_baseline, get_user_baseline, save_baselines
from .ingest import ingest_event
from .platform_models import CanonicalEvent, IngestResult
from .redaction import redact_log_value
import csv
import io
import logging
import uuid

# Pre-existing gap, not introduced here: nothing in this app ever called
# logging.basicConfig (or any dictConfig), so every logger.info() call --
# including the pre-existing ingest log line below -- was silently dropped by
# the default root logger level (WARNING). Uvicorn configures its OWN
# uvicorn.*/uvicorn.access loggers, which is why HTTP access lines show up in
# `docker compose logs api` but nothing under the shadow_kedi.* namespace ever
# did. Needed now so the new ingest-time anomaly logging (see
# _score_event_on_ingest) is actually inspectable.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Shadow Kedi anomaly engine", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    # http://100.117.86.54:5173 is the dev frontend's Tailscale-shared origin
    # (see shadowguard-dashboard/.env.tailscale) -- added alongside localhost,
    # not instead of it, so this still works normally when nobody's sharing.
    # allow_credentials=True means allow_origins can't be "*" here regardless
    # (the CORS spec disallows wildcard + credentials), so this has to be an
    # explicit list either way.
    allow_origins=["http://localhost:5173", "http://100.117.86.54:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("shadow_kedi.ingest")
anomaly_logger = logging.getLogger("shadow_kedi.anomaly")


@app.on_event("startup")
def startup() -> None:
    initialise_database()


@app.get("/health")
def health() -> dict:
    """Extended for the dashboard's heartbeat indicator (design pass, see
    ConnectorHeartbeatRow). Two independent signals, both real:
      - lastEventAt: freshest canonical_events.ingested_at (NOT occurred_at --
        an event's own claimed timestamp can be legitimately backdated or
        out of order: replay/backfill, catch-up after an outage, or a
        deliberately-past occurred_at like the demo-seed script uses to
        trigger a real time-anomaly detection. ingested_at is server-assigned
        and monotonic, so "did something land JUST NOW" is answered reliably).
      - connector: the Wazuh connector's own last-reported poll outcome
        (POST /v1/connector-heartbeat below) -- distinguishes "polling fine,
        just nothing new" from "not polling at all", which lastEventAt alone
        can't do (both look identical: no new events).
    """
    with SessionLocal() as session:
        last_event_at = session.execute(select(CanonicalEventRow.ingested_at).order_by(CanonicalEventRow.ingested_at.desc()).limit(1)).scalar_one_or_none()
        # Most-recently-reported heartbeat, not a lookup by hardcoded tenant --
        # the dashboard has no tenant concept, and this deployment is single-
        # tenant in practice, but this way api.py doesn't bake in a tenant_id.
        heartbeat = session.execute(select(ConnectorHeartbeatRow).order_by(ConnectorHeartbeatRow.polled_at.desc()).limit(1)).scalar_one_or_none()

    return {
        "status": "ok",
        "lastEventAt": last_event_at.isoformat() if last_event_at else None,
        "connector": {
            "status": heartbeat.status,
            "eventsFound": heartbeat.events_found,
            "detail": heartbeat.detail,
            "polledAt": heartbeat.polled_at.isoformat(),
        } if heartbeat else None,
    }


class ConnectorHeartbeatRequest(BaseModel):
    status: str  # "ok" | "error"
    events_found: int = 0
    detail: str | None = None


@app.post("/v1/connector-heartbeat")
def receive_connector_heartbeat(
    body: ConnectorHeartbeatRequest,
    x_ingest_key: str = Header(default=""),
    x_tenant_id: str = Header(default=""),
) -> dict[str, str]:
    """Reported by wazuh_connector.py at the end of every poll cycle --
    success (with or without new events) or failure. Same credential as
    /v1/events (no new secret to manage); a heartbeat carries no event data,
    so there's no per-event replay-safety concern the way ingest has."""
    cfg = settings()
    if x_ingest_key != cfg.ingest_api_key:
        raise HTTPException(status_code=401, detail="Invalid ingest credential")
    if body.status not in {"ok", "error"}:
        raise HTTPException(status_code=422, detail="status must be 'ok' or 'error'")

    with SessionLocal() as session:
        row = session.get(ConnectorHeartbeatRow, x_tenant_id) or ConnectorHeartbeatRow(tenant_id=x_tenant_id)
        row.status, row.events_found, row.detail = body.status, body.events_found, body.detail
        row.polled_at = datetime.now(UTC)
        session.add(row)
        session.commit()
    return {"status": "recorded"}


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
        if result.status == "accepted":
            _score_event_on_ingest(session, event.event_id, cfg)
    logger.info("ingest status=%s event_id=%s tenant=%s", result.status, event.event_id, redact_log_value(event.tenant_id))
    return result


def _score_event_on_ingest(session, event_id: str, cfg) -> None:
    """Run the Step 3 orchestrator against the just-ingested event and persist
    its output, per-event at ingest time rather than batched on the daily
    baseline schedule -- chosen so an analyst sees anomaly signals as soon as
    they happen, matching the dashboard's triage-queue UX (a day-old alert
    defeats the point of a triage queue). This event volume (dozens/day in the
    current fleet) makes the extra baseline lookup + detect() + orchestrator
    call negligible ingest-latency cost; revisit if volume grows enough for
    that to matter.

    Read endpoints (GET /overview, /alerts, etc.) only ever READ the persisted
    AnomalyScoreRow this writes -- they never recompute at request time.
    """
    row = session.get(CanonicalEventRow, event_id)
    if row is None:
        return
    try:
        result = score_and_persist(session, row, cfg)
    except ValidationError as exc:
        # Same tolerance as the batch adapter (event_adapter.py) -- a
        # scoring-only conversion issue must never fail the ingest itself.
        logger.warning("skipping ingest-time scoring for event_id=%s: %s", event_id, exc)
        return
    for anomaly in result.findings:
        anomaly_logger.info(
            "anomaly event_id=%s user_id=%s signal=%s score=%s severity=%s explanation=%s evidence=%s",
            event_id, redact_log_value(row.user_id), anomaly.signal, anomaly.score, anomaly.severity,
            anomaly.explanation, anomaly.evidence,
        )
    anomaly_logger.info(
        "orchestrated event_id=%s score=%s severity=%s tier=%s confidence=%s sample_days=%s",
        event_id, result.score, result.severity, result.tier, result.confidence, result.sample_days,
    )


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


# =============================================================================
# Dashboard read endpoints. Severity/score/tier/recommendation/evidence now
# come from the Step 3 orchestrator's persisted AnomalyScoreRow (real
# behavioral anomaly detection against user/peer baselines) rather than the
# old rule_level heuristic (_derive_severity_and_score, removed). These
# endpoints only ever READ what was already computed at ingest time (or by
# the backfill script) -- never recompute here. Status (new/under_review/
# resolved) IS real and persisted, via AlertStatusRow, same as before.
# =============================================================================

_SIGNAL_LABELS = {
    "time_anomaly": "Time anomaly",
    "volume_anomaly": "Volume anomaly",
    "new_domain": "New domain",
    "peer_comparison": "Peer comparison",
}


def _load_status_map(session, event_ids: list[str]) -> dict[str, str]:
    if not event_ids:
        return {}
    rows = session.execute(
        select(AlertStatusRow).where(AlertStatusRow.event_id.in_(event_ids))
    ).scalars().all()
    return {r.event_id: r.status for r in rows}


def _load_score_map(session, event_ids: list[str]) -> dict[str, AnomalyScoreRow]:
    if not event_ids:
        return {}
    rows = session.execute(
        select(AnomalyScoreRow).where(AnomalyScoreRow.event_id.in_(event_ids))
    ).scalars().all()
    return {r.event_id: r for r in rows}


def _event_to_alert_dict(row: "CanonicalEventRow", score_row: "AnomalyScoreRow | None", status_map: dict | None = None) -> dict:
    metadata = row.metadata_json or {}
    app_name = metadata.get("rule_description") or row.event_type.replace("_", " ").title()
    status_value = (status_map or {}).get(row.event_id, "new")

    if score_row is not None:
        severity, score, tier = score_row.severity, score_row.score, score_row.tier
        recommendation = score_row.recommendation
        findings = score_row.findings_json or []
    else:
        # Shouldn't happen for backfilled history, but a brand-new event can
        # theoretically be read before its ingest-time scoring commits, or
        # scoring could fail without failing ingest (see
        # _score_event_on_ingest's ValidationError handling). Labeled
        # honestly rather than silently reviving the old rule_level guess.
        severity, score, tier = "low", 0, "R1"
        recommendation = "Not yet scored -- awaiting anomaly detection."
        findings = []

    evidence = [
        {
            "label": "Source event",
            "detail": metadata.get("rule_description") or f"{row.event_type} event from {row.source}",
            "observedAt": row.occurred_at.strftime("%H:%M"),
            "strength": "observed",
        }
    ]
    evidence += [
        {
            "label": _SIGNAL_LABELS.get(finding["signal"], finding["signal"]),
            "detail": finding["explanation"],
            "observedAt": row.occurred_at.strftime("%H:%M"),
            "strength": "observed",
        }
        for finding in findings
    ]

    return {
        "id": row.event_id,
        "userId": row.user_id,
        "userName": row.user_id,
        "department": "Unclassified",
        "severity": severity,
        "score": score,
        "app": app_name,
        "category": row.event_type,
        "status": status_value,
        "createdAt": row.occurred_at.isoformat(),
        "tier": tier,
        "recommendation": recommendation,
        "evidence": evidence,
    }


@app.get("/overview")
def get_overview():
    with SessionLocal() as session:
        rows = session.execute(select(CanonicalEventRow)).scalars().all()
        status_map = _load_status_map(session, [r.event_id for r in rows])
        score_map = _load_score_map(session, [r.event_id for r in rows])

    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    alert_dicts = [_event_to_alert_dict(r, score_map.get(r.event_id), status_map) for r in rows]
    for a in alert_dicts:
        counts[a["severity"]] += 1

    top_risk = sorted(alert_dicts, key=lambda a: a["score"], reverse=True)[:3]

    # file_integrity (FIM/syscheck "Integrity checksum changed" etc.) is
    # routine system noise, not Shadow IT signal -- it's still counted in
    # severityCounts above (almost always "low"), so a raw total can look
    # alarmingly large without context. Broken out separately here so the
    # dashboard can show "N are routine file-integrity checks" rather than
    # one undifferentiated number with no way to explain it live.
    file_integrity_count = sum(1 for a in alert_dicts if a["category"] == "file_integrity")

    # Daily trend for the Overview metric cards' sparklines. Bucketed from
    # data we already have in memory (alert_dicts, one query above) rather
    # than a fresh query per severity. Oldest-to-newest, 7 days, by the
    # alert's own occurred_at (createdAt) date -- consistent with how
    # createdAt is used everywhere else in this file, not ingested_at.
    #
    # "reviewed" is the one series that needs its own tiny query: when an
    # alert was actually marked reviewed (AlertStatusRow.reviewed_at), not
    # when the underlying alert occurred -- those are different questions,
    # and alert_dicts only has the latter.
    #
    # Deliberately NOT provided for "new apps": that card's count is a
    # hardcoded 0 (see below), there is no real per-day app-discovery
    # tracking to bucket, and faking a flat line for a metric with no real
    # source data isn't "graceful degradation," it's fabrication. Skipped
    # rather than faked; the frontend simply omits a sparkline on that card.
    day_keys = [(datetime.now(UTC).date() - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
    severity_daily = {sev: dict.fromkeys(day_keys, 0) for sev in ("critical", "high", "medium", "low")}
    for a in alert_dicts:
        day = a["createdAt"][:10]
        bucket = severity_daily[a["severity"]]
        if day in bucket:
            bucket[day] += 1

    with SessionLocal() as session:
        reviewed_timestamps = session.execute(
            select(AlertStatusRow.reviewed_at).where(AlertStatusRow.reviewed_at.isnot(None))
        ).scalars().all()
    reviewed_daily = dict.fromkeys(day_keys, 0)
    for ts in reviewed_timestamps:
        day = ts.date().isoformat()
        if day in reviewed_daily:
            reviewed_daily[day] += 1

    return {
        "severityCounts": counts,
        "newApps": 0,
        "reviewedThisWeek": sum(1 for a in alert_dicts if a["status"] == "resolved"),
        "topRisk": top_risk,
        "fileIntegrityCount": file_integrity_count,
        "dailyTrend": {
            "critical": [severity_daily["critical"][d] for d in day_keys],
            "high": [severity_daily["high"][d] for d in day_keys],
            "medium": [severity_daily["medium"][d] for d in day_keys],
            "low": [severity_daily["low"][d] for d in day_keys],
            "reviewed": [reviewed_daily[d] for d in day_keys],
        },
    }


@app.get("/alerts")
def list_alerts(
    page: int = Query(1, ge=1),
    search: str = Query(""),
    severity: str = Query(""),
    status: str = Query(""),
):
    with SessionLocal() as session:
        rows = session.execute(
            select(CanonicalEventRow).order_by(CanonicalEventRow.occurred_at.desc())
        ).scalars().all()
        status_map = _load_status_map(session, [r.event_id for r in rows])
        score_map = _load_score_map(session, [r.event_id for r in rows])

    alert_dicts = [_event_to_alert_dict(r, score_map.get(r.event_id), status_map) for r in rows]

    if search:
        s = search.lower()
        alert_dicts = [a for a in alert_dicts if s in a["userName"].lower() or s in a["app"].lower()]
    if severity:
        alert_dicts = [a for a in alert_dicts if a["severity"] == severity]
    if status:
        alert_dicts = [a for a in alert_dicts if a["status"] == status]

    page_size = 5
    start = (page - 1) * page_size
    return {
        "items": alert_dicts[start:start + page_size],
        "page": page,
        "pageSize": page_size,
        "total": len(alert_dicts),
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with SessionLocal() as session:
        row = session.execute(
            select(CanonicalEventRow).where(CanonicalEventRow.event_id == alert_id)
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        status_map = _load_status_map(session, [alert_id])
        score_map = _load_score_map(session, [alert_id])
    return _event_to_alert_dict(row, score_map.get(alert_id), status_map)


@app.get("/users/{user_id}")
def get_user(user_id: str):
    with SessionLocal() as session:
        rows = session.execute(
            select(CanonicalEventRow)
            .where(CanonicalEventRow.user_id == user_id)
            .order_by(CanonicalEventRow.occurred_at.asc())
        ).scalars().all()
        if not rows:
            raise HTTPException(status_code=404, detail="User not found")
        status_map = _load_status_map(session, [r.event_id for r in rows])
        score_map = _load_score_map(session, [r.event_id for r in rows])

    alert_dicts = [_event_to_alert_dict(r, score_map.get(r.event_id), status_map) for r in rows]
    return {
        "id": user_id,
        "name": user_id,
        "department": "Unclassified",
        "baseline": "learning",
        # trend needs the last 6 in chronological (oldest-first) order for the
        # line chart to read left-to-right as time -- computed from alert_dicts
        # BEFORE reversing it below, not after.
        "trend": [a["score"] for a in alert_dicts[-6:]],
        "inventory": sorted({a["app"] for a in alert_dicts}),
        # Query above is oldest-first (required for the trend slice above);
        # the alerts list itself should read most-recent-first for an analyst
        # scanning "what's happened with this user recently" -- same
        # convention GET /alerts already uses (.desc()). Reversed here rather
        # than querying twice.
        "alerts": list(reversed(alert_dicts)),
    }


@app.get("/applications")
def list_applications():
    with SessionLocal() as session:
        rows = session.execute(select(CanonicalEventRow)).scalars().all()

    seen: dict[str, dict] = {}
    for r in rows:
        metadata = r.metadata_json or {}
        name = metadata.get("rule_description") or r.event_type.replace("_", " ").title()
        entry = seen.setdefault(name, {"id": name, "name": name, "category": r.event_type,
                                        "approval": "unapproved", "activeUsers": set(), "review": "needed"})
        entry["activeUsers"].add(r.user_id)

    return [
        {**e, "activeUsers": len(e["activeUsers"])}
        for e in seen.values()
    ]


class ReviewRequest(BaseModel):
    status: str = "resolved"  # "new" | "under_review" | "resolved"


@app.patch("/alerts/{alert_id}")
def review_alert(alert_id: str, body: ReviewRequest):
    with SessionLocal() as session:
        row = session.execute(
            select(CanonicalEventRow).where(CanonicalEventRow.event_id == alert_id)
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        existing = session.get(AlertStatusRow, alert_id)
        if existing is None:
            existing = AlertStatusRow(event_id=alert_id, status=body.status, reviewed_at=datetime.now(UTC))
            session.add(existing)
        else:
            existing.status = body.status
            existing.reviewed_at = datetime.now(UTC)
        session.commit()

        status_map = {alert_id: body.status}
        score_map = _load_score_map(session, [alert_id])
    return _event_to_alert_dict(row, score_map.get(alert_id), status_map)


@app.get("/leaderboard")
def get_leaderboard():
    with SessionLocal() as session:
        rows = session.execute(select(CanonicalEventRow)).scalars().all()
        status_map = _load_status_map(session, [r.event_id for r in rows])
        score_map = _load_score_map(session, [r.event_id for r in rows])

    alert_dicts = [_event_to_alert_dict(r, score_map.get(r.event_id), status_map) for r in rows]

    by_user: dict[str, list[dict]] = {}
    for a in alert_dicts:
        by_user.setdefault(a["userId"], []).append(a)

    leaderboard = []
    for user_id, alerts in by_user.items():
        top = max(alerts, key=lambda a: a["score"])
        leaderboard.append({
            "userId": user_id,
            "userName": user_id,
            "alertCount": len(alerts),
            "maxScore": top["score"],
            "topSeverity": top["severity"],
        })

    leaderboard.sort(key=lambda u: u["maxScore"], reverse=True)
    return leaderboard


@app.get("/exports.csv")
def export_csv():
    with SessionLocal() as session:
        rows = session.execute(select(CanonicalEventRow)).scalars().all()
        status_map = _load_status_map(session, [r.event_id for r in rows])
        score_map = _load_score_map(session, [r.event_id for r in rows])

    alert_dicts = [_event_to_alert_dict(r, score_map.get(r.event_id), status_map) for r in rows]

    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["id", "userId", "userName", "department", "severity", "score",
                    "app", "category", "status", "createdAt", "tier"],
        extrasaction="ignore",
    )
    writer.writeheader()
    for a in alert_dicts:
        writer.writerow(a)
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=shadow_kedi_alerts.csv"},
    )
