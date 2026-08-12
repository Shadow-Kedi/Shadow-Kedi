from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.types import JSON
from .config import settings


class Base(DeclarativeBase):
    pass


class UserBaselineRow(Base):
    __tablename__ = "user_baselines"
    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    department: Mapped[str] = mapped_column(String(64), index=True)
    login_hour_median: Mapped[float | None] = mapped_column(Float, nullable=True)
    login_hour_mad: Mapped[float | None] = mapped_column(Float, nullable=True)
    daily_volume_median: Mapped[float] = mapped_column(Float)
    daily_volume_mad: Mapped[float] = mapped_column(Float)
    known_domain_hashes: Mapped[list[str]] = mapped_column(JSON)
    sample_days: Mapped[int] = mapped_column(Integer)
    computed_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)


class PeerBaselineRow(Base):
    __tablename__ = "peer_baselines"
    department: Mapped[str] = mapped_column(String(64), primary_key=True)
    daily_volume_median: Mapped[float] = mapped_column(Float)
    daily_volume_mad: Mapped[float] = mapped_column(Float)
    cohort_size: Mapped[int] = mapped_column(Integer)
    computed_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)


class CanonicalEventRow(Base):
    __tablename__ = "canonical_events"
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    device_id: Mapped[str] = mapped_column(String(128), index=True)
    occurred_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    schema_version: Mapped[str] = mapped_column(String(8))
    metadata_json: Mapped[dict] = mapped_column(JSON)
    # Server-assigned, monotonic -- distinct from occurred_at (the event's own
    # claimed timestamp, which can legitimately be backdated or arrive out of
    # order: replay/backfill, catch-up after a connector outage, or a
    # deliberately-past occurred_at like scripts/demo_seed_anomaly.py uses to
    # trigger a real time-anomaly detection). The heartbeat indicator needs
    # "did something land JUST NOW" -- occurred_at can't answer that reliably,
    # ingested_at always can.
    ingested_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class AlertStatusRow(Base):
    __tablename__ = "alert_status"
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="new")
    reviewed_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AnomalyScoreRow(Base):
    """Step 3 orchestrator output, one row per canonical_events row (same
    event_id-as-primary-key convention as AlertStatusRow above -- a separate
    table for derived/mutable conclusions, not a column on canonical_events,
    which stays a content-free record of what was actually observed). Written
    once at ingest time (or by the backfill script) and read verbatim by the
    dashboard endpoints -- never recomputed on a GET."""
    __tablename__ = "anomaly_scores"
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    tier: Mapped[str] = mapped_column(String(4))
    recommendation: Mapped[str] = mapped_column(Text)
    # Serialized list[Anomaly] (signal/score/severity/explanation/evidence
    # dicts) -- the fired-signal detail behind the score, used to build the
    # alert detail page's evidence timeline.
    findings_json: Mapped[list] = mapped_column(JSON)
    confidence: Mapped[float] = mapped_column(Float)
    sample_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    computed_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)


class ConnectorHeartbeatRow(Base):
    """One row per tenant (one connector instance = one tenant, per
    wazuh_connector.py's own docstring), overwritten every poll cycle. This is
    what lets the dashboard's heartbeat indicator reflect the connector's own
    poll success/failure -- not just "did a new event arrive", which can't
    distinguish a healthy-but-idle connector from a dead one. Reported by
    wazuh_connector.py itself via POST /v1/connector-heartbeat, using the same
    ingest credential /v1/events already requires."""
    __tablename__ = "connector_heartbeats"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))  # "ok" | "error"
    events_found: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # error message, if status == "error"
    polled_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)


engine = create_engine(settings().database_url, connect_args={"check_same_thread": False} if settings().database_url.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def initialise_database() -> None:
    Base.metadata.create_all(engine)