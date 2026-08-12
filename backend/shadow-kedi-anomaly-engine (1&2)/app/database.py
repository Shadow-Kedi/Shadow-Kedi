from sqlalchemy import DateTime, Float, Integer, String, create_engine
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


engine = create_engine(settings().database_url, connect_args={"check_same_thread": False} if settings().database_url.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def initialise_database() -> None:
    Base.metadata.create_all(engine)
