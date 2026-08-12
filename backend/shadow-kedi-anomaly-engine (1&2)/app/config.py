from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./shadow_kedi.db"
    domain_hash_key: str = "local-development-key-change-me"
    # Rolling window used by both the daily baseline-recompute task
    # (event_adapter.recompute_baselines_from_canonical_events) and the
    # (currently orphaned) manual POST /baselines/recompute endpoint. 7 days
    # per the Risk Engine spec's baseline-builder step.
    baseline_window_days: int = 7
    min_peer_cohort: int = 5
    ingest_api_key: str = "local-development-ingest-key-change-me"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"


@lru_cache
def settings() -> Settings:
    return Settings()
