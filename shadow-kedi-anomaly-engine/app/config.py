from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./shadow_kedi.db"
    domain_hash_key: str = "local-development-key-change-me"
    baseline_window_days: int = 30
    min_peer_cohort: int = 5


@lru_cache
def settings() -> Settings:
    return Settings()
