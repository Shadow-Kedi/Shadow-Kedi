from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, Field, field_validator


class EventType(StrEnum):
    LOGIN = "login"
    ACTIVITY = "activity"
    TRANSFER = "transfer"


class SecurityEvent(BaseModel):
    """Normalized event. user_id must already be a non-reversible identity-provider subject."""
    user_id: str = Field(min_length=8, max_length=128)
    department: str = Field(min_length=1, max_length=64)
    occurred_at: datetime
    event_type: EventType
    bytes_transferred: int = Field(default=0, ge=0)
    domain: str | None = Field(default=None, max_length=253)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.lower().strip().rstrip(".") or None

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        return value


class BaselineRequest(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=100_000)


class Anomaly(BaseModel):
    signal: str
    score: int = Field(ge=0, le=100)
    severity: str
    explanation: str
    evidence: dict[str, float | int | str | bool]


class EvaluationResponse(BaseModel):
    user_id: str
    anomalies: list[Anomaly]
