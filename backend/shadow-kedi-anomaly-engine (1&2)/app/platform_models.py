from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator

# file_integrity added 2026-08-12: FIM/syscheck "Integrity checksum changed"
# alerts were being bucketed into file_upload, which is supposed to mean
# actual data movement (it feeds Volume Anomaly downstream -- see
# event_adapter.py). A system binary checksum change is not data leaving the
# device; conflating the two made file_upload's count meaningless and could
# have fed false volume-anomaly signal.
EventKind = Literal["network_access", "installed_application", "file_upload", "dlp_outcome", "file_integrity"]
SENSITIVE_KEYS = {"content", "clipboard", "password", "secret", "token", "authorization", "cookie", "raw_url", "query", "file_contents"}


class CanonicalEvent(BaseModel):
    """Versioned, content-free telemetry contract used by all simulated collectors."""
    schema_version: Literal["1.0"] = "1.0"
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    event_id: str = Field(min_length=8, max_length=128)
    occurred_at: datetime
    user_id: str = Field(min_length=8, max_length=128)
    device_id: str = Field(min_length=8, max_length=128)
    source: Literal["simulator", "wazuh", "opensearch_mock"]
    event_type: EventKind
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a UTC timezone")
        if value.utcoffset().total_seconds() != 0:
            raise ValueError("occurred_at must use UTC (+00:00 or Z)")
        return value

    @model_validator(mode="after")
    def reject_sensitive_metadata(self) -> "CanonicalEvent":
        def walk(value: Any) -> None:
            if isinstance(value, dict):
                forbidden = SENSITIVE_KEYS.intersection(key.lower() for key in value)
                if forbidden:
                    raise ValueError(f"metadata contains prohibited key(s): {', '.join(sorted(forbidden))}")
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(self.metadata)
        return self


class IngestResult(BaseModel):
    event_id: str
    status: Literal["accepted", "duplicate"]
