from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class CanonicalEvent:
    tenant_id: str
    event_id: str
    occurred_at: datetime
    user_id: str
    device_id: str
    event_type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CanonicalEvent":
        occurred_at = datetime.fromisoformat(payload["occurred_at"].replace("Z", "+00:00"))
        if occurred_at.tzinfo is None or occurred_at.utcoffset().total_seconds() != 0:
            raise ValueError("occurred_at must be UTC")
        forbidden = {"content", "clipboard", "password", "secret", "token", "raw_url", "file_contents"}
        if forbidden.intersection(key.lower() for key in payload.get("metadata", {})):
            raise ValueError("canonical event metadata cannot contain raw sensitive content")
        return cls(payload["tenant_id"], payload["event_id"], occurred_at, payload["user_id"], payload["device_id"], payload["event_type"], payload.get("metadata", {}))


@dataclass(frozen=True)
class Signal:
    signal_type: str
    severity: str
    score: int
    explanation: str
    evidence: dict[str, str | int | float | bool]
