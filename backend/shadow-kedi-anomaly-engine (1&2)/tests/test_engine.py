from datetime import UTC, datetime, timedelta
from app.baselines import build_baselines
from app.config import Settings
from app.detectors import detect
from app.models import EventType, SecurityEvent


def event(user: str, dept: str, hours_ago: int, kind: EventType, volume: int = 0, domain: str | None = None) -> SecurityEvent:
    return SecurityEvent(user_id=user, department=dept, occurred_at=datetime.now(UTC) - timedelta(hours=hours_ago), event_type=kind, bytes_transferred=volume, domain=domain)


def test_detects_volume_and_new_domain() -> None:
    events = []
    for day in range(10):
        events += [event("opaque-user-1", "finance", day * 24 + 14, EventType.LOGIN), event("opaque-user-1", "finance", day * 24 + 12, EventType.TRANSFER, 1000, "approved.example")]
    users, peers = build_baselines(events, "test-secret")
    suspicious = event("opaque-user-1", "finance", 1, EventType.TRANSFER, 100_000, "unapproved.example")
    results = detect(suspicious, users[suspicious.user_id], peers["finance"], Settings(domain_hash_key="test-secret"))
    assert {item.signal for item in results} == {"volume_anomaly", "new_domain"}


def test_small_peer_cohort_is_suppressed() -> None:
    events = [event(f"opaque-user-{n}", "legal", n + 24, EventType.TRANSFER, 1000) for n in range(3)]
    users, peers = build_baselines(events, "test-secret")
    result = detect(event("opaque-user-0", "legal", 1, EventType.TRANSFER, 99999), users["opaque-user-0"], peers["legal"], Settings(domain_hash_key="test-secret", min_peer_cohort=5))
    assert "peer_comparison" not in {item.signal for item in result}
