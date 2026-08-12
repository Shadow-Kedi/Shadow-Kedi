from datetime import UTC, datetime, timedelta
from pathlib import Path
from shadowguard_detection.catalogue import ApplicationCatalogue
from shadowguard_detection.dlp import scan_fixture_text
from shadowguard_detection.models import CanonicalEvent
from shadowguard_detection.pipeline import DetectionEngine


CATALOGUE = ApplicationCatalogue.from_json(Path(__file__).parent.parent / "fixtures/application_catalogue.json")
ENGINE = DetectionEngine(CATALOGUE, "test-hash-key")


def event(event_id: str, when: datetime, kind: str, metadata: dict, user: str = "usr_anon_17") -> CanonicalEvent:
    return CanonicalEvent("demo-acme", event_id, when, user, "dev_anon_04", kind, metadata | {"department": "finance"})


def test_fixture_dlp_returns_labels_not_values() -> None:
    result = scan_fixture_text("ssn 123-45-6789 and AWS AKIA1234567890ABCDEF")
    assert result.classification == "highly_confidential"
    assert set(result.detectors) == {"aws_key", "ssn"}
    assert "123-45-6789" not in str(result.safe_payload())


def test_first_time_dropbox_is_new_and_unapproved_only_once() -> None:
    now = datetime(2026, 8, 10, 2, 15, tzinfo=UTC)
    history = [event(f"evt-history-{day}", now - timedelta(days=day + 1), "network_access", {"domain": "drive.google.com"}) for day in range(7)]
    first = event("evt-first-dropbox", now, "network_access", {"domain": "dropbox.com"})
    first_types = {signal.signal_type for signal in ENGINE.evaluate(first, history)}
    assert {"new_domain", "unapproved_app"}.issubset(first_types)
    history.append(first)
    second = event("evt-second-dropbox", now + timedelta(minutes=1), "network_access", {"domain": "dropbox.com"})
    assert "new_domain" not in {signal.signal_type for signal in ENGINE.evaluate(second, history)}


def test_time_and_volume_need_history_then_trigger() -> None:
    now = datetime(2026, 8, 10, 2, 15, tzinfo=UTC)
    history = []
    for day in range(7):
        history.append(event(f"evt-login-{day}", now - timedelta(days=day + 1, hours=-7), "login", {}))
        history.append(event(f"evt-volume-{day}", now - timedelta(days=day + 1), "file_upload", {"bytes_transferred": 1000, "domain": "drive.google.com"}))
    suspicious_login = event("evt-late-login", now, "login", {})
    assert "time_anomaly" in {signal.signal_type for signal in ENGINE.evaluate(suspicious_login, history)}
    suspicious_transfer = event("evt-large-transfer", now, "file_upload", {"bytes_transferred": 524288000, "domain": "dropbox.com"})
    assert "volume_anomaly" in {signal.signal_type for signal in ENGINE.evaluate(suspicious_transfer, history)}


def test_approved_application_does_not_emit_unapproved_signal() -> None:
    now = datetime(2026, 8, 10, 12, tzinfo=UTC)
    signals = ENGINE.evaluate(event("evt-approved", now, "network_access", {"domain": "drive.google.com"}), [])
    assert "unapproved_app" not in {signal.signal_type for signal in signals}
