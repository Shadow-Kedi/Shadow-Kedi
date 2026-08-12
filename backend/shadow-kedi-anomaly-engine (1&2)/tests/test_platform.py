import json
import subprocess
import sys
from pathlib import Path
import pytest
from pydantic import ValidationError
from app.platform_models import CanonicalEvent


ROOT = Path(__file__).parent.parent


def canonical(**overrides) -> dict:
    event = {"schema_version": "1.0", "tenant_id": "demo-acme", "event_id": "evt-test-0001", "occurred_at": "2026-08-10T02:15:00Z", "user_id": "usr_anon_17", "device_id": "dev_anon_04", "source": "simulator", "event_type": "network_access", "metadata": {"domain": "chatgpt.com"}}
    event.update(overrides)
    return event


def test_canonical_event_rejects_secret_content() -> None:
    with pytest.raises(ValidationError, match="prohibited"):
        CanonicalEvent.model_validate(canonical(metadata={"clipboard": "do-not-store"}))


def test_canonical_event_requires_utc() -> None:
    with pytest.raises(ValidationError, match="UTC"):
        CanonicalEvent.model_validate(canonical(occurred_at="2026-08-10T02:15:00-04:00"))


def test_normalizer_emits_content_free_canonical_events(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"
    subprocess.run([sys.executable, "scripts/normalize_events.py", "fixtures/raw_simulator_events.jsonl", str(output)], cwd=ROOT, check=True)
    events = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(events) == 4
    assert events[-1]["event_type"] == "dlp_outcome"
    assert "content" not in events[-1]["metadata"]
    assert events[-1]["metadata"]["detectors"] == ["ssn", "aws_key"]
