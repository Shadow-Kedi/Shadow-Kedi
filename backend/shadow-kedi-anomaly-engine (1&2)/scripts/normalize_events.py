"""Convert safe simulated source records into the ShadowGuard canonical schema."""
import argparse
import json
from pathlib import Path
from uuid import uuid5, NAMESPACE_URL


def normalize(record: dict, tenant_id: str, line_number: int) -> dict:
    kind = record["kind"]
    event_type = {"browser": "network_access", "installed_app": "installed_application", "upload": "file_upload", "dlp": "dlp_outcome"}[kind]
    metadata: dict = {}
    if kind == "browser":
        metadata = {"domain": record["domain"], "duration_seconds": record.get("duration_seconds", 0)}
    elif kind == "installed_app":
        metadata = {"publisher": record["publisher"], "product": record["product"], "version": record.get("version", "unknown")}
    elif kind == "upload":
        metadata = {"domain": record["domain"], "bytes_transferred": record["bytes_transferred"]}
    elif kind == "dlp":
        # Deliberately no scanned input or matched secret is carried forward.
        metadata = {"classification": record["classification"], "detectors": record["detectors"], "match_count": record["match_count"]}
    stable_id = str(uuid5(NAMESPACE_URL, f"{tenant_id}:{line_number}:{record['timestamp']}:{record['user']}:{kind}"))
    return {"schema_version": "1.0", "tenant_id": tenant_id, "event_id": f"evt-{stable_id}", "occurred_at": record["timestamp"], "user_id": record["user"], "device_id": record["device"], "source": "simulator", "event_type": event_type, "metadata": metadata}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--tenant-id", default="demo-acme")
    args = parser.parse_args()
    with args.input.open() as source, args.output.open("w") as target:
        for number, line in enumerate(source, start=1):
            if line.strip():
                target.write(json.dumps(normalize(json.loads(line), args.tenant_id, number)) + "\n")


if __name__ == "__main__":
    main()
