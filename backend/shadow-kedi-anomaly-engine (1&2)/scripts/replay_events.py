"""Replay canonical fixtures to the service using stdlib only."""
import json
import os
import sys
from pathlib import Path
from urllib.request import Request, urlopen


def main() -> None:
    fixture = Path(sys.argv[1])
    api_url = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
    api_key = os.environ["INGEST_API_KEY"]
    for line in fixture.read_text().splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        request = Request(f"{api_url}/v1/events", data=json.dumps(event).encode(), method="POST", headers={"Content-Type": "application/json", "X-Ingest-Key": api_key, "X-Tenant-Id": event["tenant_id"]})
        with urlopen(request) as response:  # nosec B310 - URL is an explicit local dev configuration
            print(response.read().decode())


if __name__ == "__main__":
    main()
