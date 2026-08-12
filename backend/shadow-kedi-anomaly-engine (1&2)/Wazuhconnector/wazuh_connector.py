"""
Shadow Kedi — Wazuh connector

Polls the Wazuh indexer (OpenSearch) for new alerts and forwards them,
reshaped to the anomaly-engine's /v1/events schema, to the ingest API.

This is a SERVER-SIDE service. It holds the real INGEST_API_KEY and
Wazuh indexer credentials — never run this in a browser context, and
never commit real values for the environment variables below.

Run modes:
  - one-off:     python wazuh_connector.py --once
  - continuous:  python wazuh_connector.py            (polls every POLL_INTERVAL_SECONDS)

Recommended for production: run under systemd or a Celery beat task
instead of a bare `while True` loop, so restarts/crashes are supervised.
"""

import os
import time
import uuid
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

import requests
from opensearchpy import OpenSearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("wazuh_connector")

# --------------------------------------------------------------------------
# Configuration — all from environment, nothing hardcoded
# --------------------------------------------------------------------------

WAZUH_INDEXER_HOST = os.environ["WAZUH_INDEXER_HOST"]          # e.g. "https://wazuh-indexer:9200"
WAZUH_INDEXER_USER = os.environ["WAZUH_INDEXER_USER"]
WAZUH_INDEXER_PASS = os.environ["WAZUH_INDEXER_PASS"]
WAZUH_INDEX_PATTERN = os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
WAZUH_VERIFY_TLS = os.environ.get("WAZUH_VERIFY_TLS", "true").lower() == "true"

INGEST_API_URL = os.environ["INGEST_API_URL"]                  # e.g. "http://anomaly-engine:8000/v1/events"
INGEST_API_KEY = os.environ["INGEST_API_KEY"]                  # real secret, NOT the dev_key_123 placeholder
TENANT_ID = os.environ["TENANT_ID"]                            # this connector instance = one client/tenant

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "500"))

# Where we persist "the last alert timestamp we successfully forwarded",
# so a restart doesn't replay or drop events. In production, swap this
# file-based watermark for a row in Postgres keyed by tenant_id.
WATERMARK_FILE = Path(os.environ.get("WATERMARK_FILE", "/var/lib/shadow-kedi/watermark.txt"))


# --------------------------------------------------------------------------
# Watermark handling
# --------------------------------------------------------------------------

def load_watermark() -> str:
    """Return the ISO timestamp of the last alert we successfully forwarded."""
    if WATERMARK_FILE.exists():
        return WATERMARK_FILE.read_text().strip()
    # First-ever run: start from now, so we don't try to backfill a
    # potentially huge historical index on first boot. Change this if
    # you deliberately want a historical backfill run.
    return datetime.now(timezone.utc).isoformat()


def save_watermark(ts: str) -> None:
    WATERMARK_FILE.parent.mkdir(parents=True, exist_ok=True)
    WATERMARK_FILE.write_text(ts)


# --------------------------------------------------------------------------
# Wazuh -> Shadow Kedi event mapping
#
# This is the part you WILL need to tune against your own Wazuh rule set.
# It's intentionally conservative: unmapped alerts are forwarded with
# event_type="unclassified" rather than silently dropped, so nothing
# gets lost while you're still building out the rule mapping.
# --------------------------------------------------------------------------

# The ingest API accepts five event_type values as of 2026-08-12 (originally
# four, confirmed against a live 422 response from the real backend on
# 2026-08-11; file_integrity added when FIM/syscheck alerts turned out to be
# silently inflating file_upload's count with non-data-movement noise — see
# app/platform_models.py). Everything from Wazuh has to be bucketed into one
# of these five — there is no "unclassified" fallback accepted by the
# schema, so anything that doesn't clearly match a category defaults to the
# closest available bucket (network_access) rather than being dropped.
def classify_event_type(source: dict) -> str:
    rule_groups = source.get("rule", {}).get("groups", []) or []
    full_log = (source.get("full_log") or "").lower()

    # FIM/syscheck ("Integrity checksum changed" etc.) is a checksum/config
    # observation, not data leaving the device -- kept separate from "file"/
    # "usb", which genuinely are file-movement-shaped groups and still belong
    # in file_upload.
    if "syscheck" in rule_groups:
        return "file_integrity"
    if "file" in rule_groups or "usb" in rule_groups:
        return "file_upload"
    if "software" in rule_groups or "installed" in full_log or "package" in full_log:
        return "installed_application"
    if "dlp" in rule_groups or "data_loss" in rule_groups:
        return "dlp_outcome"
    # authentication events, web/network events, and anything else
    # fall back here — it's the closest generic bucket the schema offers
    return "network_access"


def wazuh_alert_to_event(hit: dict) -> dict:
    """Reshape one Wazuh/OpenSearch hit into the /v1/events schema."""
    source = hit.get("_source", {})
    agent = source.get("agent", {})
    data = source.get("data", {})

    return {
        "schema_version": "1.0",
        "tenant_id": TENANT_ID,
        "event_id": hit.get("_id", str(uuid.uuid4())),
        "occurred_at": source.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        # Prefixed for the same reason as device_id below: the ingest
        # API enforces an 8-character minimum on identifier fields, and
        # raw values (usernames, short hostnames used as a fallback)
        # aren't guaranteed to meet that on their own.
        "user_id": f"user-{data.get('dstuser') or data.get('srcuser') or agent.get('name', 'unknown')}",
        # Wazuh agent IDs are short (e.g. "003"), but the ingest API
        # requires device_id to be at least 8 characters. Prefix with
        # "agent-" so IDs stay stable, unique, and readable rather than
        # arbitrarily padded with zeros or spaces.
        "device_id": f"agent-{agent.get('id', 'unknown')}",
        "source": "wazuh",
        "event_type": classify_event_type(source),
        "metadata": {
            "rule_id": source.get("rule", {}).get("id"),
            "rule_description": source.get("rule", {}).get("description"),
            "rule_level": source.get("rule", {}).get("level"),
            "agent_name": agent.get("name"),
            "raw_log": source.get("full_log"),
        },
    }


# --------------------------------------------------------------------------
# Fetch + forward
# --------------------------------------------------------------------------

def get_opensearch_client() -> OpenSearch:
    return OpenSearch(
        hosts=[WAZUH_INDEXER_HOST],
        http_auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
        verify_certs=WAZUH_VERIFY_TLS,
        # Default Wazuh installs use a self-signed cert on the indexer.
        # ssl_show_warn suppresses the resulting warning spam when
        # WAZUH_VERIFY_TLS=false; it does NOT affect security, since
        # verify_certs is what actually controls cert checking.
        ssl_show_warn=WAZUH_VERIFY_TLS,
    )


def fetch_new_alerts(client: OpenSearch, since_ts: str) -> list:
    query = {
        "size": BATCH_SIZE,
        "sort": [{"timestamp": "asc"}],
        "query": {
            "range": {
                "timestamp": {"gt": since_ts}
            }
        },
    }
    resp = client.search(index=WAZUH_INDEX_PATTERN, body=query)
    return resp.get("hits", {}).get("hits", [])


def report_heartbeat(status_value: str, events_found: int = 0, detail: str | None = None) -> None:
    """Tell the API how the last poll cycle went -- success (idle or with
    events) or failure. Feeds the dashboard's heartbeat indicator, which
    needs this to tell "polling fine, nothing new" apart from "not polling at
    all" (both look identical from the ingest side alone: no new events).
    Deliberately never allowed to break the actual poll loop -- a heartbeat
    report failing is not a reason to stop forwarding real events, so this
    swallows its own errors rather than raising.
    """
    try:
        resp = requests.post(
            INGEST_API_URL.replace("/v1/events", "/v1/connector-heartbeat"),
            json={"status": status_value, "events_found": events_found, "detail": detail},
            headers={"x-ingest-key": INGEST_API_KEY, "x-tenant-id": TENANT_ID, "Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code != 200:
            log.warning("Heartbeat report rejected: status=%s body=%s", resp.status_code, resp.text[:200])
    except Exception:
        log.exception("Heartbeat report failed (not fatal -- continuing)")


def forward_batch(events: list) -> None:
    headers = {
        "x-ingest-key": INGEST_API_KEY,
        "x-tenant-id": TENANT_ID,
        "Content-Type": "application/json",
    }
    for event in events:
        resp = requests.post(INGEST_API_URL, json=event, headers=headers, timeout=10)
        if resp.status_code != 201:
            log.error(
                "Failed to forward event_id=%s status=%s body=%s",
                event["event_id"], resp.status_code, resp.text[:500],
            )
            # Don't advance the watermark past a failed event — better to
            # retry a duplicate on next run than to silently drop it.
            raise RuntimeError(f"Ingest API rejected event {event['event_id']}")


def run_once() -> None:
    client = get_opensearch_client()
    since_ts = load_watermark()

    hits = fetch_new_alerts(client, since_ts)
    if not hits:
        log.info("No new alerts since %s", since_ts)
        report_heartbeat("ok", events_found=0)
        return

    events = [wazuh_alert_to_event(hit) for hit in hits]
    forward_batch(events)

    newest_ts = max(e["occurred_at"] for e in events)
    save_watermark(newest_ts)
    log.info("Forwarded %d events, watermark advanced to %s", len(events), newest_ts)
    report_heartbeat("ok", events_found=len(events))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit")
    args = parser.parse_args()

    if args.once:
        run_once()
        return

    log.info("Starting continuous polling every %ss", POLL_INTERVAL_SECONDS)
    while True:
        try:
            run_once()
        except Exception as exc:
            log.exception("Poll cycle failed, will retry next interval")
            report_heartbeat("error", detail=str(exc)[:500])
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()