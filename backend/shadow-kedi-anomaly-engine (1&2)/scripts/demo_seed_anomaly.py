"""Demo helper: seed one controlled, clearly-anomalous event through the REAL
ingest pipeline (POST /v1/events -- the same path the Wazuh connector uses,
not a direct DB insert), so a live demo can show a real score/severity change
on the dashboard in front of a grader. Then clean it up afterward so it
doesn't linger in the fleet's real history or quietly get folded into the
next daily baseline recompute -- see Step 1/Step 3 notes on why prior test
rows were deleted before real verification.

Usage (from the host -- localhost:8000 is published -- or via
`docker exec <api-container> python -m scripts.demo_seed_anomaly ...`, both
work identically):

    python -m scripts.demo_seed_anomaly seed [--user user-Sarah]
    python -m scripts.demo_seed_anomaly cleanup --event-id demo-anomaly-...
    python -m scripts.demo_seed_anomaly cleanup --all   # remove every demo-anomaly-* row, if you lost track of the id

`seed` prints the event_id, the resulting score/severity/recommendation (so
you have something to read off live), and the exact cleanup command to run
afterward.

How it guarantees a detection: it reads the target user's CURRENT
login-hour baseline and schedules the event at the circular opposite hour
(12h away -- the maximum possible distance on a 24h clock), so it reads as a
time anomaly regardless of what that baseline happens to be that day. If the
user has no baseline yet, it warns and falls back to a generic off-hours
guess (which won't fire Time Anomaly, since detect() requires a baseline).
"""
import argparse
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.config import settings
from app.database import AnomalyScoreRow, CanonicalEventRow, SessionLocal, UserBaselineRow

DEMO_PREFIX = "demo-anomaly-"
# This environment's single real tenant (matches the live wazuh-connector's
# own .env.wazuh-connector) -- override with --tenant-id for a different one.
DEFAULT_TENANT_ID = "b02bd061-163f-4528-b828-aa0cfff43751"


def _opposite_hour_for(user_id: str) -> tuple[float | None, int]:
    with SessionLocal() as session:
        row = session.get(UserBaselineRow, user_id)
    if row is None or row.login_hour_median is None:
        return None, 3
    return row.login_hour_median, int((row.login_hour_median + 12) % 24)


def seed(user_id: str, tenant_id: str, api_url: str) -> None:
    cfg = settings()
    baseline_hour, target_hour = _opposite_hour_for(user_id)

    if baseline_hour is None:
        print(
            f"warning: {user_id} has no login-hour baseline yet -- Time Anomaly won't fire "
            f"until one exists (run scripts/backfill_anomaly_scores.py or wait for the next "
            f"daily recompute). Seeding at {target_hour:02d}:00 UTC anyway."
        )
    else:
        print(
            f"{user_id}'s current baseline login hour is ~{baseline_hour:.1f}:00 UTC -- "
            f"seeding at the circular opposite, {target_hour:02d}:30 UTC, to guarantee a real detection."
        )

    occurred_at = datetime.now(UTC).replace(hour=target_hour, minute=30, second=0, microsecond=0)
    if occurred_at > datetime.now(UTC):
        occurred_at -= timedelta(days=1)  # keep it a "past" event, not a confusing future timestamp

    event_id = f"{DEMO_PREFIX}{uuid4().hex[:12]}"
    payload = {
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "event_id": event_id,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "user_id": user_id,
        "device_id": "demo-seed-device",
        "source": "wazuh",
        "event_type": "network_access",
        "metadata": {"rule_id": "60106", "rule_description": "Windows Logon Success", "rule_level": 3, "agent_name": user_id},
    }
    request = urllib.request.Request(
        f"{api_url}/v1/events",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "x-ingest-key": cfg.ingest_api_key, "x-tenant-id": tenant_id},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            print("ingest response:", json.loads(response.read()))
    except urllib.error.HTTPError as exc:
        print(f"ingest failed: {exc.code} {exc.read().decode()}")
        return
    except urllib.error.URLError as exc:
        print(f"could not reach {api_url}: {exc.reason} (pass --api-url if the API isn't at localhost:8000 from here)")
        return

    with SessionLocal() as session:
        score_row = session.get(AnomalyScoreRow, event_id)
    if score_row is None:
        print("no anomaly_scores row was written -- check the api container's logs (docker compose logs api).")
    else:
        print(f"scored: score={score_row.score} severity={score_row.severity} tier={score_row.tier}")
        print(f"recommendation: {score_row.recommendation}")

    print(f"\nevent_id = {event_id}")
    print("Go show it on the dashboard now. When you're done demoing, clean up with:")
    print(f"  python -m scripts.demo_seed_anomaly cleanup --event-id {event_id}")


def cleanup(event_id: str | None, remove_all: bool) -> None:
    with SessionLocal() as session:
        if remove_all:
            ids = [
                row.event_id
                for row in session.query(CanonicalEventRow).filter(CanonicalEventRow.event_id.like(f"{DEMO_PREFIX}%"))
            ]
        elif event_id:
            ids = [event_id]
        else:
            raise SystemExit("cleanup needs --event-id <id> or --all")

        for eid in ids:
            session.query(AnomalyScoreRow).filter(AnomalyScoreRow.event_id == eid).delete()
            session.query(CanonicalEventRow).filter(CanonicalEventRow.event_id == eid).delete()
        session.commit()
    print(f"removed {len(ids)} demo event(s): {ids}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    seed_parser = sub.add_parser("seed", help="Post one controlled anomalous event through the real ingest pipeline.")
    seed_parser.add_argument("--user", default="user-Sarah", help="Existing user_id to seed the event for.")
    seed_parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    seed_parser.add_argument("--api-url", default="http://localhost:8000")

    cleanup_parser = sub.add_parser("cleanup", help="Remove a seeded demo event (and its score row) afterward.")
    cleanup_parser.add_argument("--event-id", help="The event_id printed by `seed`.")
    cleanup_parser.add_argument("--all", action="store_true", help=f"Remove every {DEMO_PREFIX}* row instead of one.")

    args = parser.parse_args()
    if args.command == "seed":
        seed(args.user, args.tenant_id, args.api_url)
    else:
        cleanup(args.event_id, args.all)


if __name__ == "__main__":
    main()
