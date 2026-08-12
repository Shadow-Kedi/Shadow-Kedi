"""One-time (or repeatable) backfill: score every canonical_events row that
doesn't yet have an anomaly_scores row, using whatever baselines are
currently saved. Chosen over leaving historical events un-scored so the
dashboard doesn't show a confusing split between old-style (rule_level
heuristic) and new-style (real orchestrator) alerts -- after this runs once,
every alert on the dashboard came from the same Step 3 pipeline.

Safe to re-run: score_and_persist() upserts by event_id, and by default this
only scores events that don't already have a row. Pass --rescore-all to force
recomputing every event (e.g. after a baseline recompute you want reflected
retroactively -- note this intentionally changes historical scores, so use it
deliberately, not as a matter of course).

Usage (from inside the api/worker container, where the app package and its
dependencies are installed):
    python -m scripts.backfill_anomaly_scores
    python -m scripts.backfill_anomaly_scores --rescore-all
"""
import argparse

from sqlalchemy import select

from app.config import settings
from app.database import AnomalyScoreRow, CanonicalEventRow, SessionLocal
from app.orchestrator import score_and_persist


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rescore-all", action="store_true", help="Recompute even events that already have a score.")
    args = parser.parse_args()

    cfg = settings()
    with SessionLocal() as session:
        rows = session.execute(select(CanonicalEventRow)).scalars().all()
        already_scored = (
            set()
            if args.rescore_all
            else {event_id for (event_id,) in session.execute(select(AnomalyScoreRow.event_id))}
        )
        targets = [row for row in rows if row.event_id not in already_scored]

        skipped = 0
        for row in targets:
            try:
                score_and_persist(session, row, cfg)
            except Exception as exc:  # noqa: BLE001 -- one bad row must not abort the backfill
                skipped += 1
                print(f"skipped event_id={row.event_id}: {exc}")

        print(
            f"scored {len(targets) - skipped} of {len(rows)} total events "
            f"({len(rows) - len(targets)} already had scores, {skipped} failed)"
        )


if __name__ == "__main__":
    main()
