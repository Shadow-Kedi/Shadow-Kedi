# pipeline/normalizer.py
"""
Step 3 — Normalizer

Cleans, standardizes, and deduplicates ShadowKediEvent records regardless
of source (synthetic JSON now, real Wazuh agents later). Supports two
usage patterns:

  In-memory (for streaming / real-time ingestion once Wazuh is live):
      from pipeline.normalizer import normalize_event, normalize_events
      clean_event = normalize_event(raw_event)
      clean_batch, quarantined, stats = normalize_events(raw_events)

  File-based (matches the rest of the pipeline's data/ convention):
      python -m pipeline.normalizer
      python -m pipeline.normalizer --in data/synthetic/synthetic_events.json --out data/processed/normalized_events.json
      python -m pipeline.normalizer --incremental   # skip event_ids already in --out from a prior run
"""

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from pipeline.schema import EventType, ShadowKediEvent

# ============================================================
# Canonicalization helpers
# ============================================================

# Strips a trailing parenthetical qualifier: "Zoom (Corporate)" -> "Zoom"
_APP_QUALIFIER_RE = re.compile(r"\s*\([^)]*\)\s*$")


def canonicalize_app_name(name: str | None) -> str | None:
    if not name:
        return name
    base = _APP_QUALIFIER_RE.sub("", name).strip()
    return base or name


def canonicalize_domain(domain: str | None) -> str | None:
    if not domain:
        return domain
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def to_utc(dt: datetime) -> datetime:
    """Tag naive timestamps as UTC; convert aware timestamps to UTC.
    Assumes naive timestamps from synthetic/local sources are already UTC —
    revisit this assumption once real Wazuh agents report their own tz."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


NETWORK_EVENT_TYPES = {
    EventType.NETWORK_CONN, EventType.DNS_QUERY,
    EventType.BROWSER_ACTIVITY, EventType.CLOUD_UPLOAD,
}
FILE_EVENT_TYPES = {
    EventType.FILE_ACCESS, EventType.FILE_TRANSFER, EventType.CLOUD_UPLOAD,
}


# ============================================================
# Stats
# ============================================================

@dataclass
class NormalizationStats:
    total_in: int = 0
    normalized: int = 0
    quarantined: int = 0
    duplicates_dropped: int = 0
    app_names_canonicalized: int = 0
    domains_canonicalized: int = 0
    fields_imputed: int = 0


# ============================================================
# Core normalization (in-memory)
# ============================================================

def normalize_event(event: ShadowKediEvent, stats: NormalizationStats | None = None) -> ShadowKediEvent:
    """Normalize a single ShadowKediEvent. Mutates and returns it."""

    # --- timestamp -> UTC ---
    event.timestamp = to_utc(event.timestamp)

    # --- identity fields: trim whitespace, guard against blanks/absent fields ---
    event.username = (getattr(event, "username", None) or "").strip()
    event.hostname = (getattr(event, "hostname", None) or "").strip()
    event.client_id = (getattr(event, "client_id", None) or "").strip()
    if not event.username or not event.client_id:
        raise ValueError(f"event {getattr(event, 'event_id', '?')} missing required identity field(s) after normalization")

    # --- domain canonicalization ---
    if event.destination_domain:
        canonical = canonicalize_domain(event.destination_domain)
        if canonical != event.destination_domain:
            if stats:
                stats.domains_canonicalized += 1
            event.destination_domain = canonical

    # --- app name canonicalization (preserve original in raw_data) ---
    if event.app_name:
        canonical = canonicalize_app_name(event.app_name)
        if canonical != event.app_name:
            event.raw_data = dict(event.raw_data or {})
            event.raw_data.setdefault("app_name_original", event.app_name)
            event.app_name = canonical
            if stats:
                stats.app_names_canonicalized += 1

    # --- imputation: fill type-appropriate defaults instead of leaving None ---
    imputed = 0
    if event.event_type in NETWORK_EVENT_TYPES:
        if event.bytes_sent is None:
            event.bytes_sent = 0
            imputed += 1
        if event.bytes_received is None:
            event.bytes_received = 0
            imputed += 1
    if event.event_type in FILE_EVENT_TYPES:
        if event.file_size_kb is None:
            event.file_size_kb = 0.0
            imputed += 1

    if event.risk_reasons is None:
        event.risk_reasons = []
        imputed += 1
    if event.mitre_tags is None:
        event.mitre_tags = []
        imputed += 1
    if event.is_anomaly is None:
        event.is_anomaly = False
        imputed += 1

    if stats:
        stats.fields_imputed += imputed

    return event


def normalize_events(
    events: list[ShadowKediEvent],
    existing_ids: set[str] | None = None,
) -> tuple[list[ShadowKediEvent], list[dict], NormalizationStats]:
    """
    Normalize a batch of events.

    existing_ids: event_ids already normalized in a prior run — pass this
    for incremental/streaming use to dedupe across calls, not just within
    the current batch.

    Returns (normalized_events, quarantined_records, stats).
    Quarantined records are never raised/dropped silently — they're
    returned as {"event_id", "error"} dicts so the caller decides what
    to do with them (log, alert, retry, discard).
    """
    stats = NormalizationStats(total_in=len(events))
    seen = set(existing_ids or [])
    normalized: list[ShadowKediEvent] = []
    quarantined: list[dict] = []

    for e in events:
        event_id = getattr(e, "event_id", None)

        if event_id in seen:
            stats.duplicates_dropped += 1
            continue
        seen.add(event_id)

        try:
            clean = normalize_event(e, stats=stats)
            # re-validate the mutated event against the schema before accepting it
            ShadowKediEvent.model_validate(clean.model_dump())
            normalized.append(clean)
            stats.normalized += 1
        except (ValidationError, ValueError, TypeError, AttributeError, KeyError) as exc:
            quarantined.append({"event_id": event_id, "error": f"{type(exc).__name__}: {exc}"})
            stats.quarantined += 1

    return normalized, quarantined, stats


# ============================================================
# File-based I/O
# ============================================================

def load_events_from_json(path: str) -> list[ShadowKediEvent]:
    with open(path) as f:
        raw = json.load(f)
    events = []
    for d in raw:
        try:
            events.append(ShadowKediEvent.model_validate(d))
        except ValidationError:
            # malformed even before normalization — still quarantine it below
            events.append(d)  # left as dict; normalize_events will fail it cleanly
    return events


def load_existing_ids(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    with open(p) as f:
        raw = json.load(f)
    return {d["event_id"] for d in raw}


def save_events_to_json(events: list[ShadowKediEvent], path: str):
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump([json.loads(e.model_dump_json()) for e in events], f, indent=2, default=str)


def save_quarantine(records: list[dict], path: str):
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(records, f, indent=2)


# ============================================================
# Streaming path — for large (.jsonl) sources like the CERT loader,
# where loading everything into memory first isn't safe. Processes
# and writes one line at a time; memory stays bounded regardless of
# input size.
# ============================================================

def stream_normalize_jsonl(in_path: str, out_path: str, quarantine_path: str,
                            incremental: bool = False, progress_every: int = 200_000):
    seen: set = set()
    out_p = Path(out_path)
    if incremental and out_p.exists():
        with open(out_p) as f:
            for line in f:
                line = line.strip()
                if line:
                    seen.add(json.loads(line).get("event_id"))
        print(f"Incremental mode: {len(seen)} event_ids already normalized previously.")

    out_p.parent.mkdir(parents=True, exist_ok=True)
    quar_p = Path(quarantine_path)
    quar_p.parent.mkdir(parents=True, exist_ok=True)

    stats = NormalizationStats()
    mode = "a" if (incremental and out_p.exists()) else "w"

    with open(in_path) as fin, open(out_p, mode) as fout, open(quar_p, "w") as fquar:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            stats.total_in += 1

            try:
                d = json.loads(line)
                event = ShadowKediEvent.model_validate(d)
            except Exception as exc:
                fquar.write(json.dumps({"event_id": (d.get("event_id") if isinstance(d, dict) else None),
                                         "error": f"parse/validate: {exc}"}) + "\n")
                stats.quarantined += 1
                continue

            event_id = event.event_id
            if event_id in seen:
                stats.duplicates_dropped += 1
                continue
            seen.add(event_id)

            try:
                clean = normalize_event(event, stats=stats)
                ShadowKediEvent.model_validate(clean.model_dump())
                fout.write(clean.model_dump_json())
                fout.write("\n")
                stats.normalized += 1
            except (ValidationError, ValueError, TypeError, AttributeError, KeyError) as exc:
                fquar.write(json.dumps({"event_id": event_id, "error": f"{type(exc).__name__}: {exc}"}) + "\n")
                stats.quarantined += 1

            if stats.total_in % progress_every == 0:
                print(f"    ... {stats.total_in} lines processed so far "
                      f"({stats.normalized} normalized, {stats.quarantined} quarantined)")

    return stats


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Normalize ShadowKediEvent records.")
    parser.add_argument("--in", dest="in_path", default="data/synthetic/synthetic_events.json",
                         help="Input file: .json (array, loaded fully into memory) or "
                              ".jsonl (one record per line, streamed — use for large sources like CERT)")
    parser.add_argument("--out", dest="out_path", default="data/processed/normalized_events.json",
                         help="Output path for normalized events (matches input format: .json or .jsonl)")
    parser.add_argument("--quarantine", default="data/processed/quarantined_events.json",
                         help="Output path for records that failed normalization/validation")
    parser.add_argument("--incremental", action="store_true",
                         help="Skip event_ids already present in --out (dedupe across runs)")
    args = parser.parse_args()

    if args.in_path.lower().endswith(".jsonl"):
        print(f"Streaming (low-memory) mode: {args.in_path} -> {args.out_path}")
        stats = stream_normalize_jsonl(args.in_path, args.out_path, args.quarantine,
                                        incremental=args.incremental)
    else:
        print(f"Loading raw events from {args.in_path} ...")
        raw_events = load_events_from_json(args.in_path)
        print(f"Loaded {len(raw_events)} raw records.")

        existing_ids = load_existing_ids(args.out_path) if args.incremental else None
        if existing_ids:
            print(f"Incremental mode: {len(existing_ids)} event_ids already normalized previously.")

        normalized, quarantined, stats = normalize_events(raw_events, existing_ids=existing_ids)

        save_events_to_json(normalized, args.out_path)
        if quarantined:
            save_quarantine(quarantined, args.quarantine)

    print()
    print(f"Normalized:              {stats.normalized}")
    print(f"Duplicates dropped:      {stats.duplicates_dropped}")
    print(f"Quarantined (invalid):   {stats.quarantined}")
    print(f"App names canonicalized: {stats.app_names_canonicalized}")
    print(f"Domains canonicalized:   {stats.domains_canonicalized}")
    print(f"Fields imputed:          {stats.fields_imputed}")
    print()
    print(f"Wrote: {args.out_path}")
    if stats.quarantined:
        print(f"Wrote quarantine log: {args.quarantine}")


if __name__ == "__main__":
    main()
