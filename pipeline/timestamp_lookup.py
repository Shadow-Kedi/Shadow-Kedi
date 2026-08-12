# pipeline/timestamp_lookup.py
"""
Shared timestamp-recovery utilities, used by both risk_engine.py and
classifier_daily.py to attach real calendar dates to sampled events
(feature_matrix.csv only carries hour/day_of_week, not full timestamps).

Extracted into its own module specifically so risk_engine.py and
classifier_daily.py can each import from here without importing from
EACH OTHER -- they used to import these functions directly from one
another, which works until both files need something from the other
(risk_engine.py wiring in classifier_daily.py's trained model), at which
point it becomes a circular import. A shared leaf module fixes that.
"""

import json


def load_casb_lookup(casb_normalized_path: str) -> dict:
    """event_id -> {timestamp, shadow_it_category} for CASB events only
    (small enough to load in full)."""
    lookup = {}
    with open(casb_normalized_path) as f:
        events = json.load(f)
    for e in events:
        raw = e.get("raw_data") or {}
        lookup[e["event_id"]] = {
            "timestamp": e.get("timestamp"),
            "shadow_it_category": raw.get("shadow_it_category"),
        }
    return lookup


def load_cert_timestamps(cert_normalized_path: str, needed_ids: set, progress_every: int = 5_000_000) -> dict:
    """Single streaming pass over the (potentially huge) CERT jsonl file,
    extracting timestamps ONLY for event_ids in `needed_ids`. Memory stays
    bounded by the size of needed_ids, not the source file."""
    lookup = {}
    n_scanned = 0
    with open(cert_normalized_path) as f:
        for line in f:
            n_scanned += 1
            if n_scanned % progress_every == 0:
                print(f"    ... {n_scanned} CERT lines scanned, {len(lookup)}/{len(needed_ids)} timestamps found so far")
            # cheap pre-check before a full JSON parse: event_id is near the
            # start of each line's JSON, but simplest robust approach is to
            # just parse and check -- still fast enough for one pass.
            event = json.loads(line)
            eid = event.get("event_id")
            if eid in needed_ids:
                lookup[eid] = event.get("timestamp")
                if len(lookup) == len(needed_ids):
                    break
    print(f"CERT timestamp lookup: found {len(lookup)}/{len(needed_ids)} after scanning {n_scanned} lines.")
    return lookup
