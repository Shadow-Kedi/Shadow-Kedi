# shadow_kedi_adapter.py
"""Adapter: CanonicalEventRow (real, Wazuh-sourced ingest data, see
database.py) -> the day-level feature dict pipeline.scorer.ShadowKediScorer
expects.

Mirrors event_adapter.py's own structure and honesty conventions
deliberately, not by coincidence -- this is the SAME kind of bridge
(CanonicalEventRow -> a different detection pipeline's input shape) their
own team already built once for baselines.py/detectors.py, and the two
should stay recognizable as siblings, not diverge in style.

UPDATE 2026-08-16: metadata_json now stores win_eventdata (queryName/
image/user), added directly to wazuh_connector.py in the team's absence
(see that file's own inline note explaining the decision). is_exfil_domain
and is_removable_media are now REAL, extracted from win_eventdata's
queryName/image below -- not dormant anymore, though still 0 for any
event ingested before that change, and for the entire current macOS
fleet (Sysmon is Windows-only; confirmed zero live events carry this
field today, per Backend's own Wazuh deployment doc). bytes_sent_log,
file_size_log, domain_len, has_domain, and has_file remain genuinely
dormant -- no current event, on any OS, carries byte counts or file
sizes even in principle yet.

UPDATE 2026-08-17 (pre-demo integration pass): two correctness fixes,
found while wiring this into app/ml_scoring.py for real:
  1. is_off_hours / is_weekend were being left at the blanket 0 default
     below despite being trivially derivable from occurred_at (every row
     already has it -- no sensor/OS gap, unlike the fields above). Now
     computed for real: is_off_hours is the fraction of the day's events
     outside 07:00-19:00 (mean, matching classifier_daily.py's MEAN_COLS
     aggregation); is_weekend is a single value for the day.
  2. device_managed / has_admin_rights / security_training_current (CASB-
     only concepts with no Wazuh equivalent) were defaulting to 0, but
     feature_engineer.py's own convention for "not applicable to this
     source" is the sentinel -1, not 0 (see that module: "-1... a real,
     informative value... not missing data to be imputed away"). A 0
     told the model "confirmed unmanaged / no admin rights / training not
     current" instead of "unknown for this source" -- now corrected to -1
     to match what the model actually saw for these columns in training.
Neither fix changes WHICH features are populated from live data -- see
the 2026-08-16 note and app/ml_scoring.py's own accounting for that; this
only fixes two fields that should never have been dormant in the first
place.

Usage:
    from shadow_kedi_adapter import canonical_rows_to_daily_features
    daily_features = canonical_rows_to_daily_features(rows)  # one user's rows, one day
"""

from __future__ import annotations

import logging
import math
from collections import Counter

logger = logging.getLogger("shadow_kedi.ml_adapter")

# Same rule_description keyword approach as event_adapter.py's
# _classify_network_access -- kept as a SEPARATE constant rather than
# importing theirs, since this pipeline's feature set draws a finer
# distinction than their LOGIN/ACTIVITY split (see EVENT_TYPE_MAP below).
_LOGIN_KEYWORDS = ("logon", "logged", "log on", "session", "screen locked")

# CanonicalEventRow.event_type -> this pipeline's et_* feature columns.
# Same "no clean 1:1 mapping" problem event_adapter.py documents for its
# own 3-way split -- resolved independently here since this pipeline's
# feature set is a different shape (10 et_* columns, not 3).
_EVENT_TYPE_MAP = {
    "installed_application": "et_app_install",
    "file_upload": "et_file_transfer",
    "dlp_outcome": "et_file_transfer",
    "file_integrity": None,  # deliberately excluded -- see module docstring's FIM note, same reasoning as event_adapter.py's file_integrity->ACTIVITY choice
}


def _classify_network_access(rule_description: str | None) -> str:
    text = (rule_description or "").lower()
    return "et_login_event" if any(k in text for k in _LOGIN_KEYWORDS) else "et_browser_activity"


def _event_feature_column(row) -> str | None:
    if row.event_type == "network_access":
        metadata = row.metadata_json or {}
        return _classify_network_access(metadata.get("rule_description"))
    return _EVENT_TYPE_MAP.get(row.event_type)


EXFIL_DOMAIN_HINTS = (
    "wikileaks", "mega.nz", "mega.co", "wetransfer", "pastebin",
    "anonfiles", "gofile", "sendspace", "dropbox", "drive.google",
)
REMOVABLE_MEDIA_HINTS = ("usb", "removable", "d:\\", "e:\\", "f:\\")


def _extract_win_eventdata(row) -> dict:
    """win_eventdata was added to metadata_json on 2026-08-16 (see
    wazuh_connector.py) -- absent for any event ingested before that
    change, and absent for every event from the current macOS fleet
    regardless of date (Sysmon is Windows-only, confirmed in Backend's
    own Wazuh deployment doc). Returns {} in both cases rather than
    raising, so callers degrade to the dormant defaults below exactly
    the way they did before this field existed."""
    metadata = row.metadata_json or {}
    return metadata.get("win_eventdata") or {}


def canonical_rows_to_daily_features(rows: list, feature_cols: list[str]) -> dict:
    """
    rows: all CanonicalEventRow instances for ONE user on ONE calendar
    day (caller's responsibility to group by user_id + occurred_at.date()
    before calling this -- see recompute_shadow_kedi_scores_from_canonical_events
    for the real grouped-query version).
    feature_cols: the trained model's exact required feature list (from
    ShadowKediScorer.feature_cols) -- only those features get populated;
    anything not in this adapter's coverage is filled with a neutral
    default (0) rather than omitted, so score_daily_features() never
    raises for a legitimately-scoreable day.

    Returns a dict ready for pipeline.scorer.ShadowKediScorer.score_daily_features().
    """
    n_events = len(rows)
    type_counts = Counter()
    has_exfil_domain = False
    has_removable_media = False
    n_off_hours = 0

    for row in rows:
        col = _event_feature_column(row)
        if col:
            type_counts[col] += 1
        else:
            logger.debug("event_id=%s: event_type=%s has no feature-column mapping, contributing to daily_event_count only", row.event_id, row.event_type)

        # Real extraction now that win_eventdata may be present (see
        # wazuh_connector.py's 2026-08-16 change) -- still gracefully
        # dormant (both flags stay False) for any event where it's
        # absent, which today is 100% of the live macOS fleet.
        eventdata = _extract_win_eventdata(row)
        query_name = (eventdata.get("queryName") or "").lower()
        image = (eventdata.get("image") or "").lower()
        if query_name and any(hint in query_name for hint in EXFIL_DOMAIN_HINTS):
            has_exfil_domain = True
        if image and any(hint in image for hint in REMOVABLE_MEDIA_HINTS):
            has_removable_media = True

        # is_off_hours: same hour cutoff feature_engineer.py uses per event
        # (hour<7 or hour>=19), counted here per event so the MEAN_COLS
        # aggregation below can average it the same way
        # classifier_daily.build_daily_features() does -- fraction of the
        # day's events that landed outside normal hours, not just a
        # single day-level flag.
        if row.occurred_at.hour < 7 or row.occurred_at.hour >= 19:
            n_off_hours += 1

    daily = {f: 0 for f in feature_cols}

    if "daily_event_count" in daily:
        daily["daily_event_count"] = n_events

    for col, count in type_counts.items():
        if col in daily:
            daily[col] = count
        share_col = f"{col}_share"
        if share_col in daily and n_events > 0:
            daily[share_col] = round(count / n_events, 4)

    if "is_exfil_domain" in daily:
        daily["is_exfil_domain"] = int(has_exfil_domain)
    if "is_removable_media" in daily:
        daily["is_removable_media"] = int(has_removable_media)

    # ADDED 2026-08-17: is_off_hours / is_weekend were previously left at
    # the blanket 0 default below along with the genuinely-dormant fields --
    # wrongly, since both are trivially derivable from occurred_at, which
    # every row already has (no sensor/OS gap unlike is_exfil_domain/
    # is_removable_media above). MEAN_COLS in classifier_daily.py averages
    # these per event, so is_off_hours is the fraction of the day's events
    # that were off-hours; is_weekend is a single value for the day (rows
    # are already grouped to one calendar day by the caller, so every row
    # agrees -- taking it from the first row is safe, not an approximation).
    if "is_off_hours" in daily and n_events > 0:
        daily["is_off_hours"] = round(n_off_hours / n_events, 4)
    if "is_weekend" in daily:
        daily["is_weekend"] = int(rows[0].occurred_at.weekday() >= 5)

    # --- fields STILL requiring data no current event carries at all ---
    # Unlike is_exfil_domain/is_removable_media above (now real, just
    # usually 0 given the macOS fleet), these have no live data source
    # yet even in principle -- byte counts and file sizes aren't part of
    # win_eventdata for a DNS-query or process-launch event. Genuinely
    # dormant, not broken, same framing as event_adapter.py's own
    # bytes_transferred=0 for the exact same underlying reason.
    for f in ("bytes_sent_log", "file_size_log", "domain_len", "has_domain", "has_file"):
        if f in daily:
            daily[f] = 0

    # ADDED 2026-08-17: feature_engineer.py's own convention for "not
    # applicable/unknown for this source" is the sentinel -1 (see that
    # module's docstring: "-1... a real, informative value... not missing
    # data to be imputed away"), NOT 0 -- but the blanket default above
    # was silently giving these three CASB-only fields (no Wazuh
    # equivalent exists) a 0, which the model reads as a confident
    # "unmanaged device" / "no admin rights" / "training not current"
    # rather than "genuinely unknown for this source". Overwritten here to
    # match what the model actually saw for these columns at training time.
    for f in ("device_managed", "has_admin_rights", "security_training_current"):
        if f in daily:
            daily[f] = -1

    return daily
