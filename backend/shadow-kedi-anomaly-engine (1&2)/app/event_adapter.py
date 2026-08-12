"""Adapter: CanonicalEventRow (real, Wazuh-sourced ingest data) -> SecurityEvent
(the shape build_baselines()/detect() expect).

Per the Step 0 inspection, this codebase has two event shapes that were never
connected: the real ingest pipeline (CanonicalEvent/CanonicalEventRow, fed by
the Wazuh connector via POST /v1/events) and the spec-shaped anomaly-detection
pipeline (SecurityEvent, baselines.py, detectors.py). baselines.py/detectors.py
are deliberately left untouched -- their logic is good. This module is the ONLY
place that bridges the two, so every "what's real vs. still a placeholder"
decision lives in one documented spot instead of being buried in detector
internals.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .baselines import build_baselines
from .database import CanonicalEventRow
from .models import EventType, SecurityEvent
from .repository import save_baselines

logger = logging.getLogger("shadow_kedi.adapter")

# --- department --------------------------------------------------------------
# CanonicalEventRow has NO department column at all (see Step 0 inspection) --
# Wazuh's default macOS ruleset carries no department/org-unit claim, so there
# is no real value to map. Using a single constant here is a deliberate,
# documented v1 placeholder, not a bug: every user lands in the same cohort, so
# Peer Comparison (detectors.py's peer_comparison signal) is real code running
# end-to-end -- it will not be *wrong*, just single-cohort and low-signal until
# a real department source (HR feed, IdP group, directory sync) exists. Named
# "tenant-default" rather than "Unclassified" specifically so it reads as an
# intentional v1 placeholder in logs/DB rows, not as missing/broken data.
TENANT_DEFAULT_DEPARTMENT = "tenant-default"

# --- event_type ----------------------------------------------------------
# SecurityEvent.EventType is {login, activity, transfer}. CanonicalEvent's
# event_type is collector-shaped: {network_access, installed_application,
# file_upload, dlp_outcome}. There's no clean 1:1 mapping. Decisions, in order
# of how much they matter against real data:
#
#  - installed_application -> ACTIVITY. An app being installed isn't a session
#    boundary or a data movement; "activity" is the closest of the three.
#  - file_upload            -> TRANSFER. Data leaving the device -- the
#    textbook TRANSFER case, even though no live event currently carries a
#    byte count (see bytes_transferred below -- this is forward-looking).
#  - dlp_outcome            -> TRANSFER. A DLP outcome is fundamentally about
#    data handling/movement; grouping it with file_upload keeps the mapping
#    forward-compatible with the day DLP tooling starts reporting sizes.
#  - network_access         -> see _classify_network_access() below. This is
#    the ONLY event_type actually flowing through the live macOS fleet today
#    (confirmed against the live DB while building this adapter: 25/25 rows),
#    and it is NOT uniformly "activity". Wazuh's default macOS ruleset tags
#    session boundaries -- logons, logoffs, screen locks -- as network_access
#    too, because the connector doesn't have a finer-grained category. A flat
#    network_access -> activity mapping would make Time Anomaly permanently
#    dormant against 100% of current real data, which defeats the point, so
#    network_access events are sub-classified by rule_description keyword
#    instead. Still rule-based and transparent -- no ML.
_LOGIN_KEYWORDS = ("logon", "logged", "log on", "session", "screen locked")

_STATIC_EVENT_TYPE_MAP: dict[str, EventType] = {
    "installed_application": EventType.ACTIVITY,
    "file_upload": EventType.TRANSFER,
    "dlp_outcome": EventType.TRANSFER,
}


def _classify_network_access(rule_description: str | None) -> EventType:
    """Sub-classify a network_access event as LOGIN vs ACTIVITY by keyword
    match on Wazuh's own rule_description text.

    Grounded against every distinct rule seen in the live fleet as of Step 1:
    "Windows Logon Success", "Non network or service local logon.",
    "Non service account logged off.", "Special privileges assigned to new
    logon.", "Screen locked with userID:.", and "Session 100040 has been
    created." all match and become LOGIN. "Wazuh agent started.", "Wazuh
    agent disconnected.", "Host-based anomaly detection event (rootcheck).",
    "Listened ports status ... changed", and "User account changed" don't
    match and stay ACTIVITY -- "User account changed" in particular is a
    config-change event, not a reliable proxy for when a person showed up, so
    it's deliberately excluded even though it comes from the same rule family
    as the logon rules.

    Anything not matched defaults to ACTIVITY (never silently dropped). If
    Wazuh's ruleset changes or new rule text appears, the worst case is a
    login-shaped event being treated as generic activity -- not a crash and
    not a miscounted anomaly.
    """
    text = (rule_description or "").lower()
    return EventType.LOGIN if any(keyword in text for keyword in _LOGIN_KEYWORDS) else EventType.ACTIVITY


def _map_event_type(row: CanonicalEventRow) -> EventType:
    if row.event_type == "network_access":
        metadata = row.metadata_json or {}
        return _classify_network_access(metadata.get("rule_description"))
    return _STATIC_EVENT_TYPE_MAP.get(row.event_type, EventType.ACTIVITY)


def to_security_event(row: CanonicalEventRow) -> SecurityEvent:
    """Convert one real, persisted CanonicalEventRow into the SecurityEvent
    shape build_baselines()/detect() expect. May raise pydantic's
    ValidationError (e.g. a user_id shorter than SecurityEvent's 8-char
    minimum) -- callers converting a batch should catch per-row, see
    canonical_events_to_security_events().
    """
    return SecurityEvent(
        user_id=row.user_id,
        department=TENANT_DEFAULT_DEPARTMENT,
        occurred_at=row.occurred_at,
        event_type=_map_event_type(row),
        # No live Wazuh macOS event carries a transfer size today -- Volume
        # Anomaly is dormant (never fires, never crashes), not broken.
        # Revisit once file_upload/dlp_outcome events report real byte counts.
        bytes_transferred=0,
        # No DNS-query events exist under the current macOS ruleset -- New
        # Domain Detection correctly finds nothing to compare against and
        # flags nothing. Dormant, not broken. Revisit once domain-carrying
        # events land.
        domain=None,
    )


def canonical_events_to_security_events(rows: list[CanonicalEventRow]) -> list[SecurityEvent]:
    """Convert a batch, skipping (and logging) any row that fails SecurityEvent
    validation rather than letting one bad row abort the whole recompute."""
    events: list[SecurityEvent] = []
    for row in rows:
        try:
            events.append(to_security_event(row))
        except ValidationError as exc:
            logger.warning("skipping event_id=%s during SecurityEvent adaptation: %s", row.event_id, exc)
    return events


def recompute_baselines_from_canonical_events(session: Session, secret: str, window_days: int = 7) -> dict[str, int]:
    """Query the trailing `window_days` of canonical_events, adapt them to
    SecurityEvent, and run the existing (untouched) build_baselines() /
    save_baselines(). This is the one function that turns real ingested data
    into real baselines -- the Celery beat task and any manual/dev trigger
    should call this rather than re-implementing the query+adapt+build+save
    sequence.

    New-user / partial-history edge case: build_baselines() already handles
    this correctly with no changes needed here -- it doesn't require a full
    window, it just uses whatever events are in the list, and it records
    `sample_days` on every UserBaseline it produces. A user with 1 day of
    history gets a baseline built from 1 day of history, honestly labeled via
    sample_days rather than silently padded or skipped. Downstream consumers
    (the Step 3 orchestrator) can use sample_days as a confidence signal --
    e.g. discount or flag anomalies for low sample_days -- rather than this
    function guessing at a cutoff.
    """
    cutoff = datetime.now(UTC) - timedelta(days=window_days)
    rows = session.execute(
        select(CanonicalEventRow).where(CanonicalEventRow.occurred_at >= cutoff)
    ).scalars().all()
    events = canonical_events_to_security_events(rows)
    if not events:
        return {"events_considered": len(rows), "events_adapted": 0, "users_recomputed": 0, "departments_recomputed": 0}

    users, peers = build_baselines(events, secret)
    save_baselines(session, users, peers)
    return {
        "events_considered": len(rows),
        "events_adapted": len(events),
        "users_recomputed": len(users),
        "departments_recomputed": len(peers),
    }
