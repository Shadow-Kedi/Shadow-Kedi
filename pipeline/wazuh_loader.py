# pipeline/wazuh_loader.py
"""
Converts real Wazuh alert JSON (the shape confirmed by Backend/Infra and
Detection/Security's Q&A samples) into ShadowKediEvent objects, matching
the same pattern cert_loader.py and synthetic_data.py already use for
the other two sources.

CONFIRMED SCHEMA (from the team's real sample, not assumed):
    rule.id             -> maps to a category via RULE_ID_TO_EVENT_TYPE
    rule.level           -> Wazuh's own severity (kept in raw_data, NOT
                             used as risk_score -- this pipeline's own
                             calibrated risk_engine.py score is the
                             canonical severity, per this project's own
                             history of NOT trusting a raw external scale
                             at face value; see risk_categorization.py)
    rule.mitre.id[0]     -> cross-checked against pipeline/mitre_mapping.py
                             (kept as a data point, not blindly trusted --
                             own MITRE lookup remains canonical so a future
                             rule change on their side can't silently
                             change what tag we assign)
    agent.name / agent.id -> hostname / agent_id
    data.win.eventdata.user -> "HOSTNAME\\username" -- split to just the
                             username (matches the real CSV export's own
                             known gap: raw Wazuh identity is host-scoped;
                             this at least recovers the real username
                             where Sysmon provides one, better than the
                             CSV export's hostname-only fallback)
    data.win.eventdata.queryName -> destination_domain (DNS-based rules)
    data.win.eventdata.image -> the launching process path
    timestamp            -> event timestamp

STATUS: rules are deployed per Backend's answer, but won't produce real
traffic until Sysmon is installed on endpoints (the exact gap already
diagnosed from the real CSV export). This loader is ready for that day;
it has not been run against real fired alerts yet, since none exist.

Usage:
    from pipeline.wazuh_loader import convert_wazuh_alert
    event = convert_wazuh_alert(alert_json, client_id="acme-corp")
"""

from datetime import datetime, timezone
import re

from pipeline.mitre_mapping import get_mitre_tag
from pipeline.schema import EventType, ShadowKediEvent

DEPT_HOSTNAME_RE = re.compile(r"^[A-Z0-9]+-([A-Z]+)-\d+$")


def department_from_hostname(hostname: str) -> str:
    """Best-effort, DOCUMENTED STOPGAP -- Wazuh has no native department
    field. Extracts a guess from hostnames following a
    'WIN10-<DEPT>-##' convention (confirmed present in the real sample:
    'WIN10-FINANCE-07' -> 'Finance'). Returns 'Unclassified' for any
    hostname that doesn't match -- same as the real CSV export already
    showed for machines without a department-coded name. This is NOT a
    real fix for the identity/org gap; flag that to Backend/Detection as
    a real integration need (AD, HR system, etc.), not something to rely
    on long-term."""
    m = DEPT_HOSTNAME_RE.match(hostname or "")
    return m.group(1).capitalize() if m else "Unclassified"

# rule.id -> (EventType, shadow_it_category, cert_signal-equivalent)
# Sourced directly from Detection/Security's rule-to-category answer.
# Base/gating rules (xxxx0, no_full_log in their spec) never alert on
# their own and are not included here -- only rules that actually fire.
RULE_ID_TO_INFO = {
    "100011": (EventType.DNS_QUERY, "Unapproved Cloud Storage & File Sharing", "is_exfil_domain"),
    "100012": (EventType.DNS_QUERY, "Unapproved Cloud Storage & File Sharing", "is_exfil_domain"),
    "100021": (EventType.DNS_QUERY, "Unsanctioned AI Tools", "is_exfil_domain"),
    "100022": (EventType.DNS_QUERY, "Unsanctioned AI Tools", "is_exfil_domain"),
    "100031": (EventType.APP_LAUNCH, "Unapproved Cloud Storage & File Sharing", "is_exfil_domain"),
    "100033": (EventType.DNS_QUERY, "Unapproved Cloud Storage & File Sharing", "is_exfil_domain"),
    "100041": (EventType.APP_LAUNCH, "Unauthorized Software Installs", None),
    "100042": (EventType.APP_INSTALL, "Unauthorized Software Installs", None),
    "100043": (EventType.APP_LAUNCH, "Unauthorized Software Installs", None),
    "100050": (EventType.FILE_TRANSFER, "Removable Media & Offline Transfer", "is_removable_media"),
    "100060": (EventType.FILE_ACCESS, None, None),  # sensitive data pattern match -- no CASB category equivalent
    "100061": (EventType.FILE_ACCESS, None, None),
}


def extract_username(win_user: str) -> str:
    """Wazuh/Sysmon's data.win.eventdata.user is 'HOSTNAME\\username' --
    split to just the username. Falls back to the full string if the
    expected separator isn't present, rather than raising, since a
    malformed/unexpected value here shouldn't crash the whole load."""
    if win_user and "\\" in win_user:
        return win_user.split("\\", 1)[1]
    return win_user or "unknown"


def convert_wazuh_alert(alert: dict, client_id: str) -> ShadowKediEvent | None:
    """Returns None (not an exception) for a rule ID this loader doesn't
    recognize -- new rules can be added to RULE_ID_TO_INFO as Detection
    ships them, without every unrecognized alert crashing the load."""
    rule_id = alert.get("rule", {}).get("id")
    if rule_id not in RULE_ID_TO_INFO:
        return None

    event_type, shadow_it_category, cert_signal = RULE_ID_TO_INFO[rule_id]

    win_data = alert.get("data", {}).get("win", {})
    eventdata = win_data.get("eventdata", {})
    agent = alert.get("agent", {})
    rule = alert.get("rule", {})

    username = extract_username(eventdata.get("user"))
    domain = eventdata.get("queryName")
    process_image = eventdata.get("image")

    ts_raw = alert.get("timestamp")
    timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)

    mitre_tag = get_mitre_tag(shadow_it_category=shadow_it_category, cert_signal=cert_signal)
    # cross-check against what Wazuh's own rule reported, without trusting it blindly
    reported_mitre = (rule.get("mitre", {}).get("id") or [None])[0]
    if reported_mitre and reported_mitre != mitre_tag:
        # kept as a raw_data note rather than silently overriding either
        # value -- worth surfacing if the two sides drift, not hiding it
        mitre_note = f"wazuh_reported={reported_mitre}, pipeline_assigned={mitre_tag}"
    else:
        mitre_note = None

    event = ShadowKediEvent(
        event_id=alert.get("id", f"wazuh-{rule_id}-{ts_raw}"),
        timestamp=timestamp,
        agent_id=agent.get("id", "unknown"),
        hostname=agent.get("name", "unknown"),
        username=username,
        client_id=client_id,
        event_type=event_type,
        source="wazuh",
        destination_domain=domain,
        raw_data={
            "wazuh_rule_id": rule_id,
            "wazuh_rule_level": rule.get("level"),
            "wazuh_rule_description": rule.get("description"),
            "wazuh_groups": rule.get("groups"),
            "process_image": process_image,
            "shadow_it_category": shadow_it_category,
            "department": department_from_hostname(agent.get("name", "")),  # documented stopgap, see department_from_hostname()
            "mitre_tag": mitre_tag,
            "mitre_reconciliation_note": mitre_note,
        },
        mitre_tags=[mitre_tag],
    )
    return event


def load_wazuh_alerts(alerts: list, client_id: str) -> list:
    """Batch conversion, skipping (not crashing on) any alert with an
    unrecognized rule ID. Returns the converted events plus a count of
    skipped alerts for visibility into coverage gaps."""
    events = []
    skipped = 0
    for alert in alerts:
        event = convert_wazuh_alert(alert, client_id)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    if skipped:
        print(f"NOTE: skipped {skipped} alert(s) with unrecognized rule IDs "
              f"(not yet in RULE_ID_TO_INFO -- add them as Detection ships new rules).")
    return events
