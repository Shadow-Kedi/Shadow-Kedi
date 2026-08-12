# pipeline/synthetic_data.py
"""
Step 2 — Synthetic data source for the Shadow Kedi pipeline.

Rather than generating bare random events, this loads the richer
CASB-style "Shadow IT" synthetic dataset (10,000 events / 220 employees /
90 days / 6 labeled attack scenarios) and converts it into the project's
own ShadowKediEvent / UserProfile schema. That dataset already encodes
department skew, risk personas, and correlated attacker behavior, which
a from-scratch random generator wouldn't have — closer to what real
Wazuh-fed telemetry will eventually look like.

Usage:
    python pipeline/synthetic_data.py
    python pipeline/synthetic_data.py --events-file path/to/events.xlsx --employees-file path/to/employees.csv
    python pipeline/synthetic_data.py --out data/synthetic
"""

import argparse
import json
from pathlib import Path
from datetime import datetime

import pandas as pd

from pipeline.schema import ShadowKediEvent, UserProfile, EventType, RiskCategory

# ============================================================
# Mapping: CASB activity_type -> Shadow Kedi EventType
# ============================================================

ACTIVITY_TYPE_TO_EVENT_TYPE = {
    # File-related
    "file_view":                   EventType.FILE_ACCESS,
    "file_edit":                   EventType.FILE_ACCESS,
    "file_download":               EventType.FILE_ACCESS,
    "print_export":                EventType.FILE_ACCESS,
    "report_generate":             EventType.FILE_ACCESS,
    "file_upload":                 EventType.FILE_TRANSFER,
    "external_share_link_created": EventType.CLOUD_UPLOAD,

    # App / software
    "software_install":            EventType.APP_INSTALL,
    "browser_extension_install":   EventType.APP_INSTALL,
    "saas_signup":                 EventType.APP_INSTALL,
    "video_call":                  EventType.APP_LAUNCH,
    "screen_share":                EventType.APP_LAUNCH,
    "calendar_event":              EventType.APP_LAUNCH,
    "code_commit":                 EventType.APP_LAUNCH,
    "code_push":                   EventType.APP_LAUNCH,
    "pull_request":                EventType.APP_LAUNCH,
    "ticket_update":                EventType.APP_LAUNCH,
    "ticket_create":                EventType.APP_LAUNCH,
    "crm_update":                   EventType.APP_LAUNCH,
    "expense_submit":               EventType.APP_LAUNCH,

    # Identity / auth
    "login":                       EventType.LOGIN_EVENT,
    "oauth_grant":                  EventType.LOGIN_EVENT,
    "api_token_issued":            EventType.LOGIN_EVENT,
    "device_enrollment_bypass":    EventType.LOGIN_EVENT,

    # Network / browser
    "ai_prompt_submission":        EventType.BROWSER_ACTIVITY,
    "chat_message":                EventType.BROWSER_ACTIVITY,
    "email_send":                  EventType.NETWORK_CONN,
    "email_receive":               EventType.NETWORK_CONN,
    "vpn_connect_personal":        EventType.NETWORK_CONN,

    # Device
    "usb_transfer":                EventType.USB_CONNECT,
}
DEFAULT_EVENT_TYPE = EventType.APP_LAUNCH

# CASB risk_tier strings already match RiskCategory enum values (case-insensitive)
RISK_TIER_TO_CATEGORY = {
    "Low": RiskCategory.LOW,
    "Medium": RiskCategory.MEDIUM,
    "High": RiskCategory.HIGH,
    "Critical": RiskCategory.CRITICAL,
}

CLIENT_ID = "shadow_corp"  # single-tenant for now; swap per-tenant once multi-tenant onboarding exists


def _safe(val):
    """pandas NaN / None -> None, else pass through."""
    if val is None:
        return None
    if isinstance(val, float) and pd.isna(val):
        return None
    if isinstance(val, str) and val.strip().lower() in ("none", "nan", ""):
        return None
    return val


def _build_risk_reasons(row) -> list[str]:
    reasons = []
    if _safe(row.get("is_off_hours")) == 1:
        reasons.append("off_hours_activity")
    if _safe(row.get("device_managed")) == 0:
        reasons.append("unmanaged_device")
    shadow_cat = _safe(row.get("shadow_it_category"))
    if shadow_cat:
        reasons.append(f"shadow_it:{shadow_cat}")
    if _safe(row.get("sanction_status")) == "Unsanctioned":
        reasons.append("unsanctioned_application")
    if _safe(row.get("auth_method")) in ("personal_email_signup", "shared_credential", "none"):
        reasons.append("weak_auth_method")
    data_class = _safe(row.get("data_classification"))
    if data_class in ("Restricted-PII", "Restricted-Financial"):
        reasons.append(f"sensitive_data:{data_class}")
    scope = _safe(row.get("oauth_scope_granted"))
    if scope and ("full_access" in scope or "admin" in scope):
        reasons.append("broad_oauth_scope")
    if _safe(row.get("policy_violation")) == 1:
        reasons.append("policy_violation")
    return reasons


def row_to_event(row: dict) -> ShadowKediEvent:
    activity_type = _safe(row.get("activity_type"))
    event_type = ACTIVITY_TYPE_TO_EVENT_TYPE.get(activity_type, DEFAULT_EVENT_TYPE)

    is_file_event = event_type in (EventType.FILE_ACCESS, EventType.FILE_TRANSFER, EventType.CLOUD_UPLOAD)
    is_network_event = event_type in (EventType.NETWORK_CONN, EventType.DNS_QUERY, EventType.BROWSER_ACTIVITY)

    data_volume_mb = _safe(row.get("data_volume_mb")) or 0.0
    bytes_total = int(float(data_volume_mb) * 1024 * 1024) if data_volume_mb else None

    risk_tier = _safe(row.get("risk_tier"))
    risk_score = _safe(row.get("risk_score"))

    event = ShadowKediEvent(
        event_id=str(row["event_id"]),
        timestamp=row["timestamp"] if isinstance(row["timestamp"], datetime) else pd.to_datetime(row["timestamp"]),
        agent_id=f"agent-{row['user_id']}",
        hostname=str(row.get("device_id") or f"{row['user_id']}-device"),
        username=str(row["user_id"]),
        client_id=CLIENT_ID,
        event_type=event_type,
        source="shadow_it_synthetic",
        raw_data={
            "employee_name": _safe(row.get("employee_name")),
            "department": _safe(row.get("department")),
            "role": _safe(row.get("role")),
            "site": _safe(row.get("site")),
            "risk_persona": _safe(row.get("risk_persona")),
            "is_departing_employee": _safe(row.get("is_departing_employee")),
            "has_admin_rights": _safe(row.get("has_admin_rights")),
            "security_training_current": _safe(row.get("security_training_current")),
            "device_type": _safe(row.get("device_type")),
            "device_managed": _safe(row.get("device_managed")),
            "network_zone": _safe(row.get("network_zone")),
            "source_ip_class": _safe(row.get("source_ip_class")),
            "auth_method": _safe(row.get("auth_method")),
            "oauth_scope_granted": _safe(row.get("oauth_scope_granted")),
            "activity_type": activity_type,
            "app_category": _safe(row.get("app_category")),
            "sanction_status": _safe(row.get("sanction_status")),
            "shadow_it_category": _safe(row.get("shadow_it_category")),
            "is_shadow_it": _safe(row.get("is_shadow_it")),
            "data_classification": _safe(row.get("data_classification")),
            "detection_source": _safe(row.get("detection_source")),
            "policy_violation": _safe(row.get("policy_violation")),
            "action_taken": _safe(row.get("action_taken")),
            "threat_scenario": _safe(row.get("threat_scenario")),
            "scenario_id": _safe(row.get("scenario_id")),
        },
    )

    if is_network_event:
        event.destination_domain = _safe(row.get("destination_domain"))
        event.bytes_sent = bytes_total

    if is_file_event:
        app_name = _safe(row.get("app_name"))
        event.file_name = f"{activity_type}_{row['event_id']}" if app_name else None
        event.file_size_kb = round(float(data_volume_mb) * 1024, 2) if data_volume_mb else None

    if event_type in (EventType.APP_INSTALL, EventType.APP_LAUNCH):
        event.app_name = _safe(row.get("app_name"))
        event.app_publisher = _safe(row.get("app_category"))

    event.risk_score = float(risk_score) if risk_score is not None else None
    event.risk_category = RISK_TIER_TO_CATEGORY.get(risk_tier)
    event.risk_reasons = _build_risk_reasons(row)
    event.is_anomaly = bool(_safe(row.get("is_incident")) == 1)
    event.mitre_tags = []  # populated later by the Detection Rules role (Role 3)

    return event


def load_events(events_path: str) -> list[ShadowKediEvent]:
    path = Path(events_path)
    if path.suffix.lower() in (".xlsx", ".xls"):
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path)

    events = []
    for _, row in df.iterrows():
        events.append(row_to_event(row.to_dict()))
    return events


def build_user_profiles(events: list[ShadowKediEvent], employees_path: str) -> list[UserProfile]:
    emp_path = Path(employees_path)
    emp_df = pd.read_csv(emp_path) if emp_path.suffix.lower() == ".csv" else pd.read_excel(emp_path)

    profiles = []
    by_user = {}
    for e in events:
        by_user.setdefault(e.username, []).append(e)

    n_days = 90  # matches the generator's simulation window
    for _, emp_row in emp_df.iterrows():
        uid = str(emp_row["user_id"])
        user_events = by_user.get(uid, [])

        known_domains = sorted({
            e.destination_domain for e in user_events
            if e.destination_domain and not e.raw_data.get("is_shadow_it")
        })
        known_apps = sorted({
            e.app_name for e in user_events
            if e.app_name and e.raw_data.get("sanction_status") == "Sanctioned"
        })
        typical_hours = sorted({e.timestamp.hour for e in user_events})

        risk_scores = [e.risk_score for e in user_events if e.risk_score is not None]
        current_risk_score = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0

        if len(risk_scores) >= 4:
            midpoint = len(risk_scores) // 2
            first_half_avg = sum(risk_scores[:midpoint]) / midpoint
            second_half_avg = sum(risk_scores[midpoint:]) / (len(risk_scores) - midpoint)
            if second_half_avg > first_half_avg * 1.15:
                risk_trend = "rising"
            elif second_half_avg < first_half_avg * 0.85:
                risk_trend = "falling"
            else:
                risk_trend = "stable"
        else:
            risk_trend = "stable"

        total_alerts = sum(1 for e in user_events if e.raw_data.get("policy_violation") == 1)
        last_seen = max((e.timestamp for e in user_events), default=None)

        profiles.append(UserProfile(
            username=uid,
            client_id=CLIENT_ID,
            department=_safe(emp_row.get("department")),
            role=_safe(emp_row.get("role")),
            avg_daily_events=round(len(user_events) / n_days, 3),
            typical_hours=typical_hours,
            known_domains=known_domains,
            known_apps=known_apps,
            known_ips=[],  # dataset has no literal IPs, only source_ip_class buckets
            current_risk_score=current_risk_score,
            risk_trend=risk_trend,
            total_alerts=total_alerts,
            last_seen=last_seen,
        ))
    return profiles


def save_events(events: list[ShadowKediEvent], out_dir: str, filename="synthetic_events.json"):
    out_path = Path(out_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump([json.loads(e.model_dump_json()) for e in events], f, indent=2, default=str)
    print(f"Saved {len(events)} ShadowKediEvent records to {out_path}")
    return out_path


def save_profiles(profiles: list[UserProfile], out_dir: str, filename="synthetic_user_profiles.json"):
    out_path = Path(out_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump([json.loads(p.model_dump_json()) for p in profiles], f, indent=2, default=str)
    print(f"Saved {len(profiles)} UserProfile records to {out_path}")
    return out_path


def main():
    parser = argparse.ArgumentParser(description="Convert the Shadow IT synthetic dataset into ShadowKediEvent/UserProfile records.")
    parser.add_argument("--events-file", default="data/synthetic/shadow_it_events_synthetic.xlsx",
                         help="Path to the events file (.csv or .xlsx)")
    parser.add_argument("--employees-file", default="data/synthetic/shadow_it_employees_synthetic.csv",
                         help="Path to the employees file (.csv or .xlsx)")
    parser.add_argument("--out", default="data/synthetic", help="Output directory for converted JSON")
    args = parser.parse_args()

    print(f"Loading events from {args.events_file} ...")
    events = load_events(args.events_file)
    print(f"Loaded {len(events)} events. Building user profiles from {args.employees_file} ...")
    profiles = build_user_profiles(events, args.employees_file)

    save_events(events, args.out)
    save_profiles(profiles, args.out)

    n_anomaly = sum(1 for e in events if e.is_anomaly)
    print(f"Anomalous (is_incident=1) events: {n_anomaly} ({n_anomaly / len(events) * 100:.2f}%)")
    print(f"Event types present: {sorted({e.event_type.value for e in events})}")


if __name__ == "__main__":
    main()
