# pipeline/feature_engineer.py
"""
Step 4 — Feature Engineer

Turns normalized ShadowKediEvent records from BOTH data sources (CASB/
Shadow-IT dataset + CERT r4.2) into one common numeric feature matrix for
the GA feature selector and classifier.

DELIBERATELY EXCLUDED from features: risk_score, risk_category,
risk_reasons, mitre_tags. Both loaders set these as a rule computed
DIRECTLY from the label (e.g. CERT's loader sets risk_score=90 if
malicious else 5). Including them would be trivial label leakage, not
real signal — the model would just learn to read the label back off a
value that already encodes it.

Handles source-size asymmetry: the CASB dataset (10k events) is small
enough to load in full; CERT r4.2 (30M+ events, ~0.4% anomalous) is not.
For CERT, every anomalous event is kept and normal events are reservoir-
sampled down to a target count in a single streaming pass — memory stays
bounded at roughly the sample size, not the source file size.

Usage:
    python -m pipeline.feature_engineer
    python -m pipeline.feature_engineer --sample-normal 1500000 --seed 42
    python -m pipeline.feature_engineer --cert-in data/processed/normalized_cert_events.jsonl \
                                         --casb-in data/processed/normalized_events.json \
                                         --out data/processed/feature_matrix.csv
"""

import argparse
import json
import math
import random
from datetime import datetime
from pathlib import Path

import pandas as pd

# ============================================================
# Config
# ============================================================

EVENT_TYPES = [
    "browser_activity", "app_install", "app_launch", "file_access",
    "file_transfer", "usb_connect", "network_connection", "dns_query",
    "cloud_upload", "login_event",
]

# Same list used by cert_loader.py's http heuristic — kept in sync here
# so "known bad domain" is a feature regardless of which source an event
# came from, not just a CERT-specific signal.
EXFIL_DOMAIN_HINTS = (
    "wikileaks", "pastebin", "mega.nz", "mega.co", "mediafire",
    "wetransfer", "4shared", "rapidshare", "dropbox", "drive.google",
    "anonfiles", "gofile", "transfernow", "chatgpt", "gemini", "claudeai",
    "telegram", "whatsappweb", "discord",
)

WEAK_AUTH_METHODS = {"personal_email_signup", "shared_credential", "none"}
RISKY_NETWORK_ZONES = {"public_wifi", "unrecognized_foreign_ip", "mobile_hotspot"}


# ============================================================
# Feature extraction — one event dict (already-parsed JSON) -> flat dict
# ============================================================

def extract_features(event: dict) -> dict:
    raw = event.get("raw_data") or {}
    ts = event.get("timestamp")
    if isinstance(ts, str):
        # normalizer stores ISO format with UTC offset, e.g. "...+00:00"
        dt = datetime.fromisoformat(ts)
    else:
        dt = ts

    hour = dt.hour
    dow = dt.weekday()  # 0=Mon .. 6=Sun
    is_weekend = 1 if dow >= 5 else 0
    is_off_hours = 1 if (hour < 7 or hour >= 19) else 0

    event_type = event.get("event_type", "")
    event_type_onehot = {f"et_{et}": int(event_type == et) for et in EVENT_TYPES}

    domain = event.get("destination_domain") or ""
    has_domain = 1 if domain else 0
    domain_len = len(domain)
    is_exfil_domain = 1 if any(h in domain.lower() for h in EXFIL_DOMAIN_HINTS) else 0

    bytes_sent = event.get("bytes_sent")
    bytes_received = event.get("bytes_received")
    bytes_sent_log = math.log1p(bytes_sent) if bytes_sent else 0.0
    bytes_received_log = math.log1p(bytes_received) if bytes_received else 0.0

    file_size_kb = event.get("file_size_kb")
    has_file = 1 if event.get("file_name") else 0
    file_size_log = math.log1p(file_size_kb) if file_size_kb else 0.0

    to_removable = bool(raw.get("to_removable_media"))
    from_removable = bool(raw.get("from_removable_media"))
    casb_removable_category = raw.get("shadow_it_category") == "Removable Media & Offline Transfer"
    is_removable_media = 1 if (to_removable or from_removable or casb_removable_category) else 0

    # source-specific fields: -1 sentinel means "not applicable/unknown for
    # this source" — a real, informative value in a heterogeneous-source
    # feature matrix, not missing data to be imputed away
    device_managed_raw = raw.get("device_managed")
    device_managed = int(device_managed_raw) if device_managed_raw is not None else -1

    has_admin_rights_raw = raw.get("has_admin_rights")
    has_admin_rights = int(has_admin_rights_raw) if has_admin_rights_raw is not None else -1

    security_training_raw = raw.get("security_training_current")
    security_training_current = int(security_training_raw) if security_training_raw is not None else -1

    auth_method = raw.get("auth_method")
    weak_auth = 1 if auth_method in WEAK_AUTH_METHODS else 0

    network_zone = raw.get("network_zone")
    risky_network_zone = 1 if network_zone in RISKY_NETWORK_ZONES else 0

    is_shadow_it = 1 if raw.get("is_shadow_it") else 0
    sanction_unsanctioned = 1 if raw.get("sanction_status") == "Unsanctioned" else 0

    external_recipient = 1 if raw.get("external_recipient") else 0
    is_departing_employee = int(raw.get("is_departing_employee")) if raw.get("is_departing_employee") is not None else -1

    features = {
        "event_id": event.get("event_id"),
        "hour": hour,
        "day_of_week": dow,
        "is_weekend": is_weekend,
        "is_off_hours": is_off_hours,
        **event_type_onehot,
        "has_domain": has_domain,
        "domain_len": domain_len,
        "is_exfil_domain": is_exfil_domain,
        "bytes_sent_log": bytes_sent_log,
        "bytes_received_log": bytes_received_log,
        "has_file": has_file,
        "file_size_log": file_size_log,
        "is_removable_media": is_removable_media,
        "device_managed": device_managed,
        "has_admin_rights": has_admin_rights,
        "security_training_current": security_training_current,
        "weak_auth": weak_auth,
        "risky_network_zone": risky_network_zone,
        "is_shadow_it": is_shadow_it,
        "sanction_unsanctioned": sanction_unsanctioned,
        "external_recipient": external_recipient,
        "is_departing_employee": is_departing_employee,
        # metadata — NOT features, carried through for reporting/splitting,
        # classifier.py must drop these before training
        "_label": int(bool(event.get("is_anomaly"))),
        "_source": event.get("source"),
        "_username": event.get("username"),
    }
    return features


# ============================================================
# Loading — CASB (full load) + CERT (streamed, reservoir-sampled)
# ============================================================

def load_casb(path: str) -> list:
    with open(path) as f:
        return json.load(f)


def load_cert_sampled(path: str, sample_normal: int, seed: int) -> list:
    """
    Single streaming pass over the CERT jsonl file. Keeps every anomalous
    event. Normal events are kept via reservoir sampling (algorithm R) so
    the final sample is a uniform random subset of ALL normal events seen,
    not just the first N — without needing to know the total count or
    hold the whole file in memory.
    """
    rng = random.Random(seed)
    anomalous = []
    reservoir = []
    n_normal_seen = 0
    n_total = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            n_total += 1
            event = json.loads(line)
            if event.get("is_anomaly"):
                anomalous.append(event)
                continue

            n_normal_seen += 1
            if len(reservoir) < sample_normal:
                reservoir.append(event)
            else:
                j = rng.randint(0, n_normal_seen - 1)
                if j < sample_normal:
                    reservoir[j] = event

            if n_total % 2_000_000 == 0:
                print(f"    ... {n_total} CERT lines scanned "
                      f"({len(anomalous)} anomalous kept, {len(reservoir)}/{sample_normal} normal reservoir)")

    print(f"CERT stream complete: {n_total} total lines, {len(anomalous)} anomalous, "
          f"{n_normal_seen} normal seen, {len(reservoir)} normal sampled.")
    return anomalous + reservoir


# ============================================================
# Main pipeline
# ============================================================

def build_feature_matrix(casb_path: str, cert_path: str, sample_normal: int, seed: int) -> pd.DataFrame:
    print(f"Loading CASB dataset from {casb_path} ...")
    casb_events = load_casb(casb_path)
    print(f"Loaded {len(casb_events)} CASB events (kept in full).")

    print(f"Streaming + sampling CERT dataset from {cert_path} ...")
    cert_events = load_cert_sampled(cert_path, sample_normal=sample_normal, seed=seed)

    print(f"Extracting features from {len(casb_events) + len(cert_events)} total events ...")
    rows = []
    for event in casb_events:
        rows.append(extract_features(event))
    for event in cert_events:
        rows.append(extract_features(event))

    df = pd.DataFrame(rows)
    return df


def main():
    parser = argparse.ArgumentParser(description="Build the combined feature matrix from CASB + CERT normalized data.")
    parser.add_argument("--casb-in", default="data/processed/normalized_events.json")
    parser.add_argument("--cert-in", default="data/processed/normalized_cert_events.jsonl")
    parser.add_argument("--sample-normal", type=int, default=1_500_000,
                         help="Number of normal (non-anomalous) CERT events to reservoir-sample (default 1.5M)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="data/processed/feature_matrix.csv")
    args = parser.parse_args()

    df = build_feature_matrix(args.casb_in, args.cert_in, args.sample_normal, args.seed)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    print()
    print(f"Feature matrix shape: {df.shape[0]} rows x {df.shape[1]} columns")
    print(f"Label distribution: {df['_label'].value_counts().to_dict()}")
    print(f"Source distribution: {df['_source'].value_counts().to_dict()}")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
