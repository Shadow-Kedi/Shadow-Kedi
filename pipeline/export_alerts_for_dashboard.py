# pipeline/export_alerts_for_dashboard.py
"""
Converts risk_scores_with_r_tier.csv into the dashboard's REAL contract --
confirmed directly against Frontend's actual shipped code
(shadowguard-dashboard/src/types.ts, mock.ts, api.ts), not their earlier
verbal answer, which turned out to disagree with their own code on one
point (see the `recommendation` field note below).

CONFIRMED FROM types.ts / mock.ts (authoritative -- this is what their
TypeScript compiler and running app actually accept):

    severity: EXACTLY 'low' | 'medium' | 'high' | 'critical' -- NO
        'informational' value exists in their type. Informational-tier
        days are EXCLUDED from export entirely (see below), not mapped
        to some approximation.

    tier: EXACTLY 'R2'..'R6' -- NO 'R1'. Matches R1's own definition
        ("below noise threshold, don't surface") -- R1 days are excluded
        from export, not just filtered at display time. Since every
        Informational risk_category maps to R1 in recommendation_tier.py,
        filtering on tier alone would already exclude them, but this
        filters on risk_category too, defensively, in case that mapping
        ever changes.

    evidence: Evidence[] -- NEW structure, {label, detail, observedAt,
        strength}. Built here from anomaly_detector.py's top_contributors
        string via FEATURE_EVIDENCE_MAP, translating raw feature names
        (e.g. "is_exfil_domain=0.95") into the same human-readable style
        Frontend's own mock data uses ("Volume anomaly" / "Upload volume
        is 4.8x the 30-day user baseline."). Falls back to a generic
        label for any feature not yet in the map, rather than dropping
        the evidence item silently.

    recommendation: string (a single narrative sentence) in their ACTUAL
        code -- e.g. "Flag for IT review. Confirm whether a sanctioned
        research tool meets the team's need." This CONTRADICTS Frontend's
        earlier verbal answer requesting separate tags. Implemented here
        as a single string, matching their real running code, NOT their
        stated answer -- confirm with them directly which is current
        before trusting either source blindly (see conversation notes).

NOT RECONCILED YET: this dashboard's README states it "calls only the
configured REST API" (GET /overview, /alerts, /alerts/:id, /users/:id,
/applications, POST /exports) and does not connect to Wazuh/OpenSearch or
any database directly. This appears to assume a REST API layer that
Backend's own answer ("write directly to Postgres, skip building a
bespoke API") doesn't obviously account for. Not something to resolve
unilaterally here -- flag to Backend directly.

Usage:
    python -m pipeline.export_alerts_for_dashboard
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

import pandas as pd

SEVERITY_MAP = {
    # Informational deliberately has NO entry -- excluded, not mapped
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    "Critical": "critical",
}

EXCLUDED_TIERS = {"R1"}
EXCLUDED_CATEGORIES = {"Informational"}

# feature name (as it appears in top_contributors) -> (label, detail_template).
# {val} is replaced with the feature's deviation value. Matches the
# human-readable style of Frontend's own mock evidence entries. Deliberately
# incomplete -- extend as more features prove worth surfacing; anything
# missing falls back to a generic label rather than being dropped.
FEATURE_EVIDENCE_MAP = {
    "is_exfil_domain": ("Known exfiltration-pattern domain",
                         "Destination domain matches a known personal-cloud/exfiltration pattern (deviation {val})."),
    "is_removable_media": ("Removable media activity",
                            "Event involved a removable storage device (deviation {val})."),
    "is_off_hours": ("Off-hours activity",
                      "Activity occurred outside this user's established working hours (deviation {val})."),
    "bytes_sent_log": ("Volume anomaly",
                        "Data transfer volume is a significant deviation from this user's baseline (deviation {val})."),
    "weak_auth": ("Weak authentication method",
                  "Access used a weak or non-standard authentication method (deviation {val})."),
    "risky_network_zone": ("Risky network context",
                            "Activity originated from a network zone flagged as higher-risk (deviation {val})."),
    "device_managed": ("Unmanaged device",
                        "Activity occurred on a device not enrolled in device management (deviation {val})."),
    "is_shadow_it": ("Unsanctioned application",
                      "Application is not in the approved inventory (deviation {val})."),
    "external_recipient": ("External recipient",
                            "Data was sent to a recipient outside the organization (deviation {val})."),
    "daily_event_count": ("Unusual daily activity volume",
                           "Total activity for this day is a significant deviation from baseline (deviation {val})."),
}

TOP_CONTRIBUTOR_RE = re.compile(r"([a-zA-Z_]+)=([\d.]+)")


def parse_evidence(top_contributors: str, observed_time: str) -> list:
    """Parses anomaly_detector.py's 'feat_a=0.95; feat_b=0.87' string into
    the dashboard's Evidence[] shape. Every parsed feature becomes one
    'observed' evidence item (a real, measured signal) -- 'context' items
    (like peer prevalence) come from a different source (recommendation_tier.py's
    inputs) and aren't populated here, since peer_prevalence isn't wired
    upstream into risk_scores.csv yet (documented gap, see recommendation_tier.py)."""
    if not isinstance(top_contributors, str) or not top_contributors:
        return []
    evidence = []
    for name, val in TOP_CONTRIBUTOR_RE.findall(top_contributors):
        label, detail_template = FEATURE_EVIDENCE_MAP.get(
            name, (name.replace("_", " ").title(), f"Feature '{name}' deviation: {{val}}.")
        )
        evidence.append({
            "label": label,
            "detail": detail_template.format(val=val),
            "observedAt": observed_time,
            "strength": "observed",
        })
    return evidence


def build_recommendation_sentence(row) -> str:
    """Single narrative sentence, matching Frontend's ACTUAL `recommendation:
    string` field (not their stated tags answer -- see module docstring)."""
    tier_label = row.get("r_tier_label", "Review required")
    fixes = row.get("recommended_fixes")
    if isinstance(fixes, str) and fixes and fixes != "[]":
        try:
            fix_list = json.loads(fixes)
            if fix_list:
                return f"{tier_label}. {fix_list[0]['title']}."
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
    return f"{tier_label}."


def export_alerts(df: pd.DataFrame) -> pd.DataFrame:
    df = df[~df["risk_category"].isin(EXCLUDED_CATEGORIES)]
    if "r_tier" in df.columns:
        df = df[~df["r_tier"].isin(EXCLUDED_TIERS)]

    def make_id(row):
        raw = f"{row['_username']}-{row['date']}-{row['_source']}"
        return "AL-" + hashlib.sha1(raw.encode()).hexdigest()[:12]

    def pick_app_category(row):
        if pd.notna(row.get("shadow_it_category")):
            return row["shadow_it_category"]
        if pd.notna(row.get("cert_signal")):
            return row["cert_signal"].replace("_", " ").title()
        return "Unclassified activity"

    out = pd.DataFrame()
    out["id"] = df.apply(make_id, axis=1)
    out["userId"] = df["_username"]
    out["userName"] = df["_username"]
    out["department"] = df.get("department", "Unclassified")
    out["severity"] = df["risk_category"].map(SEVERITY_MAP)
    out["score"] = df["risk_score"].round().astype(int)
    label = df.apply(pick_app_category, axis=1)
    out["app"] = label
    out["category"] = label
    out["status"] = "new"
    out["createdAt"] = pd.to_datetime(df["date"]).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    out["tier"] = df.get("r_tier", "R2")
    observed_time = pd.to_datetime(df["date"]).dt.strftime("%H:%M")
    tc_series = df.get("top_contributors", pd.Series([None] * len(df)))
    out["evidence"] = [parse_evidence(tc, ot) for tc, ot in zip(tc_series, observed_time)]
    out["recommendation"] = df.apply(build_recommendation_sentence, axis=1)
    return out


def main():
    parser = argparse.ArgumentParser(description="Export risk scores matching the dashboard's REAL confirmed contract.")
    parser.add_argument("--in-path", default="data/processed/risk_scores_with_r_tier.csv")
    parser.add_argument("--out-path", default="data/processed/dashboard_alerts_export.json")
    args = parser.parse_args()

    df = pd.read_csv(args.in_path)
    out = export_alerts(df)
    out_path = Path(args.out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out.to_json(out_path, orient="records", indent=2)
    print(f"Wrote {len(out)} alerts to {out_path} (Informational/R1 excluded: "
          f"{len(df) - len(out)} rows filtered out).")


if __name__ == "__main__":
    main()
