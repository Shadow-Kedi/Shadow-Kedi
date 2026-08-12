"""
Diagnostic: CASB recall by threat scenario (S1-S6).

risk_scores.csv only knows "this user-day had >=1 real anomalous event" --
it doesn't carry WHICH scenario that event belonged to. This traces each
missed (false-negative) day back to normalized_events.json to find out
whether misses cluster around specific scenarios, or spread evenly.

Usage: python diagnose_casb_scenarios.py
"""

import json
import pandas as pd

# 1. Load risk_scores.csv, keep only CASB rows with a real labeled anomaly that day
risk_scores = pd.read_csv("data/processed/risk_scores.csv")
casb_days = risk_scores[
    (risk_scores["_source"] == "shadow_it_synthetic") &
    (risk_scores["daily_labeled_anomaly_count"] > 0)
].copy()
casb_days["date"] = pd.to_datetime(casb_days["date"]).dt.date

print(f"CASB user-days with a real labeled anomaly: {len(casb_days)}")

# 2. Load normalized CASB events, keep only ones with a real scenario tag,
#    and compute their calendar date
with open("data/processed/normalized_events.json") as f:
    events = json.load(f)

scenario_rows = []
for e in events:
    raw = e.get("raw_data") or {}
    scenario_id = raw.get("scenario_id")
    if not scenario_id or scenario_id == "None":
        continue
    ts = pd.to_datetime(e["timestamp"])
    scenario_rows.append({
        "_username": e["username"],
        "date": ts.date(),
        "scenario_id": scenario_id,
        "threat_scenario": raw.get("threat_scenario"),
    })

scenario_df = pd.DataFrame(scenario_rows).drop_duplicates(subset=["_username", "date", "scenario_id"])
print(f"Distinct (user, day, scenario) combinations in the source data: {len(scenario_df)}")

# 3. Join: for each labeled CASB day, attach which scenario(s) drove it
merged = casb_days.merge(scenario_df, on=["_username", "date"], how="left")

# 4. Was that day actually flagged (High/Critical)?
merged["flagged"] = merged["risk_category"].isin(["High", "Critical"])

# 5. Per-scenario recall
print("\n--- Recall by CASB threat scenario ---")
print(f"{'scenario':>6} {'label':40s} {'total_days':>10} {'caught':>7} {'missed':>7} {'recall':>7}")
for scenario_id, group in merged.groupby("scenario_id"):
    label = group["threat_scenario"].iloc[0]
    total = len(group)
    caught = int(group["flagged"].sum())
    missed = total - caught
    recall = caught / total if total else 0.0
    print(f"{scenario_id:>6} {label:40s} {total:10d} {caught:7d} {missed:7d} {recall:7.4f}")

# 6. Show the actual missed days in detail, for closer inspection
print("\n--- Missed (false-negative) days, detail ---")
missed_detail = merged[~merged["flagged"]][
    ["_username", "date", "scenario_id", "threat_scenario", "classifier_score", "risk_category", "top_contributors"]
]
print(missed_detail.to_string(index=False))
