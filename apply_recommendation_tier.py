"""
Applies pipeline.recommendation_tier's recommend_tier() to an actual
risk_scores.csv file.

Only `risk_category` is a real, currently-available input -- repeat_count,
peer_prevalence, self_audit_response, and is_known_bad_category don't
exist anywhere in the pipeline yet, so they're left at their defaults
below. This still gives a real R-tier per row today; it'll get more
accurate once those upstream signals exist.

Usage: python apply_recommendation_tier.py
"""

import pandas as pd
from pipeline.recommendation_tier import recommend_tier

daily = pd.read_csv("data/processed/risk_scores.csv", low_memory=False)

results = daily["risk_category"].apply(
    lambda cat: recommend_tier(risk_category=cat)  # repeat_count/peer_prevalence/
                                                     # self_audit_response/is_known_bad_category
                                                     # all default -- not yet available upstream
)

daily["r_tier"] = results.apply(lambda r: r["tier"])
daily["r_tier_label"] = results.apply(lambda r: r["label"])

daily.to_csv("data/processed/risk_scores_with_r_tier.csv", index=False)

print(f"Wrote {len(daily)} rows to data/processed/risk_scores_with_r_tier.csv")
print()
print("R-tier distribution:")
print(daily["r_tier"].value_counts().to_string())