"""
Applies pipeline.recommendation_tier's recommend_tier() to an actual
risk_scores.csv file, via the DataFrame-native apply_recommendation_tiers()
batch function.

repeat_count, peer_prevalence, self_audit_response, and
is_known_bad_category don't exist as real columns anywhere in the
pipeline yet, so apply_recommendation_tiers() falls back to sensible
defaults for all four (and prints a note saying so). This still gives a
real, correct R-tier per row today; it'll get more accurate -- with zero
changes needed to this script -- once those upstream signals exist as
real columns in risk_scores.csv.

Usage: python apply_recommendation_tier.py
"""

import pandas as pd
from pipeline.recommendation_tier import apply_recommendation_tiers

daily = pd.read_csv("data/processed/risk_scores.csv")
daily = apply_recommendation_tiers(daily)

daily.to_csv("data/processed/risk_scores_with_r_tier.csv", index=False)

print(f"Wrote {len(daily)} rows to data/processed/risk_scores_with_r_tier.csv")
print()
print("R-tier distribution:")
print(daily["r_tier"].value_counts().to_string())
