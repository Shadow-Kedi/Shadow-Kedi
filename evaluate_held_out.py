"""
evaluate_held_out.py

CORRECTS A REAL METHODOLOGICAL ISSUE: risk_engine.py's headline F1
result was computed by scoring EVERY user-day in the dataset, including
the ~80% of users the model was actually trained on. That number is
optimistic -- it partly reflects the model recognizing users it already
saw during training, not genuine generalization to new people.

This script regenerates the EXACT SAME held-out split classifier_daily.py
and genetic_optimizer.py used (same seed=42, same user_level_split_daily
logic) to recover the list of test-set-only users the model never
trained on, then re-evaluates risk_engine.py's output filtered down to
ONLY those users. This is the honest, defensible generalization number.

Usage:
    python evaluate_held_out.py
"""

import argparse

import pandas as pd

from pipeline.classifier_daily import build_daily_features, load_and_timestamp, user_level_split_daily


def compute_metrics(daily: pd.DataFrame, flagged_categories=("High", "Critical")):
    actual_bad_day = daily["daily_labeled_anomaly_count"] > 0 if "daily_labeled_anomaly_count" in daily.columns \
        else daily["_label"] > 0
    flagged = daily["risk_category"].isin(flagged_categories)

    tp = int((flagged & actual_bad_day).sum())
    fp = int((flagged & ~actual_bad_day).sum())
    fn = int((~flagged & actual_bad_day).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def main():
    parser = argparse.ArgumentParser(description="Re-evaluate risk_engine.py output on TRUE held-out users only.")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--casb-normalized", default="data/processed/normalized_events.json")
    parser.add_argument("--cert-normalized", default="data/processed/normalized_cert_events.jsonl")
    parser.add_argument("--risk-scores-in", default="data/processed/risk_scores.csv")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"Loading {args.features_in} and recovering timestamps (same pass as training used) ...")
    df = load_and_timestamp(args.features_in, args.casb_normalized, args.cert_normalized)
    daily_features = build_daily_features(df)

    print(f"Regenerating the EXACT held-out split (seed={args.seed}, test_size={args.test_size}) "
          f"used during model training ...")
    train_df, test_df = user_level_split_daily(daily_features, args.test_size, args.seed)

    held_out_users = set(zip(test_df["_username"], test_df["_source"]))
    print(f"Held-out test users: {test_df['_username'].nunique()} "
          f"(never seen during training -- {len(held_out_users)} (user, source) pairs)")

    print(f"\nLoading {args.risk_scores_in} ...")
    risk_scores = pd.read_csv(args.risk_scores_in)
    risk_scores["_user_source"] = list(zip(risk_scores["_username"], risk_scores["_source"]))

    held_out_scores = risk_scores[risk_scores["_user_source"].isin(held_out_users)]
    train_scores = risk_scores[~risk_scores["_user_source"].isin(held_out_users)]

    print(f"\n{'='*70}")
    print("INFLATED NUMBER (what risk_engine.py currently reports -- train+test blended)")
    print(f"{'='*70}")
    all_metrics = compute_metrics(risk_scores)
    print(f"  All {len(risk_scores)} user-days: "
          f"Precision={all_metrics['precision']:.4f} Recall={all_metrics['recall']:.4f} F1={all_metrics['f1']:.4f}")

    print(f"\n{'='*70}")
    print("HONEST NUMBER (held-out test users ONLY -- the model never saw these people)")
    print(f"{'='*70}")
    held_out_metrics = compute_metrics(held_out_scores)
    print(f"  {len(held_out_scores)} user-days from {test_df['_username'].nunique()} held-out users: "
          f"Precision={held_out_metrics['precision']:.4f} Recall={held_out_metrics['recall']:.4f} "
          f"F1={held_out_metrics['f1']:.4f}")

    print(f"\nBy source (held-out only):")
    for src in held_out_scores["_source"].unique():
        sub = held_out_scores[held_out_scores["_source"] == src]
        m = compute_metrics(sub)
        print(f"  {src}: {len(sub)} user-days, {m['tp']} TP / {m['fp']} FP / {m['fn']} FN, "
              f"Precision={m['precision']:.4f} Recall={m['recall']:.4f} F1={m['f1']:.4f}")

    print(f"\n{'='*70}")
    print(f"GAP: inflated F1={all_metrics['f1']:.4f} vs honest held-out F1={held_out_metrics['f1']:.4f} "
          f"(difference: {all_metrics['f1'] - held_out_metrics['f1']:+.4f})")
    print("Report the HELD-OUT number as the project's real result, not the inflated one.")


if __name__ == "__main__":
    main()
