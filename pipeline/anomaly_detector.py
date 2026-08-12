# pipeline/anomaly_detector.py
"""
Step 7 — Statistical Anomaly Detector (heuristic IDS core)

Combines the per-user and per-source-population baselines (built in
baseline.py) into a single explainable deviation score per event.

METHOD

- Continuous features (hour, bytes_sent_log, domain_len, etc.): z-score
  against a BLENDED baseline, clipped to avoid runaway values from
  near-zero variance.
- Binary/one-hot features (is_off_hours, et_*, is_shadow_it, etc.):
  absolute deviation from the feature's baseline RATE (0-1) -- more
  meaningful than a z-score for a 0/1 value.

WHY BLENDED (SHRINKAGE), NOT PURE PER-USER Z-SCORES

feature_engineer.py reservoir-samples CERT's normal events (1.5M out of
32M), so an individual CERT user's baseline may be built from only a
handful of sampled events -- their per-user mean/std is unreliable with
so few observations. Each user's baseline is blended with their SOURCE's
population baseline, weighted by how many events that user actually has:
many events -> trust their own baseline; few events -> lean on the
population baseline instead (classic shrinkage/empirical-Bayes style
weighting: w = n / (n + k)). This directly compensates for the sampling
decision made upstream, rather than pretending every user has equally
reliable personal history.

SENTINEL HANDLING

Fields that don't exist for a given source (e.g. has_admin_rights for
CERT, always -1) are excluded from that source's deviation calculation
entirely -- not treated as a real extreme value. Same for any feature
baseline.py flagged as zero-variance within a source.

OUTPUT

Adds to each event: `anomaly_score` (0-1 composite), `top_contributors`
(the features that drove the score, for explainability), and keeps the
real `_label` alongside so you can immediately check precision/recall
against known ground truth -- a sanity check on the heuristic before the
trained classifier exists.

Usage:
    python -m pipeline.anomaly_detector
    python -m pipeline.anomaly_detector --shrinkage-k 30 --threshold 0.35
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

SENTINEL = -1
Z_CLIP = 8.0  # cap on z-score magnitude so a near-zero-variance feature can't dominate the composite score
EPS = 1e-9

CONTINUOUS_FEATURES = [
    "hour", "day_of_week", "domain_len", "bytes_sent_log",
    "bytes_received_log", "file_size_log",
]
# everything else in the feature matrix that isn't metadata or continuous
# gets treated as binary/rate-based (populated dynamically in main())


def load_inputs(feature_path: str, user_baseline_path: str, source_stats_path: str):
    df = pd.read_csv(feature_path)
    user_base = pd.read_csv(user_baseline_path)
    source_stats = pd.read_csv(source_stats_path)
    return df, user_base, source_stats


def blend_baselines(df: pd.DataFrame, user_base: pd.DataFrame, source_stats: pd.DataFrame,
                     feature_cols: list, shrinkage_k: float) -> pd.DataFrame:
    """
    Merges user-level and source-population baselines onto the event
    dataframe, then computes shrinkage-blended mean/std per feature.
    Returns df with added `{feature}_blend_mean` / `{feature}_blend_std`
    columns (std only meaningful for continuous features, harmless to
    compute for all).

    Note: baseline.py names event-type (et_*) columns differently between
    its two outputs -- `{et_col}_share` in user_baselines.csv (computed
    separately from the other numeric aggregations) vs `{et_col}_mean` in
    source_population_stats.csv (aggregated uniformly with everything
    else). Handled here rather than re-running baseline.py again.
    """
    def user_mean_col(f):
        return f"{f}_share" if f.startswith("et_") else f"{f}_mean"

    user_mean_source_cols = [user_mean_col(f) for f in feature_cols]
    user_std_source_cols = [f"{f}_std" for f in feature_cols if f in CONTINUOUS_FEATURES]
    user_cols = ["username", "event_count"] + user_mean_source_cols + user_std_source_cols
    rename_map = {**{user_mean_col(f): f"{f}_umean" for f in feature_cols},
                  **{f"{f}_std": f"{f}_ustd" for f in feature_cols if f in CONTINUOUS_FEATURES}}
    user_slim = user_base[user_cols].rename(columns=rename_map)

    src_cols = ["source"] + [f"{f}_mean" for f in feature_cols] + \
               [f"{f}_std" for f in feature_cols if f in CONTINUOUS_FEATURES]
    src_slim = source_stats[src_cols].rename(
        columns={**{f"{f}_mean": f"{f}_pmean" for f in feature_cols},
                 **{f"{f}_std": f"{f}_pstd" for f in feature_cols if f in CONTINUOUS_FEATURES}}
    )

    merged = df.merge(user_slim, left_on="_username", right_on="username", how="left")
    merged = merged.merge(src_slim, left_on="_source", right_on="source", how="left")

    # Users with zero surviving normal events (after baseline.py's fix to
    # exclude anomalous events from baselines) have NaN user-level stats.
    # Fill these with the population value BEFORE blending -- otherwise
    # 0 * NaN = NaN in IEEE 754, so even a correctly-computed shrinkage
    # weight of 0 wouldn't actually cancel out a NaN personal mean.
    for f in feature_cols:
        merged[f"{f}_umean"] = merged[f"{f}_umean"].fillna(merged[f"{f}_pmean"])
        if f in CONTINUOUS_FEATURES:
            merged[f"{f}_ustd"] = merged[f"{f}_ustd"].fillna(merged[f"{f}_pstd"])

    w = merged["event_count"] / (merged["event_count"] + shrinkage_k)

    blend_cols = {"_shrink_w": w}
    for f in feature_cols:
        umean = merged[f"{f}_umean"]
        pmean = merged[f"{f}_pmean"]
        blend_cols[f"{f}_blend_mean"] = w * umean + (1 - w) * pmean
        if f in CONTINUOUS_FEATURES:
            ustd = merged[f"{f}_ustd"]
            pstd = merged[f"{f}_pstd"]
            blend_cols[f"{f}_blend_std"] = w * ustd + (1 - w) * pstd

    merged = pd.concat([merged, pd.DataFrame(blend_cols, index=merged.index)], axis=1)
    return merged


def compute_deviations(merged: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
    """
    Returns a DataFrame (same row count as `merged`) with one normalized
    (0-1) deviation column per feature. NaN means "skipped" -- either the
    event's own value was the sentinel, or the feature doesn't apply to
    that source at all (population mean is the sentinel, or zero variance).
    """
    dev = pd.DataFrame(index=merged.index)

    for f in feature_cols:
        raw_val = merged[f]
        pop_mean = merged[f"{f}_pmean"]
        blend_mean = merged[f"{f}_blend_mean"]

        # feature not applicable to this row's source at all
        not_applicable = (raw_val == SENTINEL) | (pop_mean == SENTINEL)

        if f in CONTINUOUS_FEATURES:
            blend_std = merged[f"{f}_blend_std"]
            zero_var = blend_std.abs() < EPS
            z = (raw_val - blend_mean).abs() / blend_std.replace(0, np.nan)
            z_clipped = z.clip(upper=Z_CLIP)
            # zero variance but value differs from the (constant) baseline -> max deviation;
            # zero variance and value matches -> no deviation
            zero_var_dev = np.where((raw_val - blend_mean).abs() < EPS, 0.0, Z_CLIP)
            combined = np.where(zero_var, zero_var_dev, z_clipped)
            normalized = combined / Z_CLIP
        else:
            normalized = (raw_val - blend_mean).abs().clip(upper=1.0)

        col = pd.Series(normalized, index=merged.index)
        col[not_applicable] = np.nan
        dev[f] = col

    return dev


def score_events(deviations: pd.DataFrame, top_k: int = 5):
    """Composite score = mean of non-NaN deviations per row. Also returns
    the top-k contributing feature names per row for explainability."""
    composite = deviations.mean(axis=1, skipna=True).fillna(0.0)

    values = deviations.fillna(-1).to_numpy()
    cols = np.array(deviations.columns)
    top_idx = np.argsort(-values, axis=1)[:, :top_k]
    top_contributors = []
    for i in range(values.shape[0]):
        idxs = top_idx[i]
        pairs = [(cols[j], round(float(values[i, j]), 3)) for j in idxs if values[i, j] > 0]
        top_contributors.append("; ".join(f"{name}={val}" for name, val in pairs) if pairs else "")

    return composite, top_contributors


def evaluate_against_labels(df: pd.DataFrame, threshold: float):
    from scipy import stats

    pos = df[df["_label"] == 1]["anomaly_score"]
    neg = df[df["_label"] == 0]["anomaly_score"]
    if len(pos) and len(neg):
        u, _ = stats.mannwhitneyu(pos, neg)
        auc = u / (len(pos) * len(neg))
        print(f"\nAUC (rank-based separation, threshold-independent): {auc:.4f}")
        print(f"Mean score — anomalous: {pos.mean():.4f}  |  normal: {neg.mean():.4f}")

    print(f"\n--- Threshold sweep (heuristic sanity check vs. real ground truth) ---")
    print(f"{'threshold':>9} {'flagged':>8} {'TP':>6} {'FP':>7} {'FN':>5} {'precision':>10} {'recall':>7} {'F1':>6}")
    sweep_thresholds = sorted(set([0.10, 0.12, 0.14, 0.15, 0.16, 0.18, 0.20, 0.25, threshold]))
    for t in sweep_thresholds:
        flagged = df["anomaly_score"] >= t
        actual = df["_label"] == 1
        tp = int((flagged & actual).sum())
        fp = int((flagged & ~actual).sum())
        fn = int((~flagged & actual).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        marker = " <-- selected" if t == threshold else ""
        print(f"{t:9.2f} {flagged.sum():8d} {tp:6d} {fp:7d} {fn:5d} {precision:10.4f} {recall:7.4f} {f1:6.4f}{marker}")

    print(f"\nBy source, at selected threshold={threshold}:")
    for src in df["_source"].unique():
        sub = df[df["_source"] == src]
        sf = sub["anomaly_score"] >= threshold
        sa = sub["_label"] == 1
        stp = int((sf & sa).sum())
        sfp = int((sf & ~sa).sum())
        sfn = int((~sf & sa).sum())
        sprec = stp / (stp + sfp) if (stp + sfp) else 0.0
        srec = stp / (stp + sfn) if (stp + sfn) else 0.0
        print(f"  {src}: TP={stp} FP={sfp} FN={sfn}  Precision={sprec:.4f}  Recall={srec:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Score events against blended per-user/population baselines.")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--user-baselines-in", default="data/processed/user_baselines.csv")
    parser.add_argument("--source-stats-in", default="data/processed/source_population_stats.csv")
    parser.add_argument("--out", default="data/processed/anomaly_scores.csv")
    parser.add_argument("--shrinkage-k", type=float, default=30.0,
                         help="Shrinkage smoothing constant. Larger = lean on population baseline more; "
                              "smaller = trust each user's own history sooner.")
    parser.add_argument("--threshold", type=float, default=0.15,
                         help="Composite score cutoff for the evaluation report (does not affect saved scores). "
                              "Defaults toward higher recall since this is a detection layer feeding "
                              "risk_engine.py, not a final gate -- better to over-flag here and let "
                              "downstream scoring/rules refine than to miss real threats.")
    args = parser.parse_args()

    print(f"Loading {args.features_in}, {args.user_baselines_in}, {args.source_stats_in} ...")
    df, user_base, source_stats = load_inputs(args.features_in, args.user_baselines_in, args.source_stats_in)

    metadata_cols = {"event_id", "_label", "_source", "_username"}
    feature_cols = [c for c in df.columns if c not in metadata_cols]
    print(f"Scoring {len(df)} events across {len(feature_cols)} features "
          f"(shrinkage_k={args.shrinkage_k}) ...")

    merged = blend_baselines(df, user_base, source_stats, feature_cols, args.shrinkage_k)
    deviations = compute_deviations(merged, feature_cols)
    composite, top_contributors = score_events(deviations)

    df["anomaly_score"] = composite
    df["top_contributors"] = top_contributors

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df[["event_id", "_username", "_source", "_label", "anomaly_score", "top_contributors"]].to_csv(out_path, index=False)
    print(f"Wrote: {out_path}")

    evaluate_against_labels(df, args.threshold)


if __name__ == "__main__":
    main()
