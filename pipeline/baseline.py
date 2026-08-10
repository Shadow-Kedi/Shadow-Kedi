# pipeline/baseline.py
"""
Step 6 — Behavioral Baseline

Builds two distinct artifacts from feature_matrix.csv, deliberately kept
separate because they answer different questions:

  1. PER-USER BASELINE (source-agnostic): "what does normal look like for
     THIS specific person?" A user's own history is their own history
     regardless of which dataset it came from — mixing sources here causes
     no harm, since each user only ever appears in one source anyway.

  2. PER-SOURCE POPULATION / PEER STATS (source-aware): "what does normal
     look like for the group this person belongs to?" This must NOT be
     pooled across CASB + CERT — the two datasets have different history
     lengths per user (90 days vs ~17 months), different generating
     assumptions, and structurally different feature availability (CASB
     has real auth_method/network_zone values; CERT has -1 sentinels for
     those, and vice versa for other fields). Pooling would mean an
     "anomaly" is sometimes just "this person's data came from the other
     dataset" rather than real behavioral deviation.

Usage:
    python -m pipeline.baseline
    python -m pipeline.baseline --in data/processed/feature_matrix.csv --out data/processed
"""

import argparse
from pathlib import Path

import pandas as pd

# Columns that are metadata, not features — must be excluded from any
# statistical aggregation (mean/std would be meaningless or misleading).
METADATA_COLUMNS = {"event_id", "_label", "_source", "_username"}

# Sentinel value used by feature_engineer.py for "field not applicable to
# this source" (e.g. has_admin_rights for CERT rows). Excluded from mean/std
# computation per-source where it would just be a constant -1, but the
# per-user baseline can include it as-is since a user only has one source.
SENTINEL = -1


def load_feature_matrix(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    return df


def _feature_columns(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c not in METADATA_COLUMNS]


def build_user_baselines(df: pd.DataFrame) -> pd.DataFrame:
    """
    One row per _username. Source-agnostic by design — a user's baseline
    is built purely from their own event history.

    CRITICAL: built from _label == 0 (known-normal) events ONLY. A
    "normal behavior" baseline built from a mix that includes the user's
    own anomalous events is contaminated -- for a user whose anomalous
    events dominate their sampled history (a real risk here, since
    feature_engineer.py keeps 100% of anomalies but only ~4.6% of normal
    CERT events), their "baseline" would partly just BE their malicious
    behavior, making continued malicious activity look normal relative
    to itself. Standard practice: a baseline of normal must be built from
    normal data only.

    Users with zero surviving normal events after sampling still appear
    in the output (with NaN stats, event_count=0) rather than being
    dropped entirely, so anomaly_detector.py's shrinkage can fall back
    fully to the population baseline for them.
    """
    feature_cols = _feature_columns(df)
    et_cols = [c for c in feature_cols if c.startswith("et_")]
    numeric_cols = [c for c in feature_cols if c not in et_cols]

    normal_df = df[df["_label"] == 0]
    grouped = normal_df.groupby("_username")

    agg = grouped[numeric_cols].agg(["mean", "std"])
    agg.columns = [f"{col}_{stat}" for col, stat in agg.columns]

    et_share = grouped[et_cols].mean()
    et_share.columns = [f"{c}_share" for c in et_cols]

    event_count = grouped.size().rename("event_count")  # NORMAL-event count specifically

    normal_baseline = pd.concat([event_count, agg, et_share], axis=1).reset_index()
    normal_baseline = normal_baseline.rename(columns={"_username": "username"})

    # every user appears, even those with zero surviving normal events
    all_users = df.groupby("_username").agg(
        source=("_source", "first"),
        labeled_anomaly_count=("_label", "sum"),
    ).reset_index().rename(columns={"_username": "username"})

    baseline = all_users.merge(normal_baseline, on="username", how="left")
    baseline["event_count"] = baseline["event_count"].fillna(0).astype(int)
    std_cols = [c for c in baseline.columns if c.endswith("_std")]
    baseline[std_cols] = baseline[std_cols].fillna(0.0)

    return baseline


def build_source_population_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    One row per _source. This is the peer-comparison reference: an
    individual user's feature values get z-scored against THEIR source's
    stats here, never against the pooled dataset.

    Built from _label == 0 (known-normal) events ONLY, for the same
    contamination reason as build_user_baselines above — a population
    baseline that includes the anomalies you're trying to detect isn't a
    baseline of normal behavior.
    """
    feature_cols = _feature_columns(df)
    normal_df = df[df["_label"] == 0]
    grouped = normal_df.groupby("_source")

    stats = grouped[feature_cols].agg(["mean", "std"])
    stats.columns = [f"{col}_{stat}" for col, stat in stats.columns]

    n_normal = grouped.size().rename("n_normal_events")
    n_users = normal_df.groupby("_source")["_username"].nunique().rename("n_users")

    # report actual dataset-wide anomaly rate separately (from the full,
    # unfiltered df) -- informational only, not part of the baseline itself
    full_grouped = df.groupby("_source")
    n_total = full_grouped.size().rename("n_total_events")
    anomaly_rate = full_grouped["_label"].mean().rename("anomaly_rate")

    result = pd.concat([n_total, n_normal, n_users, anomaly_rate, stats], axis=1).reset_index()
    result = result.rename(columns={"_source": "source"})

    # std can legitimately be 0 for sentinel-only columns (e.g. has_admin_rights
    # is always -1 for cert_insider_threat -> std=0). Flag these explicitly
    # rather than let a downstream z-score divide by zero silently.
    std_cols = [c for c in result.columns if c.endswith("_std")]
    zero_std_cols = [c for c in std_cols if (result[c] == 0).any()]
    if zero_std_cols:
        print(f"NOTE: these columns have zero variance for at least one source "
              f"(likely a source-specific sentinel, e.g. always -1) — z-scoring "
              f"against them will need a guard in anomaly_detector.py: {zero_std_cols}")

    return result


def main():
    parser = argparse.ArgumentParser(description="Build per-user and per-source-population behavioral baselines.")
    parser.add_argument("--in", dest="in_path", default="data/processed/feature_matrix.csv")
    parser.add_argument("--out", dest="out_dir", default="data/processed")
    args = parser.parse_args()

    print(f"Loading feature matrix from {args.in_path} ...")
    df = load_feature_matrix(args.in_path)
    print(f"Loaded {len(df)} rows, {df['_username'].nunique()} unique users across "
          f"{df['_source'].nunique()} source(s).")

    print("Building per-user baselines (source-agnostic) ...")
    user_baselines = build_user_baselines(df)
    print("Building per-source population/peer statistics (source-aware) ...")
    source_stats = build_source_population_stats(df)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    user_path = out_dir / "user_baselines.csv"
    source_path = out_dir / "source_population_stats.csv"

    user_baselines.to_csv(user_path, index=False)
    source_stats.to_csv(source_path, index=False)

    print()
    print(f"User baselines: {user_baselines.shape[0]} users x {user_baselines.shape[1]} columns -> {user_path}")
    print(f"Source population stats: {source_stats.shape[0]} sources x {source_stats.shape[1]} columns -> {source_path}")
    print()
    print("Source population summary:")
    print(source_stats[["source", "n_total_events", "n_normal_events", "n_users", "anomaly_rate"]].to_string(index=False))


if __name__ == "__main__":
    main()
