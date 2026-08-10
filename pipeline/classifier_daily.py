# pipeline/classifier_daily.py
"""
Day-level classifier — trains on per-user-per-day AGGREGATED raw features,
not raw per-event rows.

WHY THIS EXISTS

classifier.py (per-event) confirmed the same ceiling anomaly_detector.py
already diagnosed: Decision Tree and Random Forest both scored ~0.53 AUC
overall on real data (barely above random), dragged down by CERT's
window-based labels -- most events inside a labeled malicious window are
just a person's ordinary daily activity that happens to timestamp-overlap
it. Random Forest still hit 0.927 AUC on CASB alone, so the models CAN
learn real signal; CERT's per-event granularity just doesn't have much of
it to learn.

This mirrors the fix that worked for the heuristic (risk_engine.py's
per-user-per-day aggregation) but applies it one level earlier: instead
of aggregating the heuristic's own composite score (which would just
teach a classifier to imitate anomaly_detector.py), this aggregates the
RAW per-event features themselves into per-day summaries (event counts by
type, off-hours rate, max bytes transferred, count of removable-media
events, etc.), giving the classifier new signal to learn from at the
granularity where dilution is less severe -- not a re-threshold of
existing output.

Usage:
    python -m pipeline.classifier_daily
"""

import argparse
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.tree import DecisionTreeClassifier

from pipeline.risk_engine import load_casb_lookup, load_cert_timestamps

HEURISTIC_EVENT_AUC = 0.6159   # anomaly_detector.py, real scale
CLASSIFIER_EVENT_AUC = 0.5298  # classifier.py (random_forest), real scale -- this variant's real comparison point

EVENT_TYPE_COLS = [
    "et_browser_activity", "et_app_install", "et_app_launch", "et_file_access",
    "et_file_transfer", "et_usb_connect", "et_network_connection", "et_dns_query",
    "et_cloud_upload", "et_login_event",
]
SUM_COLS = [
    "is_removable_media", "is_exfil_domain", "has_file", "weak_auth",
    "risky_network_zone", "is_shadow_it", "sanction_unsanctioned", "external_recipient",
]
MAX_COLS = ["bytes_sent_log", "bytes_received_log", "file_size_log", "domain_len"]
MEAN_COLS = ["is_off_hours", "is_weekend", "device_managed", "has_admin_rights", "security_training_current"]


def load_and_timestamp(features_path: str, casb_normalized: str, cert_normalized: str) -> pd.DataFrame:
    df = pd.read_csv(features_path)

    casb_lookup = load_casb_lookup(casb_normalized)
    casb_ids = set(df.loc[df["_source"] == "shadow_it_synthetic", "event_id"])
    cert_ids = set(df.loc[df["_source"] != "shadow_it_synthetic", "event_id"])

    print(f"Streaming {cert_normalized} once for {len(cert_ids)} needed CERT timestamps ...")
    cert_ts_lookup = load_cert_timestamps(cert_normalized, cert_ids) if cert_ids else {}

    def get_ts(row):
        if row["event_id"] in casb_lookup:
            return casb_lookup[row["event_id"]]["timestamp"]
        return cert_ts_lookup.get(row["event_id"])

    df["timestamp"] = df.apply(get_ts, axis=1)
    before = len(df)
    df = df.dropna(subset=["timestamp"])
    if len(df) < before:
        print(f"WARNING: dropped {before - len(df)} rows with no timestamp found.")

    df["date"] = pd.to_datetime(df["timestamp"]).dt.date
    return df


def build_daily_features(df: pd.DataFrame) -> pd.DataFrame:
    grouped = df.groupby(["_username", "_source", "date"])

    agg_spec = {}
    for c in EVENT_TYPE_COLS + SUM_COLS:
        agg_spec[c] = "sum"
    for c in MAX_COLS:
        agg_spec[c] = "max"
    for c in MEAN_COLS:
        agg_spec[c] = "mean"
    agg_spec["_label"] = "max"       # day is "bad" if ANY event that day was labeled anomalous
    agg_spec["event_id"] = "count"   # daily event count

    daily = grouped.agg(agg_spec).rename(columns={"event_id": "daily_event_count"}).reset_index()

    # event-type counts as shares of that day's activity, so busy days and
    # quiet days are still comparable
    for c in EVENT_TYPE_COLS:
        daily[f"{c}_share"] = daily[c] / daily["daily_event_count"].replace(0, np.nan)
        daily[f"{c}_share"] = daily[f"{c}_share"].fillna(0.0)

    return daily


def user_level_split_daily(df: pd.DataFrame, test_size: float, seed: int):
    rng = np.random.RandomState(seed)
    train_idx, test_idx = [], []
    user_has_anomaly = df.groupby(["_source", "_username"])["_label"].max()

    for source in df["_source"].unique():
        sub = df[df["_source"] == source]
        for has_anom in (0, 1):
            users = user_has_anomaly[
                (user_has_anomaly.index.get_level_values("_source") == source) &
                (user_has_anomaly == has_anom)
            ].index.get_level_values("_username").tolist()
            if not users:
                continue
            users = list(users)
            rng.shuffle(users)
            n_test = max(1, round(len(users) * test_size)) if len(users) > 1 else 0
            test_users = set(users[:n_test])
            is_test = sub["_username"].isin(test_users)
            test_idx.extend(sub[is_test].index.tolist())
            train_idx.extend(sub[~is_test & sub["_username"].isin(users)].index.tolist())

    return df.loc[train_idx].reset_index(drop=True), df.loc[test_idx].reset_index(drop=True)


def evaluate(model, X_test, y_test, source_test, model_name):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
    try:
        auc = roc_auc_score(y_test, y_proba)
    except ValueError:
        auc = float("nan")

    print(f"\n--- {model_name} (day-level) ---")
    print(f"Overall: precision={precision:.4f} recall={recall:.4f} f1={f1:.4f} auc={auc:.4f}")
    print(f"  (compare to: heuristic per-event AUC {HEURISTIC_EVENT_AUC}, "
          f"per-event classifier AUC {CLASSIFIER_EVENT_AUC}, "
          f"risk_engine.py day-level F1 0.1067)")

    for src in source_test.unique():
        mask = (source_test == src).to_numpy()
        if mask.sum() < 5 or y_test[mask].sum() == 0:
            continue
        p, r, f, _ = precision_recall_fscore_support(y_test[mask], y_pred[mask], average="binary", zero_division=0)
        try:
            a = roc_auc_score(y_test[mask], y_proba[mask])
        except ValueError:
            a = float("nan")
        print(f"  {src}: precision={p:.4f} recall={r:.4f} f1={f:.4f} auc={a:.4f}")

    return {"model": model_name, "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "auc": round(auc, 4) if not np.isnan(auc) else None}


def main():
    parser = argparse.ArgumentParser(description="Train day-level classifiers on aggregated per-user-per-day features.")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--casb-normalized", default="data/processed/normalized_events.json")
    parser.add_argument("--cert-normalized", default="data/processed/normalized_cert_events.jsonl")
    parser.add_argument("--out-dir", default="data/processed")
    parser.add_argument("--models-dir", default="data/models")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"Loading {args.features_in} and recovering timestamps ...")
    df = load_and_timestamp(args.features_in, args.casb_normalized, args.cert_normalized)

    print("Building per-user-per-day aggregated features (raw features, not the heuristic score) ...")
    daily = build_daily_features(df)
    print(f"Built {len(daily)} user-day rows from {len(df)} events.")

    print("Splitting by user (stratified by anomaly presence) ...")
    train_df, test_df = user_level_split_daily(daily, args.test_size, args.seed)
    print(f"Train: {len(train_df)} user-days, {train_df['_username'].nunique()} users")
    print(f"Test:  {len(test_df)} user-days, {test_df['_username'].nunique()} users")

    feature_cols = [c for c in daily.columns if c not in ("_username", "_source", "date", "_label")]
    X_train, y_train = train_df[feature_cols].to_numpy(), train_df["_label"].to_numpy()
    X_test, y_test = test_df[feature_cols].to_numpy(), test_df["_label"].to_numpy()
    source_test = test_df["_source"]

    print(f"\nFeatures used ({len(feature_cols)}): {feature_cols}")
    print(f"Train label distribution: {pd.Series(y_train).value_counts().to_dict()}")
    print(f"Test label distribution:  {pd.Series(y_test).value_counts().to_dict()}")

    models = {
        "decision_tree": DecisionTreeClassifier(class_weight="balanced", max_depth=10, random_state=args.seed),
        "random_forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", max_depth=12, n_jobs=-1, random_state=args.seed
        ),
    }

    results, fitted = [], {}
    for name, model in models.items():
        print(f"\nTraining {name} ...")
        t0 = time.time()
        model.fit(X_train, y_train)
        print(f"  fit time: {time.time()-t0:.1f}s")
        results.append(evaluate(model, X_test, y_test, source_test, name))
        fitted[name] = model

    results_df = pd.DataFrame(results)
    out_path = Path(args.out_dir) / "classifier_daily_comparison.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(out_path, index=False)
    print(f"\nWrote: {out_path}")

    best = max(results, key=lambda r: r["auc"] if r["auc"] is not None else -1)
    print(f"\nBest day-level model: {best['model']} (AUC {best['auc']})")

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": fitted[best["model"]], "feature_cols": feature_cols, "model_name": best["model"]},
                models_dir / "best_daily_classifier.joblib")
    print(f"Saved to {models_dir / 'best_daily_classifier.joblib'}")


if __name__ == "__main__":
    main()
