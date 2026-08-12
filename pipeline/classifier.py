# pipeline/classifier.py
"""
Step 9 — Hybrid Classifier

Trains supervised classifiers on feature_matrix.csv and benchmarks them
directly against the heuristic baseline already measured in
anomaly_detector.py (real-scale event-level AUC: 0.6159). This is the
"hybrid" half of the heuristic-IDS design the HIIDS paper this project
cites uses -- Decision Tree, Random Forest, and kNN, the same candidate
set that paper compares, with genetic_optimizer.py (next) doing GA-based
feature selection on top of whichever performs best here.

CRITICAL: train/test split is done PER USER, not per row. If the same
person's events land in both train and test, the model can partly
memorize that person rather than learn generalizable attack patterns --
this is the same identity-leakage risk the CASB dataset's own README
flagged. Split is stratified by source so both CASB and CERT are
represented in both train and test.

Class imbalance (0.4% CERT, 3.2% CASB) handled via class_weight="balanced"
for Decision Tree / Random Forest (built into sklearn, no synthetic
oversampling needed). kNN doesn't support class_weight, so it's evaluated
separately with that caveat noted, not silently skipped.

Usage:
    python -m pipeline.classifier
    python -m pipeline.classifier --skip-knn   (kNN prediction is O(n) per
                                                 query and can be slow on
                                                 a 300k+ row test set)
"""

import argparse
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

METADATA_COLUMNS = {"event_id", "_label", "_source", "_username"}

# The heuristic baseline this classifier needs to beat, from
# anomaly_detector.py's real-scale validation (see shadow-kedi.md).
HEURISTIC_BASELINE_AUC = 0.6159


def load_features(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def user_level_split(df: pd.DataFrame, test_size: float = 0.2, seed: int = 42):
    """Splits by _username within each _source separately (stratified by
    source AND by whether the user has any labeled anomaly), so no user's
    events appear in both train and test, both sources are represented in
    both splits, AND anomalous users specifically are proportionally
    represented in both splits -- without this, a small/unlucky random
    draw can put zero anomalies in the test set, making evaluation
    meaningless regardless of dataset size (this happened on a first
    test run against a small dataset)."""
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
            n_test_users = max(1, round(len(users) * test_size)) if len(users) > 1 else 0
            test_users = set(users[:n_test_users])

            is_test = sub["_username"].isin(test_users)
            test_idx.extend(sub[is_test].index.tolist())
            train_idx.extend(sub[~is_test & sub["_username"].isin(users)].index.tolist())

    return df.loc[train_idx].reset_index(drop=True), df.loc[test_idx].reset_index(drop=True)


def prepare_xy(df: pd.DataFrame):
    feature_cols = [c for c in df.columns if c not in METADATA_COLUMNS]
    X = df[feature_cols].to_numpy()
    y = df["_label"].to_numpy()
    return X, y, feature_cols


def evaluate(model, X_test, y_test, source_test: pd.Series, model_name: str) -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )
    try:
        auc = roc_auc_score(y_test, y_proba)
    except ValueError:
        auc = float("nan")  # only one class present in y_test, shouldn't happen but don't crash

    result = {
        "model": model_name,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "auc": round(auc, 4),
        "beats_heuristic_auc": bool(auc > HEURISTIC_BASELINE_AUC) if not np.isnan(auc) else None,
    }

    print(f"\n--- {model_name} ---")
    print(f"Overall: precision={precision:.4f} recall={recall:.4f} f1={f1:.4f} auc={auc:.4f}"
          f"  (heuristic baseline AUC: {HEURISTIC_BASELINE_AUC})")

    per_source = {}
    for src in source_test.unique():
        mask = (source_test == src).to_numpy()
        if mask.sum() < 5 or y_test[mask].sum() == 0:
            continue
        p, r, f, _ = precision_recall_fscore_support(y_test[mask], y_pred[mask], average="binary", zero_division=0)
        try:
            a = roc_auc_score(y_test[mask], y_proba[mask])
        except ValueError:
            a = float("nan")
        per_source[src] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "auc": round(a, 4)}
        print(f"  {src}: precision={p:.4f} recall={r:.4f} f1={f:.4f} auc={a:.4f}")

    result["per_source"] = per_source
    return result


def main():
    parser = argparse.ArgumentParser(description="Train and benchmark classifiers against the heuristic baseline.")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--out-dir", default="data/processed")
    parser.add_argument("--models-dir", default="data/models")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--skip-knn", action="store_true",
                         help="Skip kNN -- prediction is O(n) per query and can be slow on a large test set")
    args = parser.parse_args()

    print(f"Loading {args.features_in} ...")
    df = load_features(args.features_in)
    print(f"Loaded {len(df)} rows, {df['_username'].nunique()} users.")

    print("Splitting by user (not by row) to avoid identity leakage ...")
    train_df, test_df = user_level_split(df, test_size=args.test_size, seed=args.seed)
    print(f"Train: {len(train_df)} rows, {train_df['_username'].nunique()} users")
    print(f"Test:  {len(test_df)} rows, {test_df['_username'].nunique()} users "
          f"(no overlap with train users, by construction)")

    X_train, y_train, feature_cols = prepare_xy(train_df)
    X_test, y_test, _ = prepare_xy(test_df)
    source_test = test_df["_source"]

    print(f"\nFeatures used ({len(feature_cols)}): {feature_cols}")
    print(f"Train label distribution: {pd.Series(y_train).value_counts().to_dict()}")
    print(f"Test label distribution:  {pd.Series(y_test).value_counts().to_dict()}")

    models = {
        "decision_tree": DecisionTreeClassifier(class_weight="balanced", max_depth=12, random_state=args.seed),
        "random_forest": RandomForestClassifier(
            n_estimators=100, class_weight="balanced", max_depth=15, n_jobs=-1, random_state=args.seed
        ),
    }
    if not args.skip_knn:
        models["knn"] = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)  # no class_weight support -- caveat noted below

    results = []
    fitted = {}
    for name, model in models.items():
        print(f"\nTraining {name} ...")
        t0 = time.time()
        model.fit(X_train, y_train)
        print(f"  fit time: {time.time() - t0:.1f}s")
        t0 = time.time()
        res = evaluate(model, X_test, y_test, source_test, name)
        print(f"  eval time: {time.time() - t0:.1f}s")
        results.append(res)
        fitted[name] = model

    if "knn" in fitted:
        print("\nNOTE: kNN does not support class_weight -- its scores reflect the raw class "
              "imbalance and should be read with that in mind versus decision_tree/random_forest.")

    results_df = pd.DataFrame([{k: v for k, v in r.items() if k != "per_source"} for r in results])
    out_path = Path(args.out_dir) / "classifier_comparison.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(out_path, index=False)
    print(f"\nWrote comparison table: {out_path}")

    best = max(results, key=lambda r: r["auc"] if not np.isnan(r["auc"]) else -1)
    print(f"\nBest model: {best['model']} (AUC {best['auc']}, heuristic baseline {HEURISTIC_BASELINE_AUC})")
    if best["beats_heuristic_auc"]:
        print("This BEATS the heuristic anomaly_detector.py baseline.")
    else:
        print("This does NOT beat the heuristic baseline -- worth investigating before treating it as an upgrade.")

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    best_model = fitted[best["model"]]
    joblib.dump({"model": best_model, "feature_cols": feature_cols, "model_name": best["model"]},
                models_dir / "best_classifier.joblib")
    print(f"Saved best model to {models_dir / 'best_classifier.joblib'}")


if __name__ == "__main__":
    main()
