# pipeline/risk_engine.py
"""
Step 8 — Risk Scoring Engine

Turns per-event and per-day signals into the blueprint's actual
deliverable: a 0-100 explainable risk score, aggregated per user per day.

PRIMARY SCORE SOURCE: THE TRAINED DAY-LEVEL CLASSIFIER

classifier_daily.py's Random Forest, trained on per-user-per-day
aggregated raw features, dramatically outperforms the pure statistical
heuristic at real scale (CERT: AUC 0.999 vs the heuristic's day-level F1
of 0.107). When a trained model is available (data/models/
best_daily_classifier.joblib by default), its predicted probability
drives the risk score. The heuristic composite (anomaly_detector.py,
aggregated the same way as before) is kept as a smaller stabilizing
term and, more importantly, as the source of per-event explainability
(top_contributors) -- the classifier is a black box on its own; pairing
it with the heuristic's feature-level "why" keeps the output explainable,
which the blueprint requires. If no trained model is found, falls back
to heuristic-only scoring (the original design) automatically.

WHY AGGREGATE (not just relay per-event scores)

anomaly_detector.py's real-scale validation showed per-event scoring has
an inherent ceiling for high-volume "incidental" event types -- CERT's
ground truth is WINDOW-based, and most events inside a malicious window
are just a person's ordinary daily activity that happens to timestamp-
overlap it. Aggregating to (user, day) is what surfaces a genuinely
suspicious event even when it's sitting next to forty unremarkable
logins from the same person on the same day -- confirmed decisively by
classifier_daily.py's real-scale result.

WHY ONE SHARED TIMESTAMP LOOKUP PASS

Both the heuristic aggregation and the classifier's daily feature
aggregation ultimately need the same thing: real calendar dates for the
same ~1.64M sampled events. Rather than each doing its own streaming
pass over the 32.7M-row CERT file (as they did when built separately),
this does it ONCE via classifier_daily.load_and_timestamp() and reuses
the result for both.

Usage:
    python -m pipeline.risk_engine
    python -m pipeline.risk_engine --no-classifier   (heuristic-only, original behavior)
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd

from pipeline.classifier_daily import build_daily_features, load_and_timestamp
from pipeline.recommendations import RecommendationEngine
from pipeline.risk_categorization import categorize, classifier_boundaries, percentile_boundaries
from pipeline.timestamp_lookup import load_casb_lookup, load_cert_timestamps

# risk_category()'s old inline 4-tier if/elif logic has been replaced --
# see pipeline/risk_categorization.py for the shared 5-tier implementation
# (adds an "Informational" tier below Low) used by both scoring modes
# below. Kept as one shared module rather than duplicated logic so the
# percentile-rank path and the classifier-probability path can't drift
# apart on how they define tier boundaries.


# load_casb_lookup / load_cert_timestamps now live in pipeline/timestamp_lookup.py
# (imported above) -- moved there to break a circular import once this file
# needed to import from classifier_daily.py, which previously imported these
# two functions from here.


def build_daily_aggregates(scores_df: pd.DataFrame) -> pd.DataFrame:
    scores_df["date"] = pd.to_datetime(scores_df["timestamp"]).dt.date

    grouped = scores_df.groupby(["_username", "_source", "date"])

    agg = grouped.agg(
        daily_max_score=("anomaly_score", "max"),
        daily_mean_score=("anomaly_score", "mean"),
        daily_event_count=("anomaly_score", "size"),
        daily_labeled_anomaly_count=("_label", "sum"),
    ).reset_index()

    # pull the top-contributors string + any shadow_it_category/cert_signal
    # from whichever event had the day's MAX score -- that's the event
    # actually driving the day's risk, so its explanation should drive
    # the day's explanation too
    idx_of_max = grouped["anomaly_score"].idxmax()
    driver_events = scores_df.loc[idx_of_max, [
        "_username", "_source", "date", "event_id", "top_contributors",
        "shadow_it_category", "cert_signal",
    ]].rename(columns={"event_id": "driver_event_id"})

    daily = agg.merge(driver_events, on=["_username", "_source", "date"], how="left")
    return daily


def attach_recommendations(daily: pd.DataFrame, rec_engine: RecommendationEngine) -> pd.DataFrame:
    section_titles, fix_titles, statuses = [], [], []
    for _, row in daily.iterrows():
        if row["_source"] == "shadow_it_synthetic" and pd.notna(row.get("shadow_it_category")):
            rec = rec_engine.get_recommendation(shadow_it_category=row["shadow_it_category"])
        elif pd.notna(row.get("cert_signal")):
            rec = rec_engine.get_recommendation(cert_signal=row["cert_signal"])
        else:
            rec = {"status": "no_signal"}

        statuses.append(rec.get("status"))
        section_titles.append(rec.get("section_title"))
        if rec.get("status") == "ok":
            fix_titles.append("; ".join(f["title"] for f in rec["recommended_fixes"]))
        else:
            fix_titles.append(None)

    daily["recommendation_status"] = statuses
    daily["recommended_section"] = section_titles
    daily["recommended_fixes"] = fix_titles
    return daily


def compute_risk_scores(daily: pd.DataFrame, low_pct: float, medium_pct: float, high_pct: float, critical_pct: float,
                         classifier_weight: float = 0.85,
                         classifier_low: float = 0.02, classifier_medium: float = 0.10,
                         classifier_high: float = 0.50, classifier_critical: float = 0.90,
                         source_thresholds: dict = None) -> pd.DataFrame:
    """
    source_thresholds: optional {source_name: {"low": w, "medium": x, "high": y,
    "critical": z}} to override the global classifier_low/medium/high/critical
    for specific sources. Exists because a single global threshold, tuned
    on the overall population, is biased toward whichever source has more
    volume -- diagnosed directly: CASB's probability distribution tops out
    lower than CERT's (CERT dominates real-scale row count), so a
    threshold tuned mostly by CERT was too strict for CASB, causing many
    CASB misses that were actually scored 0.3-0.95 (real signal, just
    under a cutoff calibrated for a different source's distribution) --
    not genuine model blind spots.
    """
    # heuristic composite (same as before): a sharp single-event spike
    # matters more than a mildly elevated average
    heuristic_raw = 0.7 * daily["daily_max_score"] + 0.3 * daily["daily_mean_score"]
    daily["heuristic_raw_score"] = heuristic_raw

    has_classifier = "classifier_score" in daily.columns
    if has_classifier:
        daily["classifier_score"] = daily["classifier_score"].fillna(0.0)
        raw = classifier_weight * daily["classifier_score"] + (1 - classifier_weight) * heuristic_raw
        daily["raw_composite_score"] = raw
        daily["scoring_mode"] = "classifier+heuristic"
    else:
        raw = heuristic_raw
        daily["raw_composite_score"] = raw
        daily["scoring_mode"] = "heuristic_only"

    # risk_score (the 0-100 DISPLAY value) stays percentile-rank rescaled
    # either way -- useful for sorting/dashboard/trend purposes regardless
    # of scoring mode.
    percentile_score = raw.rank(pct=True) * 100
    daily["risk_score"] = percentile_score.round(1)

    if has_classifier:
        # risk_category (the FLAGGING decision) is based on the classifier's
        # own ABSOLUTE probability, not a percentile rank, when a trained
        # model is available. Percentile-rank flagging forces a fixed top-N%
        # of days into High/Critical regardless of how confident the model
        # actually is -- with a near-perfect classifier (real CERT standalone
        # eval: precision 0.97, recall 0.99 at the standard 0.5 cutoff) that
        # DILUTES precision by pulling in days the model was never actually
        # worried about, just to fill a fixed quota. Measured directly: this
        # caused CERT precision to drop from ~0.97 (classifier alone, 0.5
        # cutoff) to ~0.18 (blended + percentile-ranked) on real data.
        # Absolute thresholds let a confident model flag exactly as many
        # days as it's actually confident about -- no more, no less.
        source_thresholds = source_thresholds or {}
        default_boundaries = classifier_boundaries(classifier_low, classifier_medium, classifier_high, classifier_critical)

        def category_for_row(row):
            th = source_thresholds.get(row["_source"])
            if th:
                boundaries = classifier_boundaries(
                    th.get("low", classifier_low),
                    th.get("medium", classifier_medium),
                    th.get("high", classifier_high),
                    th.get("critical", classifier_critical),
                )
            else:
                boundaries = default_boundaries
            return categorize(row["classifier_score"], boundaries)
        daily["risk_category"] = daily.apply(category_for_row, axis=1)
    else:
        boundaries = percentile_boundaries(low_pct, medium_pct, high_pct, critical_pct)
        daily["risk_category"] = percentile_score.apply(lambda p: categorize(p, boundaries))
    return daily


def evaluate_daily_against_labels(daily: pd.DataFrame):
    threshold_categories = ("High", "Critical")
    actual_bad_day = daily["daily_labeled_anomaly_count"] > 0
    flagged = daily["risk_category"].isin(threshold_categories)

    tp = int((flagged & actual_bad_day).sum())
    fp = int((flagged & ~actual_bad_day).sum())
    fn = int((~flagged & actual_bad_day).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"\n--- Day-level evaluation (flagged = {'/'.join(threshold_categories)}) ---")
    print(f"Total user-days: {len(daily)}  |  Days with >=1 real anomalous event: {actual_bad_day.sum()}")
    print(f"TP={tp}  FP={fp}  FN={fn}")
    print(f"Precision={precision:.4f}  Recall={recall:.4f}  F1={f1:.4f}")
    print("\nBy source:")
    for src in daily["_source"].unique():
        sub = daily[daily["_source"] == src]
        sf = sub["risk_category"].isin(threshold_categories)
        sa = sub["daily_labeled_anomaly_count"] > 0
        stp = int((sf & sa).sum())
        sfp = int((sf & ~sa).sum())
        sfn = int((~sf & sa).sum())
        sprec = stp / (stp + sfp) if (stp + sfp) else 0.0
        srec = stp / (stp + sfn) if (stp + sfn) else 0.0
        print(f"  {src}: TP={stp} FP={sfp} FN={sfn}  Precision={sprec:.4f}  Recall={srec:.4f}")


def print_classifier_threshold_sweep(daily: pd.DataFrame):
    """
    Different trained models have very different classifier_score
    distributions -- a Random Forest gives a smooth continuous
    probability; a single Decision Tree only has as many distinct output
    values as leaves your data reaches (observed: as few as 10). Fixed
    thresholds tuned for one model don't reliably transfer to another.
    This sweeps over the model's ACTUAL observed probability values (not
    arbitrary round numbers) so thresholds can be tuned to whatever
    model is currently loaded, every time, rather than assumed.
    """
    if "classifier_score" not in daily.columns:
        return
    actual_bad_day = (daily["daily_labeled_anomaly_count"] > 0).to_numpy()
    scores = daily["classifier_score"].to_numpy()
    unique_vals = sorted(set(scores.round(6)))
    if len(unique_vals) < 2:
        return

    # candidate cutoffs: the midpoints between consecutive unique observed
    # values -- these are the only points where the flagged/not-flagged
    # decision can actually change for this specific model
    candidates = [(unique_vals[i] + unique_vals[i + 1]) / 2 for i in range(len(unique_vals) - 1)]
    if len(candidates) > 15:  # keep the printed table readable
        step = len(candidates) // 15
        candidates = candidates[::step]

    print(f"\n--- Classifier threshold sweep ({len(unique_vals)} distinct probability values observed) ---")
    print(f"{'cutoff':>10} {'flagged':>8} {'TP':>6} {'FP':>7} {'FN':>5} {'precision':>10} {'recall':>7} {'F1':>6}")
    best = (0.0, None)
    for c in candidates:
        flagged = scores >= c
        tp = int((flagged & actual_bad_day).sum())
        fp = int((flagged & ~actual_bad_day).sum())
        fn = int((~flagged & actual_bad_day).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        if f1 > best[0]:
            best = (f1, c)
        print(f"{c:10.4f} {int(flagged.sum()):8d} {tp:6d} {fp:7d} {fn:5d} {precision:10.4f} {recall:7.4f} {f1:6.4f}")

    if best[1] is not None:
        print(f"\nBest single-cutoff F1 (overall, all sources combined): {best[0]:.4f} at classifier_score >= {best[1]:.4f}")

    # Per-source sweep -- a threshold tuned on the combined population is
    # biased toward whichever source has more rows (CERT, at real scale).
    # This finds the best cutoff PER SOURCE separately, so a source with a
    # different probability distribution (diagnosed: CASB tops out lower)
    # doesn't get stuck with a threshold calibrated for a different source.
    print(f"\n--- Per-source threshold sweep (same cutoffs, source-specific F1) ---")
    for src in daily["_source"].unique():
        src_mask = (daily["_source"] == src).to_numpy()
        src_scores = scores[src_mask]
        src_bad = actual_bad_day[src_mask]
        if src_bad.sum() < 3:
            continue
        src_best = (0.0, None)
        for c in candidates:
            flagged = src_scores >= c
            tp = int((flagged & src_bad).sum())
            fp = int((flagged & ~src_bad).sum())
            fn = int((~flagged & src_bad).sum())
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            if f1 > src_best[0]:
                src_best = (f1, c, precision, recall)
        if src_best[1] is not None:
            print(f"  {src}: best F1={src_best[0]:.4f} at cutoff >= {src_best[1]:.4f} "
                  f"(precision={src_best[2]:.4f}, recall={src_best[3]:.4f})")
            print(f"    -> pass this source's cutoff via source_thresholds in code, "
                  f"or add a --{src.replace('_','-')}-high CLI override")


def main():
    parser = argparse.ArgumentParser(description="Aggregate anomaly scores + trained classifier into per-user-per-day explainable risk scores.")
    parser.add_argument("--scores-in", default="data/processed/anomaly_scores.csv")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--casb-normalized", default="data/processed/normalized_events.json")
    parser.add_argument("--cert-normalized", default="data/processed/normalized_cert_events.jsonl")
    parser.add_argument("--classifier-model", default="data/models/ga_optimized_classifier.joblib",
                         help="Trained model bundle to use for scoring. Defaults to the GA-optimized "
                              "Decision Tree (genetic_optimizer.py) over the Random Forest -- slightly "
                              "lower F1 (0.9399 vs 0.9496 on real data) but a ~22-feature model whose "
                              "decision path is actually traceable, matching the project's explainable-"
                              "scoring requirement. Point at data/models/best_daily_classifier.joblib "
                              "to use the Random Forest instead.")
    parser.add_argument("--no-classifier", action="store_true",
                         help="Skip the trained classifier and use heuristic-only scoring (original behavior)")
    parser.add_argument("--classifier-weight", type=float, default=0.85,
                         help="Weight given to the classifier score vs the heuristic score when both are available")
    parser.add_argument("--report", default="9-shadow-it-full-report.md")
    parser.add_argument("--claims", default="shadow_it_claims.json")
    parser.add_argument("--out", default="data/processed/risk_scores.csv")
    parser.add_argument("--low-pct", type=float, default=70.0,
                         help="Percentile cutoff for Low (the Informational/Low split, heuristic-only mode). "
                              "Default: bottom 70%% of days are Informational, next 20%% are Low.")
    parser.add_argument("--medium-pct", type=float, default=90.0,
                         help="Percentile cutoff for Medium (default: top 10%%)")
    parser.add_argument("--high-pct", type=float, default=97.0,
                         help="Percentile cutoff for High (default: top 3%%)")
    parser.add_argument("--critical-pct", type=float, default=99.0,
                         help="Percentile cutoff for Critical (default: top 1%%) -- used only in heuristic-only mode")
    parser.add_argument("--classifier-low", type=float, default=0.02,
                         help="Absolute classifier probability cutoff for Low (Informational/Low split)")
    parser.add_argument("--classifier-medium", type=float, default=0.10,
                         help="Absolute classifier probability cutoff for Medium (used when classifier is active)")
    parser.add_argument("--classifier-high", type=float, default=0.50,
                         help="Absolute classifier probability cutoff for High")
    parser.add_argument("--classifier-critical", type=float, default=0.90,
                         help="Absolute classifier probability cutoff for Critical")
    parser.add_argument("--casb-low", type=float, default=None,
                         help="Override --classifier-low specifically for the shadow_it_synthetic source")
    parser.add_argument("--casb-medium", type=float, default=None,
                         help="Override --classifier-medium specifically for the shadow_it_synthetic source. "
                              "Diagnosed need: CASB's probability distribution tops out lower than CERT's at "
                              "real scale, so a single global threshold (calibrated mostly by CERT's larger "
                              "volume) was too strict for CASB, missing real detections that scored 0.3-0.95 "
                              "but fell short of a cutoff meant for a different source's distribution.")
    parser.add_argument("--casb-high", type=float, default=None,
                         help="Override --classifier-high specifically for the shadow_it_synthetic source")
    parser.add_argument("--casb-critical", type=float, default=None,
                         help="Override --classifier-critical specifically for the shadow_it_synthetic source")
    args = parser.parse_args()

    print(f"Loading {args.features_in} and recovering timestamps (single shared pass) ...")
    df = load_and_timestamp(args.features_in, args.casb_normalized, args.cert_normalized)

    print(f"Loading CASB shadow_it_category from {args.casb_normalized} ...")
    casb_lookup = load_casb_lookup(args.casb_normalized)
    df["shadow_it_category"] = df["event_id"].map(
        lambda eid: (casb_lookup.get(eid) or {}).get("shadow_it_category")
    )

    def pick_cert_signal(row):
        for c in ("is_removable_media", "external_recipient", "is_exfil_domain"):
            if c in row and row[c] == 1:
                return c
        return None
    df["cert_signal"] = df.apply(pick_cert_signal, axis=1)

    print(f"Loading per-event anomaly scores from {args.scores_in} ...")
    event_scores = pd.read_csv(args.scores_in, usecols=["event_id", "anomaly_score", "top_contributors"])
    scores = df.merge(event_scores, on="event_id", how="left")

    print("Building per-user-per-day heuristic aggregates ...")
    daily = build_daily_aggregates(scores)

    classifier_used = False
    model_path = Path(args.classifier_model)
    if not args.no_classifier and model_path.exists():
        print(f"Loading trained day-level classifier from {model_path} ...")
        bundle = joblib.load(model_path)
        model, feature_cols = bundle["model"], bundle["feature_cols"]

        print("Building day-level RAW feature aggregates for classifier prediction ...")
        daily_features = build_daily_features(df)
        X = daily_features[feature_cols].to_numpy()
        proba = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else model.predict(X)
        daily_features = daily_features[["_username", "_source", "date"]].copy()
        daily_features["classifier_score"] = proba

        daily = daily.merge(daily_features, on=["_username", "_source", "date"], how="left")
        classifier_used = True
        print(f"Classifier ({bundle.get('model_name', 'unknown')}) scored {len(daily_features)} user-days.")
    elif not args.no_classifier:
        print(f"NOTE: no trained classifier found at {model_path} -- falling back to heuristic-only scoring. "
              f"Run classifier_daily.py first to enable the trained-model score.")

    print(f"Loading recommendation engine from {args.report} / {args.claims} ...")
    rec_engine = RecommendationEngine.load(args.report, args.claims)
    daily = attach_recommendations(daily, rec_engine)

    source_thresholds = {}
    casb_override = {}
    if args.casb_low is not None:
        casb_override["low"] = args.casb_low
    if args.casb_medium is not None:
        casb_override["medium"] = args.casb_medium
    if args.casb_high is not None:
        casb_override["high"] = args.casb_high
    if args.casb_critical is not None:
        casb_override["critical"] = args.casb_critical
    if casb_override:
        source_thresholds["shadow_it_synthetic"] = casb_override
        print(f"Using CASB-specific thresholds: {casb_override}")

    daily = compute_risk_scores(daily, args.low_pct, args.medium_pct, args.high_pct, args.critical_pct,
                                 classifier_weight=args.classifier_weight,
                                 classifier_low=args.classifier_low,
                                 classifier_medium=args.classifier_medium,
                                 classifier_high=args.classifier_high,
                                 classifier_critical=args.classifier_critical,
                                 source_thresholds=source_thresholds)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    daily.to_csv(out_path, index=False)
    print(f"\nWrote {len(daily)} user-day risk scores to {out_path}  (scoring mode: "
          f"{'classifier+heuristic' if classifier_used else 'heuristic_only'})")

    print(f"\nRisk category distribution:\n{daily['risk_category'].value_counts().to_string()}")
    evaluate_daily_against_labels(daily)
    print_classifier_threshold_sweep(daily)


if __name__ == "__main__":
    main()
