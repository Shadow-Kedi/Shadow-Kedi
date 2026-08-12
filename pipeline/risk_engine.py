# pipeline/risk_engine.py
"""
Step 8 — Risk Scoring Engine

Turns anomaly_detector.py's per-event scores into the blueprint's actual
deliverable: a 0-100 explainable risk score, aggregated per user per day.

WHY AGGREGATE (not just relay per-event scores)

anomaly_detector.py's real-scale validation showed per-event scoring has
an inherent ceiling for high-volume "incidental" event types (login_event,
browser_activity, network_connection/email) -- CERT's ground truth is
WINDOW-based, and most events inside a malicious window are just a
person's ordinary daily activity that happens to timestamp-overlap it.
Aggregating to (user, day) is what the blueprint's own "trend tracking"
and "per-user scoring" deliverables call for, and it's what actually
surfaces a genuinely suspicious event (a file_transfer, a usb_connect)
even when it's sitting next to forty unremarkable logins from the same
person on the same day.

WHY A SEPARATE TIMESTAMP LOOKUP PASS

feature_matrix.csv only has hour/day_of_week (sufficient for features,
not for grouping by calendar day). Rather than reload all 32.7M CERT
events, this does one streaming pass over normalized_cert_events.jsonl,
filtering to only the event_ids actually present in the sampled feature
matrix (a simple set-membership check per line) -- memory-bounded and
far cheaper than a full reload.

Usage:
    python -m pipeline.risk_engine
"""

import argparse
import json
from pathlib import Path

import pandas as pd

from pipeline.recommendations import RecommendationEngine

# Blueprint's official thresholds (Deliverable 4) -- distinct from the
# informal risk_tier bundled in the CASB dataset's own generator, which
# used slightly different cutoffs for its own baseline-heuristic purposes.
# Blueprint's official categories (Deliverable 4) are kept as labels, but
# the boundaries are redefined as PERCENTILE cutoffs on the population,
# not literal numeric-score cutoffs. Reasoning: once risk_score is a
# percentile rank (see compute_risk_scores), applying the blueprint's
# literal Low<=30/Medium<=60/High<=80/Critical>80 numbers directly means
# "bottom 30% / next 30% / next 20% / top 20%" -- which flags a fixed 20%
# of ALL days as High/Critical regardless of how many are actually risky
# (tested: 40% flagged, 2.8% precision, unusable for real triage). A
# human analyst can realistically investigate maybe the top 1-5% of days,
# not 20-40%, so the default cutoffs below target that instead. This is a
# product/ops judgment call, not a purely technical one -- tune via the
# --critical-pct/--high-pct/--medium-pct CLI args for your team's actual
# triage capacity.
def risk_category(percentile_score: float, medium_pct: float, high_pct: float, critical_pct: float) -> str:
    if percentile_score >= critical_pct:
        return "Critical"
    elif percentile_score >= high_pct:
        return "High"
    elif percentile_score >= medium_pct:
        return "Medium"
    else:
        return "Low"


def load_casb_lookup(casb_normalized_path: str) -> dict:
    """event_id -> {timestamp, shadow_it_category} for CASB events only
    (small enough to load in full)."""
    lookup = {}
    with open(casb_normalized_path) as f:
        events = json.load(f)
    for e in events:
        raw = e.get("raw_data") or {}
        lookup[e["event_id"]] = {
            "timestamp": e.get("timestamp"),
            "shadow_it_category": raw.get("shadow_it_category"),
        }
    return lookup


def load_cert_timestamps(cert_normalized_path: str, needed_ids: set, progress_every: int = 5_000_000) -> dict:
    """Single streaming pass over the (potentially huge) CERT jsonl file,
    extracting timestamps ONLY for event_ids in `needed_ids`. Memory stays
    bounded by the size of needed_ids, not the source file."""
    lookup = {}
    n_scanned = 0
    with open(cert_normalized_path) as f:
        for line in f:
            n_scanned += 1
            if n_scanned % progress_every == 0:
                print(f"    ... {n_scanned} CERT lines scanned, {len(lookup)}/{len(needed_ids)} timestamps found so far")
            # cheap pre-check before a full JSON parse: event_id is near the
            # start of each line's JSON, but simplest robust approach is to
            # just parse and check -- still fast enough for one pass.
            event = json.loads(line)
            eid = event.get("event_id")
            if eid in needed_ids:
                lookup[eid] = event.get("timestamp")
                if len(lookup) == len(needed_ids):
                    break
    print(f"CERT timestamp lookup: found {len(lookup)}/{len(needed_ids)} after scanning {n_scanned} lines.")
    return lookup


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


def compute_risk_scores(daily: pd.DataFrame, medium_pct: float, high_pct: float, critical_pct: float) -> pd.DataFrame:
    # primary driver = the day's single worst event (a sharp spike matters
    # more than a mildly elevated average); mean contributes a smaller
    # weight so a day with many moderately-unusual events also registers
    raw = 0.7 * daily["daily_max_score"] + 0.3 * daily["daily_mean_score"]
    daily["raw_composite_score"] = raw  # kept for transparency/debugging

    # Percentile-rank rescaling onto 0-100, not a raw*100 multiply.
    # anomaly_detector.py's composite score is an AVERAGE across ~31
    # normalized per-feature deviations, most of which are 0 for any given
    # event -- its natural range tops out well under 1.0 (observed max
    # ~0.34 on real data), nowhere near a fixed 0-100 scale. The relative
    # RANKING of raw scores is meaningful (real anomalous days scored ~2x
    # higher than normal ones in testing); the raw NUMERIC SCALE just
    # isn't calibrated to 0-100. Percentile rank is a monotonic transform
    # -- it changes the scale, not the ordering.
    percentile_score = raw.rank(pct=True) * 100
    daily["risk_score"] = percentile_score.round(1)
    daily["risk_category"] = percentile_score.apply(
        lambda p: risk_category(p, medium_pct, high_pct, critical_pct)
    )
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


def main():
    parser = argparse.ArgumentParser(description="Aggregate anomaly scores into per-user-per-day explainable risk scores.")
    parser.add_argument("--scores-in", default="data/processed/anomaly_scores.csv")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--casb-normalized", default="data/processed/normalized_events.json")
    parser.add_argument("--cert-normalized", default="data/processed/normalized_cert_events.jsonl")
    parser.add_argument("--report", default="9-shadow-it-full-report.md")
    parser.add_argument("--claims", default="shadow_it_claims.json")
    parser.add_argument("--out", default="data/processed/risk_scores.csv")
    parser.add_argument("--medium-pct", type=float, default=90.0,
                         help="Percentile cutoff for Medium (default: top 10%%)")
    parser.add_argument("--high-pct", type=float, default=97.0,
                         help="Percentile cutoff for High (default: top 3%%)")
    parser.add_argument("--critical-pct", type=float, default=99.0,
                         help="Percentile cutoff for Critical (default: top 1%%)")
    args = parser.parse_args()

    print(f"Loading scores from {args.scores_in} ...")
    scores = pd.read_csv(args.scores_in)

    print(f"Loading signal columns from {args.features_in} for CERT fallback recommendation routing ...")
    feat_cols = pd.read_csv(args.features_in, nrows=1).columns
    signal_cols = [c for c in ("is_removable_media", "external_recipient", "is_exfil_domain") if c in feat_cols]
    signals = pd.read_csv(args.features_in, usecols=["event_id"] + signal_cols)

    def pick_signal(row):
        for c in signal_cols:
            if row.get(c) == 1:
                return c
        return None
    signals["cert_signal"] = signals.apply(pick_signal, axis=1)
    scores = scores.merge(signals[["event_id", "cert_signal"]], on="event_id", how="left")

    print(f"Loading CASB timestamps + shadow_it_category from {args.casb_normalized} ...")
    casb_lookup = load_casb_lookup(args.casb_normalized)

    casb_ids = set(scores.loc[scores["_source"] == "shadow_it_synthetic", "event_id"])
    cert_ids = set(scores.loc[scores["_source"] != "shadow_it_synthetic", "event_id"])

    print(f"Streaming {args.cert_normalized} once for {len(cert_ids)} needed CERT timestamps ...")
    cert_ts_lookup = load_cert_timestamps(args.cert_normalized, cert_ids) if cert_ids else {}

    def get_timestamp(row):
        if row["event_id"] in casb_lookup:
            return casb_lookup[row["event_id"]]["timestamp"]
        return cert_ts_lookup.get(row["event_id"])

    def get_shadow_category(row):
        entry = casb_lookup.get(row["event_id"])
        return entry["shadow_it_category"] if entry else None

    scores["timestamp"] = scores.apply(get_timestamp, axis=1)
    scores["shadow_it_category"] = scores.apply(get_shadow_category, axis=1)

    missing_ts = scores["timestamp"].isna().sum()
    if missing_ts:
        print(f"WARNING: {missing_ts} events had no timestamp found (dropping from daily aggregation).")
        scores = scores.dropna(subset=["timestamp"])

    print("Building per-user-per-day aggregates ...")
    daily = build_daily_aggregates(scores)

    print(f"Loading recommendation engine from {args.report} / {args.claims} ...")
    rec_engine = RecommendationEngine.load(args.report, args.claims)
    daily = attach_recommendations(daily, rec_engine)

    daily = compute_risk_scores(daily, args.medium_pct, args.high_pct, args.critical_pct)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    daily.to_csv(out_path, index=False)
    print(f"\nWrote {len(daily)} user-day risk scores to {out_path}")

    print(f"\nRisk category distribution:\n{daily['risk_category'].value_counts().to_string()}")
    evaluate_daily_against_labels(daily)


if __name__ == "__main__":
    main()
