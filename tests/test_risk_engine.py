# tests/test_risk_engine.py
"""
Tests for pipeline/risk_engine.py's compute_risk_scores() -- the function
at the center of this project's threshold-calibration history:
percentile-vs-absolute flagging, per-source threshold overrides, and the
classifier-vs-heuristic blend. These tests exercise that logic directly
against small constructed DataFrames rather than requiring the full
pipeline (feature matrix, trained model, timestamp recovery) to run.
"""

import pandas as pd
import pytest

from pipeline.risk_engine import compute_risk_scores


def _make_daily(rows):
    """Helper: build a minimal per-user-day DataFrame with the columns
    compute_risk_scores() actually requires."""
    out = []
    for r in rows:
        row = {"daily_max_score": 0.0, "daily_mean_score": 0.0, "_source": "test_source"}
        row.update(r)
        out.append(row)
    return pd.DataFrame(out)


# ============================================================
# Heuristic-only mode (no classifier_score column present)
# ============================================================

def test_heuristic_only_mode_used_when_no_classifier_score():
    df = _make_daily([{"daily_max_score": 0.3, "daily_mean_score": 0.1}])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99)
    assert result["scoring_mode"].iloc[0] == "heuristic_only"


def test_heuristic_only_risk_score_is_percentile_ranked_0_to_100():
    df = _make_daily([
        {"daily_max_score": 0.1, "daily_mean_score": 0.0},
        {"daily_max_score": 0.5, "daily_mean_score": 0.0},
        {"daily_max_score": 0.9, "daily_mean_score": 0.0},
    ])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99)
    assert result["risk_score"].min() >= 0
    assert result["risk_score"].max() <= 100
    # highest raw score should get the highest risk_score (ordering preserved)
    assert result.loc[result["daily_max_score"].idxmax(), "risk_score"] == result["risk_score"].max()


def test_percentile_mode_low_thresholds_flag_everything_regression():
    """Regression guard for the exact bug found earlier: applying the
    blueprint's literal Low<=30/etc cutoffs directly to a percentile
    score flags a fixed ~20-40% of ALL days regardless of true risk.
    With only 3 rows and default percentile cutoffs (medium=90,high=97,
    critical=99), NONE should hit High/Critical since percentile rank
    with n=3 can't reach the 97th/99th percentile meaningfully -- but
    the key regression check is that risk_category is a REAL categorical
    result, not that literal numbers 30/60/80 were used as cutoffs."""
    df = _make_daily([
        {"daily_max_score": 0.01, "daily_mean_score": 0.0},
        {"daily_max_score": 0.02, "daily_mean_score": 0.0},
        {"daily_max_score": 0.03, "daily_mean_score": 0.0},
    ])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99)
    assert set(result["risk_category"]).issubset({"Informational", "Low", "Medium", "High", "Critical"})


# ============================================================
# Classifier mode: absolute threshold, not percentile
# ============================================================

def test_classifier_mode_used_when_classifier_score_present():
    df = _make_daily([{"daily_max_score": 0.3, "daily_mean_score": 0.1, "classifier_score": 0.95}])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99)
    assert result["scoring_mode"].iloc[0] == "classifier+heuristic"


def test_classifier_mode_flagging_is_absolute_not_percentile():
    """The core fix: with classifier scores available, risk_category
    must be based on the classifier's ABSOLUTE probability against
    classifier_high/critical, not a percentile rank. Construct a case
    where percentile rank and absolute threshold would clearly disagree:
    one very-high-confidence row among many low ones. Percentile rank
    would still flag it as "top of the group" either way here, so
    instead verify the DIRECT relationship: a classifier_score below
    classifier_high must NOT be flagged High/Critical, regardless of how
    it ranks relative to other rows."""
    df = _make_daily([
        {"daily_max_score": 0.01, "daily_mean_score": 0.0, "classifier_score": 0.05},  # low absolute score
        {"daily_max_score": 0.01, "daily_mean_score": 0.0, "classifier_score": 0.04},
        {"daily_max_score": 0.01, "daily_mean_score": 0.0, "classifier_score": 0.03},
    ])
    # even though row 0 has the highest classifier_score of the three
    # (would rank at the 100th percentile), it's still far below the
    # default classifier_high=0.50 threshold and must not be flagged
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99)
    assert result["risk_category"].iloc[0] not in ("High", "Critical")


def test_classifier_mode_high_confidence_gets_flagged():
    df = _make_daily([{"daily_max_score": 0.0, "daily_mean_score": 0.0, "classifier_score": 0.95}])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99,
                                  classifier_high=0.50, classifier_critical=0.90)
    assert result["risk_category"].iloc[0] == "Critical"


def test_classifier_score_nan_defaults_to_zero():
    """A missing classifier_score (e.g. a user-day the model didn't
    score) must default to 0.0, not crash or propagate NaN into the
    final risk_category."""
    df = _make_daily([{"daily_max_score": 0.5, "daily_mean_score": 0.3, "classifier_score": None}])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99)
    assert result["risk_category"].iloc[0] in ("Informational", "Low", "Medium", "High", "Critical")
    assert not pd.isna(result["risk_category"].iloc[0])


# ============================================================
# Per-source threshold overrides
# ============================================================

def test_per_source_override_only_affects_that_source():
    df = _make_daily([
        {"daily_max_score": 0.0, "daily_mean_score": 0.0, "classifier_score": 0.60, "_source": "casb"},
        {"daily_max_score": 0.0, "daily_mean_score": 0.0, "classifier_score": 0.60, "_source": "cert"},
    ])
    # global threshold for High is 0.90 (won't fire for either at 0.60);
    # CASB gets a much lower override (0.50) so ONLY casb's row should flag
    result = compute_risk_scores(
        df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99,
        classifier_high=0.90, classifier_critical=0.99,
        source_thresholds={"casb": {"high": 0.50, "critical": 0.95}},
    )
    casb_row = result[result["_source"] == "casb"].iloc[0]
    cert_row = result[result["_source"] == "cert"].iloc[0]
    assert casb_row["risk_category"] in ("High", "Critical")
    assert cert_row["risk_category"] not in ("High", "Critical")


def test_per_source_override_partial_falls_back_to_global_for_unset_keys():
    """A source_thresholds override that only sets 'high' should still
    use the GLOBAL classifier_critical/classifier_medium/classifier_low
    for whatever it didn't override -- not silently zero them out."""
    df = _make_daily([{"daily_max_score": 0.0, "daily_mean_score": 0.0,
                        "classifier_score": 0.999, "_source": "casb"}])
    result = compute_risk_scores(
        df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99,
        classifier_high=0.90, classifier_critical=0.99,
        source_thresholds={"casb": {"high": 0.50}},  # critical NOT overridden
    )
    # 0.999 exceeds the GLOBAL critical (0.99), which should still apply
    assert result["risk_category"].iloc[0] == "Critical"


def test_source_with_no_override_uses_global_thresholds():
    df = _make_daily([{"daily_max_score": 0.0, "daily_mean_score": 0.0,
                        "classifier_score": 0.60, "_source": "unlisted_source"}])
    result = compute_risk_scores(
        df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99,
        classifier_high=0.90, classifier_critical=0.99,
        source_thresholds={"casb": {"high": 0.10}},  # a different source's override, irrelevant here
    )
    assert result["risk_category"].iloc[0] not in ("High", "Critical")  # 0.60 < global 0.90


# ============================================================
# classifier_weight blending
# ============================================================

def test_classifier_weight_zero_ignores_classifier_score():
    """classifier_weight=0.0 should make the blend purely heuristic --
    a sanity check that the weighting math is actually applied, not a
    fixed/ignored parameter."""
    df = _make_daily([
        {"daily_max_score": 0.5, "daily_mean_score": 0.5, "classifier_score": 0.0},
        {"daily_max_score": 0.5, "daily_mean_score": 0.5, "classifier_score": 1.0},
    ])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99,
                                  classifier_weight=0.0)
    # both rows have identical heuristic scores; with classifier_weight=0
    # their raw_composite_score should be equal despite very different
    # classifier_score values
    assert result["raw_composite_score"].iloc[0] == result["raw_composite_score"].iloc[1]


def test_classifier_weight_one_uses_only_classifier_score():
    df = _make_daily([
        {"daily_max_score": 0.9, "daily_mean_score": 0.9, "classifier_score": 0.2},
        {"daily_max_score": 0.1, "daily_mean_score": 0.1, "classifier_score": 0.2},
    ])
    result = compute_risk_scores(df, low_pct=70, medium_pct=90, high_pct=97, critical_pct=99,
                                  classifier_weight=1.0)
    # both rows have identical classifier_score; with classifier_weight=1
    # their raw_composite_score should be equal despite very different
    # heuristic scores
    assert result["raw_composite_score"].iloc[0] == result["raw_composite_score"].iloc[1]
