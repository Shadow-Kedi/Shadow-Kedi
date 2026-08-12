# tests/test_anomaly_detector.py
"""
Tests for pipeline/anomaly_detector.py's compute_deviations() and
score_events() -- the heuristic IDS core. Covers the sentinel-skip
handling (a feature not applicable to a source must never contribute a
false deviation), the zero-variance guard (must not divide by zero, but
must still register max deviation when a constant baseline is violated),
the Z_CLIP ceiling, and the top-contributors explainability output.
"""

import numpy as np
import pandas as pd

from pipeline.anomaly_detector import (
    CONTINUOUS_FEATURES,
    SENTINEL,
    Z_CLIP,
    compute_deviations,
    score_events,
)


def _merged_row(feature_cols, **overrides):
    """Builds a single-row 'merged' DataFrame with the _pmean/_blend_mean/
    _blend_std columns compute_deviations() expects, defaulting every
    feature to a neutral (no-deviation) baseline unless overridden."""
    row = {}
    for f in feature_cols:
        row[f] = 0
        row[f"{f}_pmean"] = 0
        row[f"{f}_blend_mean"] = 0
        if f in CONTINUOUS_FEATURES:
            row[f"{f}_blend_std"] = 1.0  # non-zero default, avoids the zero-variance branch
    row.update(overrides)
    return pd.DataFrame([row])


# ============================================================
# Sentinel handling -- a feature not applicable to this source
# must never contribute a real deviation value
# ============================================================

def test_sentinel_raw_value_is_skipped_not_scored():
    """If the event's OWN value is the sentinel (-1, meaning this field
    doesn't apply to its source), the feature must be NaN in the
    deviation output -- not treated as a real extreme value."""
    feature_cols = ["has_admin_rights"]
    merged = _merged_row(feature_cols, has_admin_rights=SENTINEL,
                          has_admin_rights_pmean=0.3, has_admin_rights_blend_mean=0.3)
    dev = compute_deviations(merged, feature_cols)
    assert pd.isna(dev["has_admin_rights"].iloc[0])


def test_sentinel_population_mean_means_feature_inapplicable_to_source():
    """If the POPULATION mean itself is the sentinel (the whole source
    never has this field, e.g. has_admin_rights for CERT), the feature
    must be skipped for every row of that source, even if the row's own
    value happens to not be -1."""
    feature_cols = ["has_admin_rights"]
    merged = _merged_row(feature_cols, has_admin_rights=1,
                          has_admin_rights_pmean=SENTINEL, has_admin_rights_blend_mean=SENTINEL)
    dev = compute_deviations(merged, feature_cols)
    assert pd.isna(dev["has_admin_rights"].iloc[0])


def test_non_sentinel_feature_is_scored_normally():
    feature_cols = ["is_shadow_it"]
    merged = _merged_row(feature_cols, is_shadow_it=1,
                          is_shadow_it_pmean=0.05, is_shadow_it_blend_mean=0.05)
    dev = compute_deviations(merged, feature_cols)
    assert not pd.isna(dev["is_shadow_it"].iloc[0])
    assert dev["is_shadow_it"].iloc[0] > 0  # 1 vs a baseline rate of 0.05 is a real deviation


# ============================================================
# Zero-variance guard (continuous features)
# ============================================================

def test_zero_variance_with_matching_value_gives_zero_deviation():
    """A continuous feature with zero baseline variance (blend_std=0)
    and a value that MATCHES the constant baseline must score 0
    deviation, not divide-by-zero or NaN."""
    feature_cols = ["hour"]
    merged = _merged_row(feature_cols, hour=10, hour_pmean=10, hour_blend_mean=10, hour_blend_std=0.0)
    dev = compute_deviations(merged, feature_cols)
    assert dev["hour"].iloc[0] == 0.0


def test_zero_variance_with_differing_value_gives_max_deviation():
    """Same zero-variance scenario, but the value DIFFERS from the
    constant baseline -- this should register maximum deviation (1.0
    after normalization by Z_CLIP), since any difference from an
    always-constant value is maximally surprising."""
    feature_cols = ["hour"]
    merged = _merged_row(feature_cols, hour=23, hour_pmean=10, hour_blend_mean=10, hour_blend_std=0.0)
    dev = compute_deviations(merged, feature_cols)
    assert dev["hour"].iloc[0] == 1.0  # combined/Z_CLIP == Z_CLIP/Z_CLIP == 1.0


def test_normal_variance_zscore_computed_correctly():
    feature_cols = ["hour"]
    # value is exactly 2 standard deviations from the mean
    merged = _merged_row(feature_cols, hour=14, hour_pmean=10, hour_blend_mean=10, hour_blend_std=2.0)
    dev = compute_deviations(merged, feature_cols)
    expected = min(2.0, Z_CLIP) / Z_CLIP  # |14-10|/2 = 2.0 std devs, clipped and normalized
    assert abs(dev["hour"].iloc[0] - expected) < 1e-9


def test_zscore_is_clipped_at_z_clip_ceiling():
    """An extreme outlier (50 std devs away) must be clipped to Z_CLIP,
    not allowed to produce an enormous unbounded deviation that would
    dominate the composite score."""
    feature_cols = ["hour"]
    merged = _merged_row(feature_cols, hour=1000, hour_pmean=10, hour_blend_mean=10, hour_blend_std=1.0)
    dev = compute_deviations(merged, feature_cols)
    assert dev["hour"].iloc[0] == 1.0  # clipped to Z_CLIP, normalized to 1.0 -- not > 1.0


# ============================================================
# Binary/rate-based features (non-continuous)
# ============================================================

def test_binary_feature_deviation_is_absolute_difference_from_rate():
    feature_cols = ["is_shadow_it"]
    merged = _merged_row(feature_cols, is_shadow_it=1,
                          is_shadow_it_pmean=0.2, is_shadow_it_blend_mean=0.2)
    dev = compute_deviations(merged, feature_cols)
    assert abs(dev["is_shadow_it"].iloc[0] - 0.8) < 1e-9  # |1 - 0.2|


def test_binary_feature_deviation_capped_at_one():
    """Deviation for a binary/rate feature must never exceed 1.0, even
    if blend_mean is somehow negative or otherwise unusual."""
    feature_cols = ["weird_feature"]
    merged = _merged_row(feature_cols, weird_feature=5,
                          weird_feature_pmean=-3, weird_feature_blend_mean=-3)
    dev = compute_deviations(merged, feature_cols)
    assert dev["weird_feature"].iloc[0] <= 1.0


# ============================================================
# score_events() -- composite score and explainability
# ============================================================

def test_composite_score_is_mean_of_non_nan_deviations():
    dev = pd.DataFrame({
        "feat_a": [0.5],
        "feat_b": [0.3],
        "feat_c": [np.nan],  # skipped (sentinel/inapplicable)
    })
    composite, _ = score_events(dev)
    assert abs(composite.iloc[0] - 0.4) < 1e-9  # mean of 0.5 and 0.3, ignoring the NaN


def test_composite_score_all_nan_defaults_to_zero():
    """A row where every feature was skipped (all NaN) must score 0.0,
    not NaN -- otherwise it would propagate into downstream aggregation
    and threshold comparisons as an undefined value."""
    dev = pd.DataFrame({"feat_a": [np.nan], "feat_b": [np.nan]})
    composite, _ = score_events(dev)
    assert composite.iloc[0] == 0.0


def test_top_contributors_lists_highest_deviation_features_first():
    dev = pd.DataFrame({
        "low_feat": [0.1],
        "high_feat": [0.9],
        "mid_feat": [0.5],
    })
    _, contributors = score_events(dev, top_k=2)
    # top 2 by deviation should be high_feat then mid_feat
    assert "high_feat=0.9" in contributors[0]
    assert "mid_feat=0.5" in contributors[0]
    assert "low_feat" not in contributors[0]


def test_top_contributors_excludes_zero_and_negative_deviations():
    """A feature with 0 deviation (or the -1 fillna sentinel used
    internally for ranking NaN values) must not appear in the
    human-readable explanation, even if it's among the 'top k' by sort
    order."""
    dev = pd.DataFrame({"feat_a": [0.7], "feat_b": [np.nan]})
    _, contributors = score_events(dev, top_k=5)
    assert "feat_a=0.7" in contributors[0]
    assert "feat_b" not in contributors[0]


def test_top_contributors_empty_string_when_nothing_deviates():
    dev = pd.DataFrame({"feat_a": [0.0], "feat_b": [np.nan]})
    _, contributors = score_events(dev)
    assert contributors[0] == ""
