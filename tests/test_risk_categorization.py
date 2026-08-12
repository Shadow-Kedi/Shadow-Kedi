# tests/test_risk_categorization.py
"""
Tests for pipeline/risk_categorization.py -- the shared 5-tier
(Informational/Low/Medium/High/Critical) categorization logic used by
both risk_engine.py's percentile-rank mode and its classifier-probability
mode.
"""

import pytest

from pipeline.risk_categorization import (
    DEFAULT_LABELS,
    TierBoundaries,
    categorize,
    classifier_boundaries,
    percentile_boundaries,
)


# ============================================================
# TierBoundaries validation
# ============================================================

def test_boundaries_must_be_strictly_ascending():
    with pytest.raises(ValueError):
        TierBoundaries(low=10, medium=10, high=20, critical=30)  # low == medium


def test_boundaries_reject_out_of_order():
    with pytest.raises(ValueError):
        TierBoundaries(low=50, medium=30, high=70, critical=90)  # medium < low


def test_boundaries_accept_valid_ascending_values():
    b = TierBoundaries(low=10, medium=20, high=30, critical=40)
    assert b.low < b.medium < b.high < b.critical


# ============================================================
# categorize() -- boundary correctness (each tier's edges)
# ============================================================

@pytest.fixture
def boundaries():
    return TierBoundaries(low=10, medium=20, high=30, critical=40)


def test_value_below_low_is_informational(boundaries):
    assert categorize(5, boundaries) == "Informational"


def test_value_exactly_at_low_is_low_not_informational(boundaries):
    """Boundary is inclusive on the lower tier's side (>=), matching
    categorize()'s implementation -- a value AT the cutoff belongs to
    the tier it just entered, not the one it left."""
    assert categorize(10, boundaries) == "Low"


def test_value_just_below_low_is_informational(boundaries):
    assert categorize(9.99, boundaries) == "Informational"


def test_value_exactly_at_medium_is_medium(boundaries):
    assert categorize(20, boundaries) == "Medium"


def test_value_exactly_at_high_is_high(boundaries):
    assert categorize(30, boundaries) == "High"


def test_value_exactly_at_critical_is_critical(boundaries):
    assert categorize(40, boundaries) == "Critical"


def test_value_far_above_critical_is_still_critical(boundaries):
    assert categorize(1000, boundaries) == "Critical"


def test_value_far_below_zero_is_informational(boundaries):
    assert categorize(-100, boundaries) == "Informational"


# ============================================================
# categorize() -- custom labels
# ============================================================

def test_custom_labels_are_used(boundaries):
    custom = ("None", "Minor", "Moderate", "Severe", "Emergency")
    assert categorize(5, boundaries, labels=custom) == "None"
    assert categorize(40, boundaries, labels=custom) == "Emergency"


def test_wrong_number_of_labels_raises(boundaries):
    with pytest.raises(ValueError):
        categorize(5, boundaries, labels=("OnlyOne",))


def test_default_labels_are_the_five_expected():
    assert DEFAULT_LABELS == ("Informational", "Low", "Medium", "High", "Critical")
    assert len(DEFAULT_LABELS) == 5


# ============================================================
# percentile_boundaries() preset
# ============================================================

def test_percentile_boundaries_default_values():
    b = percentile_boundaries()
    assert (b.low, b.medium, b.high, b.critical) == (70.0, 90.0, 97.0, 99.0)


def test_percentile_boundaries_preserves_existing_medium_high_critical():
    """Regression: adding the Low tier must not have shifted the
    pre-existing Medium/High/Critical cutoffs (90th/97th/99th
    percentile) that were already tuned and locked in before Informational
    was introduced."""
    b = percentile_boundaries()
    assert b.medium == 90.0
    assert b.high == 97.0
    assert b.critical == 99.0


def test_percentile_boundaries_custom_values():
    b = percentile_boundaries(low_pct=60.0, medium_pct=85.0, high_pct=95.0, critical_pct=99.5)
    assert (b.low, b.medium, b.high, b.critical) == (60.0, 85.0, 95.0, 99.5)


def test_percentile_boundaries_full_range_categorization():
    """End-to-end: a realistic percentile score at each tier lands
    correctly through the full preset -> categorize() path."""
    b = percentile_boundaries()
    assert categorize(50.0, b) == "Informational"
    assert categorize(75.0, b) == "Low"
    assert categorize(93.0, b) == "Medium"
    assert categorize(98.0, b) == "High"
    assert categorize(99.9, b) == "Critical"


# ============================================================
# classifier_boundaries() preset
# ============================================================

def test_classifier_boundaries_default_values():
    b = classifier_boundaries()
    assert (b.low, b.medium, b.high, b.critical) == (0.02, 0.10, 0.50, 0.90)


def test_classifier_boundaries_custom_values():
    """This is the shape risk_engine.py's --casb-high etc. overrides
    actually construct at runtime -- confirm arbitrary tuned values work,
    not just the defaults."""
    b = classifier_boundaries(low=0.01, medium=0.15, high=0.9857, critical=0.9926)
    assert categorize(0.9857, b) == "High"
    assert categorize(0.9926, b) == "Critical"
    assert categorize(0.005, b) == "Informational"


def test_classifier_boundaries_full_range_categorization():
    b = classifier_boundaries()
    assert categorize(0.001, b) == "Informational"
    assert categorize(0.05, b) == "Low"
    assert categorize(0.30, b) == "Medium"
    assert categorize(0.70, b) == "High"
    assert categorize(0.95, b) == "Critical"
