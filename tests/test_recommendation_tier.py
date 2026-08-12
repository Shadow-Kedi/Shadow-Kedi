# tests/test_recommendation_tier.py
"""
Regression tests for pipeline/recommendation_tier.py.

Covers: all 5 worked examples from the Recommendation Engine Logic
Specification (Section 5), the two bugs found and fixed during review
(Informational escalating via peer_prevalence; the known-bad-category
floor silently overriding an R4 redirect), input validation, and the
documented behavior where peer_prevalence and repeat_count are mutually
exclusive (peer_prevalence takes priority when both fire).

Run with: pytest tests/test_recommendation_tier.py -v
"""

import pytest

from pipeline.recommendation_tier import recommend_tier, apply_recommendation_tiers


# ============================================================
# Spec's own worked examples (Section 5) -- must never regress
# ============================================================

def test_worked_example_1_medium_first_occurrence():
    result = recommend_tier(risk_category="Medium", repeat_count=1)
    assert result["tier"] == "R2"


def test_worked_example_2_medium_fourth_repeat():
    result = recommend_tier(risk_category="Medium", repeat_count=4)
    assert result["tier"] == "R3"


def test_worked_example_3_high_widespread_peer_group():
    result = recommend_tier(risk_category="High", repeat_count=1, peer_prevalence=0.43)
    assert result["tier"] == "R4"


def test_worked_example_4_critical_severe_individual():
    result = recommend_tier(risk_category="Critical", repeat_count=1)
    assert result["tier"] == "R6"


def test_worked_example_5_self_audit_denial_overrides_everything():
    result = recommend_tier(risk_category="Medium", repeat_count=1, self_audit_response="denied")
    assert result["tier"] == "R6"


def test_worked_example_5_denial_overrides_even_critical_base():
    """Denial forces R6 regardless of base tier -- confirm it's not just
    coincidentally already R6 for a Medium base."""
    result = recommend_tier(risk_category="Informational", self_audit_response="denied")
    assert result["tier"] == "R6"


# ============================================================
# Bug fix 1: Informational must never escalate via EITHER
# repeat_count OR peer_prevalence
# ============================================================

def test_informational_does_not_escalate_via_repeat_count():
    result = recommend_tier(risk_category="Informational", repeat_count=100)
    assert result["tier"] == "R1"


def test_informational_does_not_escalate_via_peer_prevalence():
    """This was the actual bug: Informational + high peer_prevalence used
    to redirect to R4, contradicting the module's own stated reasoning
    for why Informational is exempt from individual escalation."""
    result = recommend_tier(risk_category="Informational", peer_prevalence=0.99)
    assert result["tier"] == "R1"


def test_informational_does_not_escalate_via_both_at_once():
    result = recommend_tier(risk_category="Informational", repeat_count=100, peer_prevalence=0.99)
    assert result["tier"] == "R1"


# ============================================================
# Bug fix 2: known-bad-category floor must exempt R4
# ============================================================

def test_known_bad_category_floor_raises_r1_to_r5():
    result = recommend_tier(risk_category="Low", is_known_bad_category=True)
    assert result["tier"] == "R5"


def test_known_bad_category_floor_raises_r2_to_r5():
    result = recommend_tier(risk_category="Medium", is_known_bad_category=True)
    assert result["tier"] == "R5"


def test_known_bad_category_floor_raises_r3_to_r5():
    result = recommend_tier(risk_category="High", is_known_bad_category=True)
    assert result["tier"] == "R5"


def test_known_bad_category_floor_does_not_override_r4_redirect():
    """This was the actual bug: a widespread (R4) known-bad-category event
    used to get silently bumped to R5, defeating the entire point of the
    R4 redirect (evaluate a sanctioned alternative, not block outright) --
    especially damaging for Shadow AI, the category with the strongest
    evidence FOR the sanctioned-alternative approach."""
    result = recommend_tier(risk_category="High", peer_prevalence=0.50, is_known_bad_category=True)
    assert result["tier"] == "R4"


def test_known_bad_category_floor_never_downgrades_r6():
    result = recommend_tier(risk_category="Medium", self_audit_response="denied",
                             is_known_bad_category=True)
    assert result["tier"] == "R6"


def test_known_bad_category_false_has_no_effect():
    result = recommend_tier(risk_category="Low", is_known_bad_category=False)
    assert result["tier"] == "R1"


# ============================================================
# Documented behavior: peer_prevalence and repeat_count are
# mutually exclusive -- peer_prevalence wins when both fire
# ============================================================

def test_peer_prevalence_takes_priority_over_repeat_count():
    result = recommend_tier(risk_category="High", repeat_count=50, peer_prevalence=0.50)
    assert result["tier"] == "R4"
    assert "peer_prevalence" in result["explanation"]
    assert "repeat_count" not in result["explanation"] or "50" not in result["explanation"]


def test_repeat_count_applies_when_peer_prevalence_below_threshold():
    result = recommend_tier(risk_category="High", repeat_count=5, peer_prevalence=0.10)
    assert result["tier"] == "R4"  # High=R3, escalated one step


def test_peer_prevalence_does_not_apply_to_critical_base():
    """A Critical/R6 base isn't downgraded to R4 just because it's also
    widespread -- R6 stays R6."""
    result = recommend_tier(risk_category="Critical", peer_prevalence=0.90)
    assert result["tier"] == "R6"


# ============================================================
# Input validation -- fail-fast on bad data
# ============================================================

def test_invalid_risk_category_raises():
    with pytest.raises(ValueError):
        recommend_tier(risk_category="Nonexistent")


def test_invalid_self_audit_response_raises():
    with pytest.raises(ValueError):
        recommend_tier(risk_category="Medium", self_audit_response="maybe")


def test_peer_prevalence_above_one_raises():
    with pytest.raises(ValueError):
        recommend_tier(risk_category="Medium", peer_prevalence=1.5)


def test_peer_prevalence_negative_raises():
    with pytest.raises(ValueError):
        recommend_tier(risk_category="Medium", peer_prevalence=-0.1)


def test_negative_repeat_count_raises():
    with pytest.raises(ValueError):
        recommend_tier(risk_category="Medium", repeat_count=-1)


def test_peer_prevalence_boundary_values_are_valid():
    """0.0 and 1.0 are valid boundary values, not off-by-one errors."""
    recommend_tier(risk_category="Medium", peer_prevalence=0.0)
    recommend_tier(risk_category="Medium", peer_prevalence=1.0)


# ============================================================
# apply_recommendation_tiers() -- DataFrame batch path
# ============================================================

def test_apply_recommendation_tiers_adds_expected_columns():
    import pandas as pd
    df = pd.DataFrame({"risk_category": ["Medium", "Critical", "Informational"]})
    out = apply_recommendation_tiers(df)
    assert "r_tier" in out.columns
    assert "r_tier_label" in out.columns
    assert "r_tier_explanation" in out.columns
    assert list(out["r_tier"]) == ["R2", "R6", "R1"]


def test_apply_recommendation_tiers_uses_real_columns_when_present():
    """Confirms the forward-compatibility claim: once repeat_count etc.
    exist as real columns, they get used automatically."""
    import pandas as pd
    df = pd.DataFrame({
        "risk_category": ["Medium"],
        "repeat_count": [4],
    })
    out = apply_recommendation_tiers(df)
    assert out["r_tier"].iloc[0] == "R3"  # escalated via the real repeat_count column


def test_apply_recommendation_tiers_does_not_mutate_input():
    import pandas as pd
    df = pd.DataFrame({"risk_category": ["Medium"]})
    original_columns = list(df.columns)
    apply_recommendation_tiers(df)
    assert list(df.columns) == original_columns  # input df untouched
