# tests/test_synthetic_data.py
"""
Tests for pipeline/synthetic_data.py's pure helper functions: _safe()
(the None/NaN/"none"-string normalizer used throughout the CASB loader)
and _build_risk_reasons() (the explainability-reason builder). Tested
directly rather than via row_to_event(), which constructs a
ShadowKediEvent (pydantic) object.
"""

import math

from pipeline.synthetic_data import _build_risk_reasons, _safe


# ============================================================
# _safe
# ============================================================

def test_safe_passes_through_normal_value():
    assert _safe("Zoom") == "Zoom"
    assert _safe(42) == 42


def test_safe_none_stays_none():
    assert _safe(None) is None


def test_safe_nan_float_becomes_none():
    assert _safe(float("nan")) is None


def test_safe_string_none_becomes_none():
    """The CASB CSV source represents missing values as the literal
    string 'None' in some columns -- must be treated the same as a real
    None, not passed through as a truthy non-empty string."""
    assert _safe("None") is None
    assert _safe("none") is None
    assert _safe("NONE") is None


def test_safe_string_nan_becomes_none():
    assert _safe("nan") is None


def test_safe_empty_string_becomes_none():
    assert _safe("") is None


def test_safe_whitespace_only_string_becomes_none():
    assert _safe("   ") is None


def test_safe_zero_is_not_treated_as_none():
    """A real value of 0 (a legitimate falsy-but-meaningful value, e.g.
    policy_violation=0) must NOT be converted to None -- this would be
    a serious bug if 0 and 'missing' were confused."""
    assert _safe(0) == 0
    assert _safe(0.0) == 0.0


def test_safe_false_is_not_treated_as_none():
    assert _safe(False) is False


# ============================================================
# _build_risk_reasons
# ============================================================

def test_off_hours_reason_added():
    row = {"is_off_hours": 1}
    reasons = _build_risk_reasons(row)
    assert "off_hours_activity" in reasons


def test_off_hours_reason_not_added_when_zero():
    row = {"is_off_hours": 0}
    reasons = _build_risk_reasons(row)
    assert "off_hours_activity" not in reasons


def test_unmanaged_device_reason_added():
    row = {"device_managed": 0}
    reasons = _build_risk_reasons(row)
    assert "unmanaged_device" in reasons


def test_shadow_it_category_reason_includes_category_name():
    row = {"shadow_it_category": "Unsanctioned AI Tools"}
    reasons = _build_risk_reasons(row)
    assert "shadow_it:Unsanctioned AI Tools" in reasons


def test_unsanctioned_status_reason_added():
    row = {"sanction_status": "Unsanctioned"}
    reasons = _build_risk_reasons(row)
    assert "unsanctioned_application" in reasons


def test_sanctioned_status_does_not_add_reason():
    row = {"sanction_status": "Sanctioned"}
    reasons = _build_risk_reasons(row)
    assert "unsanctioned_application" not in reasons


def test_weak_auth_methods_all_detected():
    for method in ("personal_email_signup", "shared_credential", "none"):
        row = {"auth_method": method}
        reasons = _build_risk_reasons(row)
        assert "weak_auth_method" in reasons


def test_strong_auth_method_not_flagged():
    row = {"auth_method": "corporate_sso"}
    reasons = _build_risk_reasons(row)
    assert "weak_auth_method" not in reasons


def test_restricted_pii_data_class_flagged():
    row = {"data_classification": "Restricted-PII"}
    reasons = _build_risk_reasons(row)
    assert "sensitive_data:Restricted-PII" in reasons


def test_public_data_class_not_flagged():
    row = {"data_classification": "Public"}
    reasons = _build_risk_reasons(row)
    assert not any("sensitive_data" in r for r in reasons)


def test_broad_oauth_scope_full_access_flagged():
    row = {"oauth_scope_granted": "read:mail full_access"}
    reasons = _build_risk_reasons(row)
    assert "broad_oauth_scope" in reasons


def test_broad_oauth_scope_admin_flagged():
    row = {"oauth_scope_granted": "admin:directory"}
    reasons = _build_risk_reasons(row)
    assert "broad_oauth_scope" in reasons


def test_narrow_oauth_scope_not_flagged():
    row = {"oauth_scope_granted": "read:calendar"}
    reasons = _build_risk_reasons(row)
    assert "broad_oauth_scope" not in reasons


def test_policy_violation_reason_added():
    row = {"policy_violation": 1}
    reasons = _build_risk_reasons(row)
    assert "policy_violation" in reasons


def test_missing_fields_produce_no_matching_reasons():
    """A row with no risk-relevant fields at all should produce an empty
    reason list, not crash on missing keys."""
    row = {}
    reasons = _build_risk_reasons(row)
    assert reasons == []


def test_multiple_reasons_combine_in_one_row():
    row = {
        "is_off_hours": 1,
        "device_managed": 0,
        "sanction_status": "Unsanctioned",
        "auth_method": "shared_credential",
    }
    reasons = _build_risk_reasons(row)
    assert len(reasons) == 4
    assert "off_hours_activity" in reasons
    assert "unmanaged_device" in reasons
    assert "unsanctioned_application" in reasons
    assert "weak_auth_method" in reasons


def test_string_none_values_in_row_do_not_produce_false_reasons():
    """Fields that are the literal string 'None' (as they'd appear from
    a raw CSV read) must be treated as absent by _safe(), not matched
    against any reason condition."""
    row = {"sanction_status": "None", "auth_method": "None", "data_classification": "None"}
    reasons = _build_risk_reasons(row)
    assert reasons == []
