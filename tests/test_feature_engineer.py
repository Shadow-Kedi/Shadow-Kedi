# tests/test_feature_engineer.py
"""
Tests for pipeline/feature_engineer.py's extract_features(). Covers:
label-leakage exclusion (risk_score/risk_category/etc must never appear
as features, since both loaders set them directly FROM the label), the
-1 sentinel convention for source-specific fields, domain/exfil-hint
detection, and time-derived features.
"""

from datetime import datetime, timezone

from pipeline.feature_engineer import extract_features


def _make_event(**overrides):
    event = {
        "event_id": "EVT001",
        "timestamp": datetime(2025, 6, 10, 14, 30, tzinfo=timezone.utc),  # Tuesday, 14:30
        "event_type": "login_event",
        "destination_domain": None,
        "bytes_sent": None,
        "bytes_received": None,
        "file_size_kb": None,
        "file_name": None,
        "raw_data": {},
        "is_anomaly": False,
        "_label": 0,
    }
    event.update(overrides)
    return event


# ============================================================
# Label leakage exclusion -- the single most important property
# ============================================================

def test_risk_score_never_appears_as_a_feature():
    event = _make_event(risk_score=95.0, risk_category="Critical",
                         risk_reasons=["something"], mitre_tags=["T1499"])
    features = extract_features(event)
    assert "risk_score" not in features
    assert "risk_category" not in features
    assert "risk_reasons" not in features
    assert "mitre_tags" not in features


def test_is_anomaly_the_label_itself_does_not_leak_into_features():
    event = _make_event(is_anomaly=True)
    features = extract_features(event)
    assert "is_anomaly" not in features


# ============================================================
# Time-derived features
# ============================================================

def test_hour_and_day_of_week_extracted_correctly():
    event = _make_event(timestamp=datetime(2025, 6, 10, 14, 30, tzinfo=timezone.utc))  # Tuesday
    features = extract_features(event)
    assert features["hour"] == 14
    assert features["day_of_week"] == 1  # Monday=0, Tuesday=1


def test_weekend_flag_true_for_saturday():
    event = _make_event(timestamp=datetime(2025, 6, 14, 12, 0, tzinfo=timezone.utc))  # Saturday
    features = extract_features(event)
    assert features["is_weekend"] == 1


def test_weekend_flag_false_for_wednesday():
    event = _make_event(timestamp=datetime(2025, 6, 11, 12, 0, tzinfo=timezone.utc))  # Wednesday
    features = extract_features(event)
    assert features["is_weekend"] == 0


def test_off_hours_true_before_7am():
    event = _make_event(timestamp=datetime(2025, 6, 10, 3, 0, tzinfo=timezone.utc))
    features = extract_features(event)
    assert features["is_off_hours"] == 1


def test_off_hours_true_after_7pm():
    event = _make_event(timestamp=datetime(2025, 6, 10, 22, 0, tzinfo=timezone.utc))
    features = extract_features(event)
    assert features["is_off_hours"] == 1


def test_off_hours_false_during_business_hours():
    event = _make_event(timestamp=datetime(2025, 6, 10, 10, 0, tzinfo=timezone.utc))
    features = extract_features(event)
    assert features["is_off_hours"] == 0


def test_timestamp_as_iso_string_is_parsed_same_as_datetime_object():
    """normalizer.py stores timestamps as ISO strings; extract_features
    must handle both a real datetime object and a string equivalently."""
    dt = datetime(2025, 6, 10, 14, 30, tzinfo=timezone.utc)
    event_obj = _make_event(timestamp=dt)
    event_str = _make_event(timestamp=dt.isoformat())
    f_obj = extract_features(event_obj)
    f_str = extract_features(event_str)
    assert f_obj["hour"] == f_str["hour"]
    assert f_obj["day_of_week"] == f_str["day_of_week"]


# ============================================================
# Event-type one-hot encoding
# ============================================================

def test_event_type_onehot_marks_correct_column():
    event = _make_event(event_type="usb_connect")
    features = extract_features(event)
    assert features["et_usb_connect"] == 1
    assert features["et_login_event"] == 0
    assert features["et_file_transfer"] == 0


# ============================================================
# Sentinel convention: -1 means "not applicable to this source"
# ============================================================

def test_device_managed_sentinel_when_absent():
    event = _make_event(raw_data={})  # CERT-style event, no device_managed field
    features = extract_features(event)
    assert features["device_managed"] == -1


def test_device_managed_real_value_when_present():
    event = _make_event(raw_data={"device_managed": 1})
    features = extract_features(event)
    assert features["device_managed"] == 1


def test_has_admin_rights_sentinel_when_absent():
    event = _make_event(raw_data={})
    features = extract_features(event)
    assert features["has_admin_rights"] == -1


def test_is_departing_employee_sentinel_when_absent():
    event = _make_event(raw_data={})
    features = extract_features(event)
    assert features["is_departing_employee"] == -1


def test_is_departing_employee_real_zero_is_not_confused_with_sentinel():
    """A REAL value of 0 (not departing) must be distinguishable from
    the -1 'not applicable' sentinel -- this was a real risk given both
    look 'falsy' if checked carelessly."""
    event = _make_event(raw_data={"is_departing_employee": 0})
    features = extract_features(event)
    assert features["is_departing_employee"] == 0
    assert features["is_departing_employee"] != -1


# ============================================================
# Domain / exfil-hint detection
# ============================================================

def test_exfil_domain_hint_detected():
    event = _make_event(destination_domain="wikileaks.org")
    features = extract_features(event)
    assert features["is_exfil_domain"] == 1


def test_normal_domain_not_flagged_as_exfil():
    event = _make_event(destination_domain="intranet.company.com")
    features = extract_features(event)
    assert features["is_exfil_domain"] == 0


def test_no_domain_has_domain_flag_false():
    event = _make_event(destination_domain=None)
    features = extract_features(event)
    assert features["has_domain"] == 0
    assert features["domain_len"] == 0


# ============================================================
# Weak-auth / risky-network-zone detection
# ============================================================

def test_weak_auth_flagged_for_shared_credential():
    event = _make_event(raw_data={"auth_method": "shared_credential"})
    features = extract_features(event)
    assert features["weak_auth"] == 1


def test_strong_auth_not_flagged():
    event = _make_event(raw_data={"auth_method": "corporate_sso"})
    features = extract_features(event)
    assert features["weak_auth"] == 0


def test_risky_network_zone_flagged_for_public_wifi():
    event = _make_event(raw_data={"network_zone": "public_wifi"})
    features = extract_features(event)
    assert features["risky_network_zone"] == 1


# ============================================================
# Removable media detection (multi-source: CERT flags OR CASB category)
# ============================================================

def test_removable_media_detected_via_cert_to_removable_flag():
    event = _make_event(raw_data={"to_removable_media": True})
    features = extract_features(event)
    assert features["is_removable_media"] == 1


def test_removable_media_detected_via_casb_category():
    event = _make_event(raw_data={"shadow_it_category": "Removable Media & Offline Transfer"})
    features = extract_features(event)
    assert features["is_removable_media"] == 1


def test_removable_media_false_when_neither_signal_present():
    event = _make_event(raw_data={})
    features = extract_features(event)
    assert features["is_removable_media"] == 0


# ============================================================
# Bytes / file size log transforms
# ============================================================

def test_bytes_sent_log_transform_applied():
    import math
    event = _make_event(bytes_sent=1000)
    features = extract_features(event)
    assert abs(features["bytes_sent_log"] - math.log1p(1000)) < 1e-9


def test_bytes_sent_none_defaults_to_zero_log():
    event = _make_event(bytes_sent=None)
    features = extract_features(event)
    assert features["bytes_sent_log"] == 0.0


def test_has_file_true_when_file_name_present():
    event = _make_event(file_name="report.docx")
    features = extract_features(event)
    assert features["has_file"] == 1


def test_has_file_false_when_no_file_name():
    event = _make_event(file_name=None)
    features = extract_features(event)
    assert features["has_file"] == 0
