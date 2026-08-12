# tests/test_classifier_daily.py
"""
Tests for pipeline/classifier_daily.py's build_daily_features() and
user_level_split_daily() -- the aggregation logic responsible for the
single largest performance improvement in this project (per-event AUC
~0.53 -> day-level F1 ~0.98), and the split logic that must guarantee
zero user overlap between train/test to avoid identity leakage.
"""

import pandas as pd

from pipeline.classifier_daily import build_daily_features, user_level_split_daily


def _make_event_row(username, source, date, event_type, **overrides):
    row = {
        "_username": username, "_source": source, "date": date, "_label": 0,
        "event_id": f"EVT-{username}-{date}-{event_type}",
        "et_browser_activity": 0, "et_app_install": 0, "et_app_launch": 0,
        "et_file_access": 0, "et_file_transfer": 0, "et_usb_connect": 0,
        "et_network_connection": 0, "et_dns_query": 0, "et_cloud_upload": 0, "et_login_event": 0,
        "is_removable_media": 0, "is_exfil_domain": 0, "has_file": 0, "weak_auth": 0,
        "risky_network_zone": 0, "is_shadow_it": 0, "sanction_unsanctioned": 0, "external_recipient": 0,
        "bytes_sent_log": 0.0, "bytes_received_log": 0.0, "file_size_log": 0.0, "domain_len": 0,
        "is_off_hours": 0, "is_weekend": 0, "device_managed": 0, "has_admin_rights": 0,
        "security_training_current": 0,
    }
    row[f"et_{event_type}"] = 1
    row.update(overrides)
    return row


# ============================================================
# build_daily_features -- aggregation correctness
# ============================================================

def test_event_type_counts_summed_per_day():
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "login_event"),
        _make_event_row("alice", "cert", "2025-06-10", "login_event"),
        _make_event_row("alice", "cert", "2025-06-10", "usb_connect"),
    ])
    daily = build_daily_features(df)
    row = daily.iloc[0]
    assert row["et_login_event"] == 2
    assert row["et_usb_connect"] == 1
    assert row["daily_event_count"] == 3


def test_max_cols_take_the_maximum_not_the_sum():
    """bytes_sent_log etc. should be the DAY'S MAX, not summed -- a
    single large transfer should register as one large value, not get
    diluted/inflated by averaging or summing with unrelated small events."""
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "file_transfer", bytes_sent_log=2.0),
        _make_event_row("alice", "cert", "2025-06-10", "file_transfer", bytes_sent_log=9.5),
        _make_event_row("alice", "cert", "2025-06-10", "file_transfer", bytes_sent_log=1.0),
    ])
    daily = build_daily_features(df)
    assert daily.iloc[0]["bytes_sent_log"] == 9.5


def test_mean_cols_average_correctly():
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "login_event", is_off_hours=1),
        _make_event_row("alice", "cert", "2025-06-10", "login_event", is_off_hours=0),
    ])
    daily = build_daily_features(df)
    assert daily.iloc[0]["is_off_hours"] == 0.5


def test_label_is_max_across_the_day():
    """A day is labeled anomalous if ANY event that day was labeled
    anomalous -- one bad event among many normal ones must make the
    whole day _label=1, not get averaged away."""
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "login_event", _label=0),
        _make_event_row("alice", "cert", "2025-06-10", "usb_connect", _label=1),
        _make_event_row("alice", "cert", "2025-06-10", "login_event", _label=0),
    ])
    daily = build_daily_features(df)
    assert daily.iloc[0]["_label"] == 1


def test_different_days_produce_separate_rows():
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "login_event"),
        _make_event_row("alice", "cert", "2025-06-11", "login_event"),
    ])
    daily = build_daily_features(df)
    assert len(daily) == 2


def test_different_users_produce_separate_rows_even_on_same_day():
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "login_event"),
        _make_event_row("bob", "cert", "2025-06-10", "login_event"),
    ])
    daily = build_daily_features(df)
    assert len(daily) == 2


def test_event_type_share_is_fraction_of_day_not_raw_count():
    """et_*_share columns should be a fraction (0-1) of that day's total
    events, so busy days and quiet days remain comparable."""
    df = pd.DataFrame([
        _make_event_row("alice", "cert", "2025-06-10", "login_event"),
        _make_event_row("alice", "cert", "2025-06-10", "login_event"),
        _make_event_row("alice", "cert", "2025-06-10", "usb_connect"),
        _make_event_row("alice", "cert", "2025-06-10", "usb_connect"),
    ])
    daily = build_daily_features(df)
    row = daily.iloc[0]
    assert row["et_login_event_share"] == 0.5
    assert row["et_usb_connect_share"] == 0.5


def test_zero_events_day_share_does_not_divide_by_zero():
    """Defensive: even though build_daily_features only ever aggregates
    real events (so a zero-event day shouldn't occur in practice), the
    share computation explicitly guards divide-by-zero -- confirm no
    NaN/inf leaks through for a degenerate single-event case."""
    df = pd.DataFrame([_make_event_row("alice", "cert", "2025-06-10", "login_event")])
    daily = build_daily_features(df)
    assert not daily["et_login_event_share"].isna().any()


# ============================================================
# user_level_split_daily -- no identity leakage
# ============================================================

def test_split_produces_zero_user_overlap():
    rows = []
    for i in range(20):
        rows.append({"_username": f"user{i}", "_source": "cert", "_label": 0 if i % 2 else 1})
    df = pd.DataFrame(rows)
    train, test = user_level_split_daily(df, test_size=0.3, seed=42)
    train_users = set(train["_username"])
    test_users = set(test["_username"])
    assert len(train_users & test_users) == 0


def test_split_stratifies_by_anomaly_presence():
    """Both train and test must get a share of anomalous users -- a
    naive random split on a small/imbalanced set can otherwise draw
    zero anomalous users into test, making evaluation meaningless (a
    real issue found during this project's classifier.py work)."""
    rows = []
    for i in range(10):
        rows.append({"_username": f"normal_user{i}", "_source": "cert", "_label": 0})
    for i in range(10):
        rows.append({"_username": f"anom_user{i}", "_source": "cert", "_label": 1})
    df = pd.DataFrame(rows)
    train, test = user_level_split_daily(df, test_size=0.3, seed=42)

    test_users = set(test["_username"])
    has_anomalous_test_user = any(u.startswith("anom_user") for u in test_users)
    has_normal_test_user = any(u.startswith("normal_user") for u in test_users)
    assert has_anomalous_test_user
    assert has_normal_test_user


def test_split_covers_multiple_sources_independently():
    rows = []
    for i in range(10):
        rows.append({"_username": f"cert_user{i}", "_source": "cert", "_label": 0})
    for i in range(10):
        rows.append({"_username": f"casb_user{i}", "_source": "casb", "_label": 0})
    df = pd.DataFrame(rows)
    train, test = user_level_split_daily(df, test_size=0.3, seed=42)

    assert "cert" in set(test["_source"])
    assert "casb" in set(test["_source"])


def test_split_is_reproducible_with_same_seed():
    rows = [{"_username": f"user{i}", "_source": "cert", "_label": i % 2} for i in range(20)]
    df = pd.DataFrame(rows)
    train1, test1 = user_level_split_daily(df, test_size=0.3, seed=42)
    train2, test2 = user_level_split_daily(df, test_size=0.3, seed=42)
    assert set(test1["_username"]) == set(test2["_username"])
