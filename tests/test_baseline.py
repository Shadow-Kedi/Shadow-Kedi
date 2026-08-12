# tests/test_baseline.py
"""
Tests for pipeline/baseline.py.

The most important tests here are the contamination regressions: an
earlier version of this module built "normal behavior" baselines from a
user's ENTIRE event history, including their own anomalous events. Since
feature_engineer.py keeps 100% of anomalies but only ~4.6% of normal
CERT events, a malicious user's baseline could end up mostly built from
their own attack behavior -- making continued malicious activity score
as "normal" relative to a baseline that partly WAS that malicious
activity. Fixed by filtering to _label==0 before aggregating. These
tests construct a deliberately contaminated scenario and confirm the
fix actually excludes the anomalous rows.
"""

import numpy as np
import pandas as pd
import pytest

from pipeline.baseline import build_source_population_stats, build_user_baselines


def _make_df(rows):
    """Helper: build a minimal feature-matrix-shaped DataFrame from a
    list of dicts, filling any unspecified feature columns with 0."""
    feature_cols = ["hour", "bytes_sent_log", "is_off_hours", "et_login_event"]
    out = []
    for r in rows:
        row = {c: 0 for c in feature_cols}
        row.update(r)
        out.append(row)
    return pd.DataFrame(out)


# ============================================================
# Contamination regression: a user whose baseline would be
# mostly-anomalous if unfiltered
# ============================================================

def test_user_baseline_excludes_users_own_anomalous_events():
    """A user with 1 normal event (hour=9) and 3 anomalous events
    (hour=3, heavily off-hours) -- an UNFILTERED baseline would average
    all 4 and show a contaminated ~4.5-hour mean. The fix must produce
    a baseline built from the single normal event only (hour=9)."""
    df = _make_df([
        {"_username": "alice", "_source": "cert_insider_threat", "_label": 0, "hour": 9},
        {"_username": "alice", "_source": "cert_insider_threat", "_label": 1, "hour": 3},
        {"_username": "alice", "_source": "cert_insider_threat", "_label": 1, "hour": 2},
        {"_username": "alice", "_source": "cert_insider_threat", "_label": 1, "hour": 3},
    ])
    baselines = build_user_baselines(df)
    alice = baselines[baselines["username"] == "alice"].iloc[0]

    assert alice["hour_mean"] == 9.0  # NOT contaminated toward the anomalous hour=2/3 events
    assert alice["event_count"] == 1  # only the one normal event counted
    assert alice["labeled_anomaly_count"] == 3  # anomaly count still tracked separately


def test_user_with_zero_normal_events_still_appears_with_zero_count():
    """A user whose entire history is anomalous (0 surviving normal
    events after sampling) must still appear in the output -- with
    event_count=0 and NaN stats -- so downstream shrinkage can fall back
    fully to the population baseline, rather than the user silently
    disappearing from the baseline table."""
    df = _make_df([
        {"_username": "bob", "_source": "cert_insider_threat", "_label": 1, "hour": 3},
        {"_username": "bob", "_source": "cert_insider_threat", "_label": 1, "hour": 4},
    ])
    baselines = build_user_baselines(df)
    assert "bob" in baselines["username"].values
    bob = baselines[baselines["username"] == "bob"].iloc[0]
    assert bob["event_count"] == 0
    assert bob["labeled_anomaly_count"] == 2


def test_source_population_stats_excludes_anomalous_events():
    """Same contamination principle at the population level: population
    stats must also be built from _label==0 only."""
    df = _make_df([
        {"_username": "u1", "_source": "cert_insider_threat", "_label": 0, "hour": 10},
        {"_username": "u2", "_source": "cert_insider_threat", "_label": 0, "hour": 10},
        {"_username": "u3", "_source": "cert_insider_threat", "_label": 1, "hour": 2},
        {"_username": "u3", "_source": "cert_insider_threat", "_label": 1, "hour": 2},
    ])
    stats = build_source_population_stats(df)
    row = stats[stats["source"] == "cert_insider_threat"].iloc[0]

    assert row["hour_mean"] == 10.0  # NOT pulled toward the anomalous hour=2 events
    assert row["n_normal_events"] == 2
    assert row["n_total_events"] == 4  # total count still reported for transparency
    assert abs(row["anomaly_rate"] - 0.5) < 1e-9  # 2 of 4 total events were anomalous


# ============================================================
# Normal (non-contamination) behavior
# ============================================================

def test_user_baseline_averages_multiple_normal_events_correctly():
    df = _make_df([
        {"_username": "carol", "_source": "shadow_it_synthetic", "_label": 0, "hour": 8},
        {"_username": "carol", "_source": "shadow_it_synthetic", "_label": 0, "hour": 12},
        {"_username": "carol", "_source": "shadow_it_synthetic", "_label": 0, "hour": 16},
    ])
    baselines = build_user_baselines(df)
    carol = baselines[baselines["username"] == "carol"].iloc[0]
    assert carol["hour_mean"] == 12.0  # (8+12+16)/3
    assert carol["event_count"] == 3


def test_user_baseline_std_is_zero_not_nan_for_single_event():
    """A user with exactly one normal event has zero observed variance
    -- std must be filled to 0.0, not left as NaN (which would break
    downstream z-score division)."""
    df = _make_df([
        {"_username": "dave", "_source": "cert_insider_threat", "_label": 0, "hour": 9},
    ])
    baselines = build_user_baselines(df)
    dave = baselines[baselines["username"] == "dave"].iloc[0]
    assert dave["hour_std"] == 0.0
    assert not pd.isna(dave["hour_std"])


def test_et_columns_use_share_not_raw_count():
    """Event-type (et_*) columns should be reported as a SHARE of that
    user's total events, not a raw count -- so users with very different
    total activity volume remain comparable."""
    df = _make_df([
        {"_username": "erin", "_source": "cert_insider_threat", "_label": 0, "et_login_event": 1},
        {"_username": "erin", "_source": "cert_insider_threat", "_label": 0, "et_login_event": 0},
    ])
    baselines = build_user_baselines(df)
    erin = baselines[baselines["username"] == "erin"].iloc[0]
    assert erin["et_login_event_share"] == 0.5  # 1 of 2 events


def test_source_population_flags_zero_variance_columns():
    """A column that's constant across an entire source (e.g. a sentinel
    value always -1 for that source) should be printed as a NOTE so
    downstream code knows to guard against dividing by zero -- not fail
    silently."""
    import contextlib
    import io

    df = _make_df([
        {"_username": "u1", "_source": "cert_insider_threat", "_label": 0, "bytes_sent_log": -1},
        {"_username": "u2", "_source": "cert_insider_threat", "_label": 0, "bytes_sent_log": -1},
    ])
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        build_source_population_stats(df)
    output = captured.getvalue()
    assert "zero variance" in output
    assert "bytes_sent_log_std" in output


def test_multiple_sources_produce_separate_rows():
    df = _make_df([
        {"_username": "u1", "_source": "cert_insider_threat", "_label": 0, "hour": 10},
        {"_username": "u2", "_source": "shadow_it_synthetic", "_label": 0, "hour": 14},
    ])
    stats = build_source_population_stats(df)
    assert set(stats["source"]) == {"cert_insider_threat", "shadow_it_synthetic"}
    assert len(stats) == 2
