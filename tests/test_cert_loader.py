# tests/test_cert_loader.py
"""
Tests for pipeline/cert_loader.py's pure helper functions -- deliberately
NOT the row-to-event conversion functions, which construct ShadowKediEvent
(pydantic) objects and require the real schema module. These functions
were chosen because they hold the highest-value, most bug-prone logic:
infer_http_activity() is where a real false positive was found and fixed
during this project (a legitimate internal CRM upload was being flagged
as exfiltration because generic content markers like "multipart/form-
data" are the mechanics of ANY web upload form, not something specific
to attacks); is_malicious() is the core window-based ground-truth
matching that CERT's entire label scheme depends on.
"""

from datetime import datetime

from pipeline.cert_loader import (
    _truthy,
    domain_from_url,
    infer_http_activity,
    is_malicious,
    parse_dt,
)


# ============================================================
# parse_dt -- CERT's date format
# ============================================================

def test_parse_dt_standard_cert_format():
    dt = parse_dt("3/6/2010 1:41:56")
    assert dt == datetime(2010, 3, 6, 1, 41, 56)


def test_parse_dt_handles_surrounding_whitespace():
    dt = parse_dt("  3/6/2010 1:41:56  ")
    assert dt == datetime(2010, 3, 6, 1, 41, 56)


# ============================================================
# _truthy -- CSV string -> bool coercion
# ============================================================

def test_truthy_recognizes_true_variants():
    assert _truthy("True") is True
    assert _truthy("true") is True
    assert _truthy("1") is True
    assert _truthy("yes") is True


def test_truthy_recognizes_false_variants():
    assert _truthy("False") is False
    assert _truthy("false") is False
    assert _truthy("0") is False
    assert _truthy("") is False
    assert _truthy(None) is False


# ============================================================
# domain_from_url
# ============================================================

def test_domain_from_url_with_scheme():
    assert domain_from_url("http://wikileaks.org/upload") == "wikileaks.org"


def test_domain_from_url_without_scheme():
    """CERT's http.csv URLs sometimes lack a scheme entirely -- must
    still resolve to the correct domain rather than treating the whole
    string as a path."""
    assert domain_from_url("wikileaks.org/upload") == "wikileaks.org"


def test_domain_from_url_empty_string_returns_none():
    assert domain_from_url("") is None


def test_domain_from_url_malformed_does_not_crash():
    result = domain_from_url("not a url at all :::")
    assert result is None or isinstance(result, str)  # must not raise


# ============================================================
# infer_http_activity -- the heuristic classifier with real bug history
# ============================================================

def test_known_exfil_domain_classified_as_upload():
    event_type, label, reason = infer_http_activity("http://wikileaks.org/upload", "some content")
    assert label == "upload"
    assert "domain_hint" in reason


def test_mega_domain_classified_as_upload():
    event_type, label, reason = infer_http_activity("http://mega.nz/file/abc123", "")
    assert label == "upload"


def test_download_extension_classified_as_download():
    event_type, label, reason = infer_http_activity("http://files.example.com/report.pdf", "")
    assert label == "download"
    assert "url_extension" in reason


def test_download_extension_with_query_string_still_detected():
    """A URL like report.pdf?token=abc123 must still match the .pdf
    extension -- the extension check needs to ignore the query string,
    not just check the raw string's ending."""
    event_type, label, reason = infer_http_activity("http://files.example.com/report.pdf?token=abc123", "")
    assert label == "download"


def test_normal_browsing_classified_as_browse():
    event_type, label, reason = infer_http_activity("http://news.google.com/search?q=weather", "Weather results")
    assert label == "browse"
    assert reason == "no_hint_matched"


def test_internal_intranet_domain_not_flagged():
    event_type, label, reason = infer_http_activity("http://intranet.dtaa.com/news", "Company newsletter")
    assert label == "browse"


def test_legitimate_crm_upload_not_flagged_as_exfiltration():
    """REGRESSION TEST for the actual bug found during this project: a
    legitimate internal CRM API call using multipart/form-data content
    (the standard mechanics of ANY web upload form) was being flagged as
    'upload' purely because of generic content-keyword matching. Fixed
    by removing content-keyword heuristics entirely, keeping only
    specific domain-hint and file-extension matching. This must never
    regress back to flagging ordinary business traffic."""
    event_type, label, reason = infer_http_activity(
        "http://company-crm.dtaa.com/api",
        "multipart/form-data; boundary=xyz customer record update",
    )
    assert label == "browse"  # NOT "upload" -- this was the actual bug


def test_case_insensitive_domain_matching():
    event_type, label, reason = infer_http_activity("http://WIKILEAKS.ORG/upload", "")
    assert label == "upload"


# ============================================================
# is_malicious -- window-based ground truth matching
# ============================================================

def test_timestamp_inside_window_is_malicious():
    windows = {"alice": [(datetime(2010, 2, 15, 23, 0), datetime(2010, 2, 16, 1, 0), "S1")]}
    is_bad, scenario = is_malicious("alice", datetime(2010, 2, 15, 23, 50), windows)
    assert is_bad is True
    assert scenario == "S1"


def test_timestamp_just_before_window_is_not_malicious():
    """Boundary check: a timestamp one minute before the window start
    must NOT be flagged -- this is exactly the kind of off-by-one that
    could silently mislabel real data."""
    windows = {"alice": [(datetime(2010, 2, 15, 23, 0), datetime(2010, 2, 16, 1, 0), "S1")]}
    is_bad, scenario = is_malicious("alice", datetime(2010, 2, 15, 22, 59), windows)
    assert is_bad is False


def test_timestamp_just_after_window_is_not_malicious():
    """This is the exact boundary case validated during this project:
    a departing-employee's LOGOFF event just after their malicious
    window ended was confirmed to correctly stay non-anomalous."""
    windows = {"alice": [(datetime(2010, 2, 15, 23, 0), datetime(2010, 2, 16, 1, 0), "S1")]}
    is_bad, scenario = is_malicious("alice", datetime(2010, 2, 16, 1, 1), windows)
    assert is_bad is False


def test_timestamp_at_exact_window_boundaries_is_malicious():
    """Boundaries are inclusive on both ends."""
    windows = {"alice": [(datetime(2010, 2, 15, 23, 0), datetime(2010, 2, 16, 1, 0), "S1")]}
    assert is_malicious("alice", datetime(2010, 2, 15, 23, 0), windows)[0] is True
    assert is_malicious("alice", datetime(2010, 2, 16, 1, 0), windows)[0] is True


def test_user_with_no_windows_is_never_malicious():
    windows = {"alice": [(datetime(2010, 2, 15, 23, 0), datetime(2010, 2, 16, 1, 0), "S1")]}
    is_bad, scenario = is_malicious("bob", datetime(2010, 2, 15, 23, 30), windows)
    assert is_bad is False
    assert scenario is None


def test_empty_windows_dict_never_flags_anyone():
    is_bad, scenario = is_malicious("alice", datetime(2010, 2, 15, 23, 30), {})
    assert is_bad is False


def test_user_with_multiple_windows_checked_against_all():
    windows = {"alice": [
        (datetime(2010, 1, 1), datetime(2010, 1, 2), "S1"),
        (datetime(2010, 6, 1), datetime(2010, 6, 2), "S3"),
    ]}
    is_bad, scenario = is_malicious("alice", datetime(2010, 6, 1, 12, 0), windows)
    assert is_bad is True
    assert scenario == "S3"
