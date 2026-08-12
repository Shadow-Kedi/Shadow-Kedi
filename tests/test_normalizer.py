# tests/test_normalizer.py
"""
Tests for pipeline/normalizer.py's pure canonicalization functions:
canonicalize_app_name(), canonicalize_domain(), and to_utc(). These are
tested directly (not via the full normalize_event()/normalize_events()
pipeline, which constructs ShadowKediEvent/pydantic objects) since this
is where the actual canonicalization bugs would hide -- confirmed
against real data during this project (e.g. "Zoom (Corporate)" ->
"Zoom", app names varying by qualifier across sources).
"""

from datetime import datetime, timedelta, timezone

from pipeline.normalizer import canonicalize_app_name, canonicalize_domain, to_utc


# ============================================================
# canonicalize_app_name
# ============================================================

def test_strips_corporate_qualifier():
    assert canonicalize_app_name("Zoom (Corporate)") == "Zoom"


def test_strips_personal_account_qualifier():
    assert canonicalize_app_name("ChatGPT (Personal Account)") == "ChatGPT"


def test_strips_unlicensed_qualifier():
    assert canonicalize_app_name("TeamViewer (Unlicensed)") == "TeamViewer"


def test_app_name_without_qualifier_unchanged():
    assert canonicalize_app_name("Slack") == "Slack"


def test_none_input_returns_none():
    assert canonicalize_app_name(None) is None


def test_empty_string_returns_as_is():
    assert canonicalize_app_name("") == ""


def test_only_qualifier_falls_back_to_original():
    """If stripping the qualifier would leave an empty string (a
    degenerate case, e.g. a name that's ENTIRELY a parenthetical), the
    function must fall back to the original rather than return an
    empty/useless app name."""
    result = canonicalize_app_name("(Unknown)")
    assert result == "(Unknown)"  # falls back, doesn't return ""


def test_multiple_parenthetical_groups_only_trailing_one_stripped():
    """Only a TRAILING parenthetical qualifier should be stripped -- a
    name with parentheses in the middle (unusual, but possible) should
    not be mangled."""
    result = canonicalize_app_name("App (Beta) (Corporate)")
    assert result == "App (Beta)"


# ============================================================
# canonicalize_domain
# ============================================================

def test_lowercases_domain():
    assert canonicalize_domain("WikiLeaks.ORG") == "wikileaks.org"


def test_strips_https_scheme():
    assert canonicalize_domain("https://wikileaks.org") == "wikileaks.org"


def test_strips_http_scheme():
    assert canonicalize_domain("http://wikileaks.org") == "wikileaks.org"


def test_strips_path_after_domain():
    assert canonicalize_domain("wikileaks.org/upload/path") == "wikileaks.org"


def test_strips_www_prefix():
    assert canonicalize_domain("www.example.com") == "example.com"


def test_combines_scheme_www_and_path_stripping():
    assert canonicalize_domain("HTTPS://WWW.Example.COM/some/path") == "example.com"


def test_none_domain_returns_none():
    assert canonicalize_domain(None) is None


def test_empty_domain_returns_as_is():
    assert canonicalize_domain("") == ""


def test_domain_without_scheme_or_www_unchanged_besides_case():
    assert canonicalize_domain("Intranet.Company.com") == "intranet.company.com"


def test_strips_surrounding_whitespace():
    assert canonicalize_domain("  wikileaks.org  ") == "wikileaks.org"


# ============================================================
# to_utc
# ============================================================

def test_naive_datetime_tagged_as_utc():
    """A naive (no timezone) datetime is assumed to already be UTC and
    gets tagged accordingly -- not converted, just labeled."""
    naive = datetime(2025, 6, 10, 14, 30)
    result = to_utc(naive)
    assert result.tzinfo == timezone.utc
    assert result.hour == 14  # value unchanged, only the tag added


def test_aware_datetime_converted_to_utc():
    """A timezone-AWARE datetime in a different zone must be actually
    CONVERTED (not just tagged) to the equivalent UTC time."""
    eastern = timezone(timedelta(hours=-5))
    aware = datetime(2025, 6, 10, 14, 30, tzinfo=eastern)  # 14:30 EST = 19:30 UTC
    result = to_utc(aware)
    assert result.tzinfo == timezone.utc
    assert result.hour == 19


def test_already_utc_datetime_unchanged():
    already_utc = datetime(2025, 6, 10, 14, 30, tzinfo=timezone.utc)
    result = to_utc(already_utc)
    assert result == already_utc
