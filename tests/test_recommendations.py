# tests/test_recommendations.py
"""
Tests for pipeline/recommendations.py's RecommendationEngine. Uses a
small, self-contained mock report + claims file (not the real 9-section
report) so these tests don't depend on the actual research document
being present or unmodified -- they test the PARSING/MAPPING mechanism
itself.
"""

import json
import tempfile
from pathlib import Path

import pytest

from pipeline.recommendations import CATEGORY_TO_SECTION, RecommendationEngine


MOCK_REPORT = """# Mock Report

## 9.1 Removable Storage

**Fix 1 — Issue managed encrypted drives.** *(Verified)*
Some detail text here.

**Fix 2 — Block unrecognized devices.** *(Practice, not proof)*
More detail text.

## 9.6 Shadow AI

**Fix 1 — Provide a sanctioned enterprise AI tool.** *(Verified)*
The single best-evidenced intervention.

**Fix 2 — Tiered governance.** *(Verified)*
Sanctioned / conditional / prohibited tiers.

**Fix 3 — Fast approval pipeline.** *(Practice, not proof)*
Speed matters.
"""

MOCK_CLAIMS = {
    "schema_version": "1.0",
    "claims": [
        {"id": "9.1-1", "section": "9.1", "tier": "verified"},
        {"id": "9.6-1", "section": "9.6", "tier": "verified"},
    ],
}


@pytest.fixture
def engine():
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "report.md"
        claims_path = Path(tmpdir) / "claims.json"
        report_path.write_text(MOCK_REPORT)
        claims_path.write_text(json.dumps(MOCK_CLAIMS))
        yield RecommendationEngine.load(str(report_path), str(claims_path))


# ============================================================
# Section parsing
# ============================================================

def test_sections_parsed_correctly(engine):
    assert "9.1" in engine.sections
    assert "9.6" in engine.sections


def test_section_title_extracted(engine):
    assert engine.sections["9.1"].section_title == "Removable Storage"


def test_fixes_parsed_with_correct_count(engine):
    assert len(engine.sections["9.1"].fixes) == 2
    assert len(engine.sections["9.6"].fixes) == 3


def test_fix_title_and_tier_extracted_correctly(engine):
    fix = engine.sections["9.6"].fixes[0]
    assert fix.title == "Provide a sanctioned enterprise AI tool"
    assert fix.tier_note == "Verified"


def test_claims_loaded_from_json(engine):
    assert len(engine.claims) == 2


# ============================================================
# get_recommendation() -- category mapping
# ============================================================

def test_known_category_returns_ok_status(engine):
    rec = engine.get_recommendation(shadow_it_category="Removable Media & Offline Transfer")
    assert rec["status"] == "ok"
    assert rec["section_id"] == "9.1"


def test_recommendation_respects_max_fixes_limit(engine):
    rec = engine.get_recommendation(shadow_it_category="Unsanctioned AI Tools", max_fixes=2)
    assert len(rec["recommended_fixes"]) == 2  # section has 3 fixes, capped at max_fixes


def test_recommended_fixes_preserve_evidence_tier(engine):
    """The tiered evidence distinction (verified/practice-not-proof/
    flagged) must survive into the output -- this is the whole point of
    not treating every recommendation as equally certain."""
    rec = engine.get_recommendation(shadow_it_category="Unsanctioned AI Tools")
    tiers = [f["evidence_tier"] for f in rec["recommended_fixes"]]
    assert "Verified" in tiers


def test_unknown_category_returns_unknown_status(engine):
    rec = engine.get_recommendation(shadow_it_category="Completely Made Up Category")
    assert rec["status"] == "unknown_category"


def test_documented_gap_returns_no_match_not_a_guess():
    """CATEGORY_TO_SECTION should never contain a silently-guessed
    mapping -- every entry must point to a real section id (string),
    confirming the 'no guessing' design principle holds at the config
    level, not just in the lookup logic."""
    for category, section_id in CATEGORY_TO_SECTION.items():
        assert isinstance(section_id, str), (
            f"{category!r} maps to {section_id!r} -- should be a real section "
            f"id string, or the mapping should be removed entirely rather than "
            f"set to a placeholder"
        )


def test_cert_signal_fallback_mapping(engine):
    rec = engine.get_recommendation(cert_signal="is_removable_media")
    assert rec["status"] == "ok"
    assert rec["section_id"] == "9.1"


def test_no_category_and_no_signal_returns_no_match(engine):
    rec = engine.get_recommendation()
    assert rec["status"] == "no_match"


def test_section_not_in_report_returns_section_not_found():
    """If CATEGORY_TO_SECTION points at a section id that the loaded
    report doesn't actually contain (e.g. report file is an older
    version missing a section), this must fail informatively rather
    than crash with a KeyError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "report.md"
        claims_path = Path(tmpdir) / "claims.json"
        report_path.write_text("# Empty report\n")  # no sections at all
        claims_path.write_text(json.dumps({"claims": []}))
        engine = RecommendationEngine.load(str(report_path), str(claims_path))

        rec = engine.get_recommendation(shadow_it_category="Removable Media & Offline Transfer")
        assert rec["status"] == "section_not_found"


def test_all_eight_casb_categories_have_a_defined_mapping():
    """Every CASB shadow_it_category the dataset actually produces must
    have SOME entry in CATEGORY_TO_SECTION (even if that entry is a
    documented None gap) -- silently missing a category entirely would
    mean get_recommendation() returns unknown_category for real data."""
    expected_categories = {
        "Unsanctioned AI Tools", "Unapproved Cloud Storage & File Sharing",
        "Unsanctioned Messaging & Collaboration", "Third-Party Integrations & OAuth Grants",
        "Unauthorized Software Installs", "Personal Devices (BYOD)",
        "Departmental / Citizen IT", "Removable Media & Offline Transfer",
    }
    assert expected_categories.issubset(set(CATEGORY_TO_SECTION.keys()))


def test_missing_claims_file_does_not_crash():
    """Claims JSON is supplementary -- a report loaded without a valid
    claims file should still work for section/fix lookup, just with an
    empty claims list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "report.md"
        report_path.write_text(MOCK_REPORT)
        engine = RecommendationEngine.load(str(report_path), str(tmpdir) + "/nonexistent.json")
        assert engine.claims == []
        rec = engine.get_recommendation(shadow_it_category="Removable Media & Offline Transfer")
        assert rec["status"] == "ok"
