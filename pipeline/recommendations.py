# pipeline/recommendations.py
"""
Loads the Shadow IT Counter-Research report (9-shadow-it-full-report.md +
shadow_it_claims.json, from the Detection & Security Engineering role) and
exposes a lookup from a detected shadow-IT category to sourced, evidence-
tiered recommended fixes. This is what turns risk_engine.py's explainable
output from "why this scored high" into "why this scored high AND what to
do about it."

Deliberately preserves the report's evidence tiers (verified / practice,
not proof / flagged) rather than presenting every recommendation as
equally certain -- that distinction is the whole point of how the report
was built, and collapsing it here would misrepresent the source material.

One gap that existed at first pass -- "Unauthorized Software Installs" (a
CASB shadow-IT category) had no matching report section -- has since been
closed by an addendum (9.10, Unauthorized Remote-Access Tools & P2P/
Torrent Clients), added specifically to cover it.

Usage:
    from pipeline.recommendations import RecommendationEngine
    engine = RecommendationEngine.load(
        report_path="9-shadow-it-full-report.md",
        claims_path="shadow_it_claims.json",
    )
    rec = engine.get_recommendation(shadow_it_category="Removable Media & Offline Transfer")
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

FIX_HEADER_RE = re.compile(
    r"\*\*Fix (\d+) — (.+?)\.\*\*\s*\*\(([^)]+)\)\*"
)
SECTION_HEADER_RE = re.compile(r"^## (9\.\d+) (.+)$", re.MULTILINE)

# CASB shadow_it_category -> report section id. "None" means a deliberate,
# documented gap -- do not guess a mapping for it.
CATEGORY_TO_SECTION = {
    "Unsanctioned AI Tools": "9.6",
    "Unapproved Cloud Storage & File Sharing": "9.4",
    "Unsanctioned Messaging & Collaboration": "9.5",
    "Third-Party Integrations & OAuth Grants": "9.3",
    "Unauthorized Software Installs": "9.10",  # addendum section, added to close this exact gap
    "Personal Devices (BYOD)": "9.2",
    "Departmental / Citizen IT": "9.7",
    "Removable Media & Offline Transfer": "9.1",
}

# Fallback mapping for CERT events, which don't carry a shadow_it_category
# field at all -- inferred from whatever signal is available instead.
CERT_SIGNAL_TO_SECTION = {
    "is_removable_media": "9.1",
    "external_recipient": "9.5",
    "is_exfil_domain": "9.4",  # domain-hint heuristic catches personal-cloud/exfil-style destinations
}


@dataclass
class Fix:
    number: int
    title: str
    tier_note: str


@dataclass
class SectionRecommendation:
    section_id: str
    section_title: str
    fixes: list = field(default_factory=list)


class RecommendationEngine:
    def __init__(self, sections: dict, claims: list):
        self.sections = sections  # section_id -> SectionRecommendation
        self.claims = claims      # raw claims list from the JSON, kept for citation lookups

    @classmethod
    def load(cls, report_path: str, claims_path: str) -> "RecommendationEngine":
        report_text = Path(report_path).read_text()
        sections = cls._parse_sections(report_text)

        claims = []
        claims_path_obj = Path(claims_path)
        if claims_path_obj.exists():
            data = json.loads(claims_path_obj.read_text())
            claims = data.get("claims", [])

        return cls(sections, claims)

    @staticmethod
    def _parse_sections(text: str) -> dict:
        headers = list(SECTION_HEADER_RE.finditer(text))
        sections = {}
        for i, m in enumerate(headers):
            section_id = m.group(1)
            title = m.group(2).split("—")[0].strip()
            start = m.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            body = text[start:end]

            fixes = [
                Fix(number=int(num), title=title_text.strip(), tier_note=tier.strip())
                for num, title_text, tier in FIX_HEADER_RE.findall(body)
            ]
            sections[section_id] = SectionRecommendation(
                section_id=section_id, section_title=title, fixes=fixes
            )
        return sections

    def get_recommendation(self, shadow_it_category: str = None, cert_signal: str = None,
                            max_fixes: int = 2):
        """
        Returns a dict ready to attach to an alert/explanation, or a
        "no_match" dict if there's a documented gap -- never silently
        guesses a section.
        """
        section_id = None
        if shadow_it_category is not None:
            if shadow_it_category not in CATEGORY_TO_SECTION:
                return {"status": "unknown_category", "category": shadow_it_category}
            section_id = CATEGORY_TO_SECTION[shadow_it_category]
        elif cert_signal is not None:
            section_id = CERT_SIGNAL_TO_SECTION.get(cert_signal)

        if section_id is None:
            return {
                "status": "no_match",
                "note": "No corresponding section in the shadow-IT counter-research report "
                        "for this category -- flagged as a documented gap, not guessed.",
            }

        section = self.sections.get(section_id)
        if section is None:
            return {"status": "section_not_found", "section_id": section_id}

        fixes = section.fixes[:max_fixes]
        return {
            "status": "ok",
            "section_id": section.section_id,
            "section_title": section.section_title,
            "recommended_fixes": [
                {"title": f.title, "evidence_tier": f.tier_note} for f in fixes
            ],
        }


if __name__ == "__main__":
    # quick manual smoke test
    engine = RecommendationEngine.load(
        report_path="9-shadow-it-full-report.md",
        claims_path="shadow_it_claims.json",
    )
    for cat in CATEGORY_TO_SECTION:
        print(cat, "->", engine.get_recommendation(shadow_it_category=cat))
