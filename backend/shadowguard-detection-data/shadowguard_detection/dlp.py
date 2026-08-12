"""Controlled-fixture DLP. Results never contain matched values."""
import re
from dataclasses import dataclass

PATTERNS = {
    "api_key": re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*['\"]?[a-z0-9_-]{12,}"),
    "password": re.compile(r"(?i)\bpassword\s*[:=]\s*['\"]?\S{8,}"),
    "jwt": re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-\d{2}-\d{4}\b"),
    "connection_string": re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s]+"),
}
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


@dataclass(frozen=True)
class DLPResult:
    classification: str
    detectors: tuple[str, ...]
    match_count: int

    def safe_payload(self) -> dict[str, object]:
        return {"classification": self.classification, "detectors": list(self.detectors), "match_count": self.match_count}


def _luhn(number: str) -> bool:
    digits = [int(char) for char in number if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        checksum += digit if index % 2 == 0 else (digit * 2 - 9 if digit > 4 else digit * 2)
    return checksum % 10 == 0


def scan_fixture_text(text: str) -> DLPResult:
    """Only call this with controlled capstone fixtures, never retained production content."""
    found = {name: len(pattern.findall(text)) for name, pattern in PATTERNS.items()}
    cards = sum(1 for candidate in CARD_RE.findall(text) if _luhn(candidate))
    emails = len(EMAIL_RE.findall(text))
    if cards:
        found["credit_card"] = cards
    if emails >= 3:
        found["email_list"] = emails
    detectors = tuple(sorted(name for name, count in found.items() if count))
    count = sum(found[name] for name in detectors)
    classification = "highly_confidential" if {"aws_key", "ssn", "credit_card", "password"}.intersection(detectors) else "confidential" if detectors else "public"
    return DLPResult(classification, detectors, count)
