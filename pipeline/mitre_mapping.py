# pipeline/mitre_mapping.py
"""
Single shared source of MITRE ATT&CK tags for both data sources in this
pipeline. Written to close a real gap: cert_loader.py and the Detection
team's Wazuh rule spec each independently picked MITRE tags with no
shared reference, risking silent drift between the two.

RECONCILIATION FINDING (not a conflict -- checked directly against the
actual code, not memory): cert_loader.py currently applies exactly ONE
coarse tag, T1052 (Exfiltration Over Physical Medium), to every
CERT-flagged anomalous event regardless of scenario. Detection's
proposed T1052.001 (Exfiltration Over USB) is the more specific CHILD
of that same tag -- fully compatible, not overlapping differently. This
module adopts the more specific tag for the case it actually applies to
(removable-media signals) and keeps a sensible fallback for CERT events
where no more specific signal is available.

Detection's other four mappings (T1567.002, T1071.001, T1204, T1005)
cover CASB shadow-IT categories the ML pipeline doesn't currently tag at
all -- pure addition, not reconciliation.

Source: Detection/Security Team Q&A, MITRE mapping proposal, accepted
as-is for the categories it covers.
"""

# CASB shadow_it_category -> MITRE tag, per Detection team's proposal
CASB_CATEGORY_TO_MITRE = {
    "Unsanctioned AI Tools": "T1567.002",
    "Unapproved Cloud Storage & File Sharing": "T1567.002",
    "Unsanctioned Messaging & Collaboration": "T1071.001",
    "Third-Party Integrations & OAuth Grants": "T1071.001",
    "Unauthorized Software Installs": "T1204",
    "Personal Devices (BYOD)": "T1071.001",  # closest fit: BYOD access itself isn't a distinct technique in their proposal
    "Departmental / Citizen IT": "T1204",    # closest fit: unsanctioned software/tooling built by non-IT staff
    "Removable Media & Offline Transfer": "T1052.001",
}

# CERT signal (from feature_engineer.py's is_removable_media / external_recipient /
# is_exfil_domain columns, same signals recommendations.py already uses as a
# fallback) -> MITRE tag
CERT_SIGNAL_TO_MITRE = {
    "is_removable_media": "T1052.001",  # was T1052 (coarse parent) -- now the specific USB child, matching Detection's proposal
    "external_recipient": "T1071.001",
    "is_exfil_domain": "T1567.002",
}

# Fallback for a CERT-flagged event with NONE of the above specific
# signals present -- keeps the original coarse tag rather than tagging
# nothing at all, since these events are still genuinely exfiltration-
# labeled in CERT's own ground truth.
CERT_DEFAULT_MITRE = "T1052"

# Sensitive-data pattern matches (Detection's rules 100060/100061) --
# not currently produced by anything in this ML pipeline, included here
# so the mapping is complete once/if that signal exists upstream.
SENSITIVE_DATA_MITRE = "T1005"


def get_mitre_tag(shadow_it_category: str = None, cert_signal: str = None) -> str:
    """Single lookup function mirroring recommendations.py's own
    get_recommendation() priority order (CASB category first, then CERT
    signal, then a sane default) -- kept consistent so the two lookups
    don't diverge on which signal takes priority."""
    if shadow_it_category and shadow_it_category in CASB_CATEGORY_TO_MITRE:
        return CASB_CATEGORY_TO_MITRE[shadow_it_category]
    if cert_signal and cert_signal in CERT_SIGNAL_TO_MITRE:
        return CERT_SIGNAL_TO_MITRE[cert_signal]
    return CERT_DEFAULT_MITRE
