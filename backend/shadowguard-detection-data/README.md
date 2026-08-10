# ShadowGuard Detection & Data Package

Standalone Detection & Data module for the ShadowGuard AI capstone. It consumes canonical simulated events and returns privacy-preserving, explainable signal records. It does not require the earlier platform or anomaly-engine project files.

## Included capabilities

- Application catalogue lookup by domain or publisher; unknown apps are routed to review, not blocked.
- AI tool and first-use signals.
- Controlled-fixture DLP scanning for common sensitive-data patterns. Scanner output contains detector labels/counts only, never matched text.
- Rolling user and department baselines: login-time pattern, daily transfer volume, known hashed domains, and known apps.
- Signals: `time_anomaly`, `volume_anomaly`, `new_domain`, `peer_comparison`, `unapproved_app`, `ai_tool_first_use`, and `sensitive_upload`.
- Optional Isolation Forest helper, explicitly marked experimental and tenant-local.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Use `DetectionEngine.evaluate(event, history)` for each new canonical event. Pass only the current tenant's history and append the event to history after a successful evaluation.

## Privacy contract

Use a strong `DOMAIN_HASH_KEY` outside source control. Do not persist the `domain` field after classification; signals and baselines contain HMAC domain tokens only. The DLP scanner is for controlled capstone fixtures; it returns classifications, detector names, and counts only. Do not send real employee content or secrets to it.
