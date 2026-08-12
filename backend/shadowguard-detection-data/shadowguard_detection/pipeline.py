from __future__ import annotations
from .baselines import UserBaseline, build_baselines, circular_distance
from .catalogue import ApplicationCatalogue
from .models import CanonicalEvent, Signal
from .privacy import hmac_domain


def _severity(score: int) -> str:
    return "high" if score >= 75 else "medium" if score >= 50 else "low"


def _anomaly_score(z: float) -> int:
    return min(100, max(0, round((z - 2) * 25)))


class DetectionEngine:
    def __init__(self, catalogue: ApplicationCatalogue, domain_hash_key: str, baseline_window_days: int = 7, min_login_samples: int = 5, min_peer_cohort: int = 5):
        self.catalogue = catalogue
        self.domain_hash_key = domain_hash_key
        self.baseline_window_days = baseline_window_days
        self.min_login_samples = min_login_samples
        self.min_peer_cohort = min_peer_cohort

    def evaluate(self, event: CanonicalEvent, history: list[CanonicalEvent]) -> list[Signal]:
        """Evaluate one event against prior events from the same tenant only."""
        tenant_history = [prior for prior in history if prior.tenant_id == event.tenant_id and prior.event_id != event.event_id]
        users, peers = build_baselines(tenant_history, self.catalogue, self.domain_hash_key, self.baseline_window_days)
        baseline = users.get(event.user_id)
        signals: list[Signal] = []
        domain = event.metadata.get("domain")
        publisher = event.metadata.get("publisher")
        app = self.catalogue.find(domain=domain if isinstance(domain, str) else None, publisher=publisher if isinstance(publisher, str) else None)

        if isinstance(domain, str) or isinstance(publisher, str):
            if app is None:
                signals.append(Signal("unknown_application", "low", 0, "Application is not in the catalogue and requires review; it was not automatically blocked.", {"review_required": True}))
            elif app.approval_state == "unapproved":
                signals.append(Signal("unapproved_app", _severity(app.risk_weight), app.risk_weight, "Application is marked unapproved by policy.", {"application": app.name, "category": app.category, "policy_state": app.approval_state}))
            if app and app.category == "ai" and (baseline is None or app.name not in baseline.known_app_names):
                signals.append(Signal("ai_tool_first_use", "low", 15, "First observed use of a catalogued AI tool for this user.", {"application": app.name, "category": "ai", "first_use": True}))

        if isinstance(domain, str) and baseline and baseline.sample_days >= 1:
            token = hmac_domain(domain, self.domain_hash_key)
            if token not in baseline.known_domain_hashes:
                signals.append(Signal("new_domain", "low", 20, "Destination has not appeared in this user's baseline window.", {"domain_hash": token, "baseline_days": baseline.sample_days}))

        if event.event_type == "login" and baseline and baseline.login_hour_centre is not None and baseline.login_hour_scale and baseline.login_samples >= self.min_login_samples:
            hour = event.occurred_at.hour + event.occurred_at.minute / 60
            distance = circular_distance(hour, baseline.login_hour_centre)
            z = distance / baseline.login_hour_scale
            if z >= 3:
                score = _anomaly_score(z)
                signals.append(Signal("time_anomaly", _severity(score), score, "Login time is outside the user's established pattern.", {"robust_z": round(z, 2), "distance_hours": round(distance, 2), "samples": baseline.login_samples}))

        transferred = int(event.metadata.get("bytes_transferred", 0))
        if transferred and baseline and baseline.sample_days >= 5:
            z = abs(transferred - baseline.daily_bytes_median) / baseline.daily_bytes_scale
            if z >= 3:
                score = _anomaly_score(z)
                signals.append(Signal("volume_anomaly", _severity(score), score, "Transfer volume is outside the user's established daily range.", {"robust_z": round(z, 2), "bytes_transferred": transferred, "baseline_days": baseline.sample_days}))
        department = event.metadata.get("department")
        peer = peers.get(department) if isinstance(department, str) else None
        if transferred and peer and peer.cohort_size >= self.min_peer_cohort:
            z = abs(transferred - peer.daily_bytes_median) / peer.daily_bytes_scale
            if z >= 3:
                score = _anomaly_score(z)
                signals.append(Signal("peer_comparison", _severity(score), score, "Transfer volume is unusual relative to the department cohort.", {"robust_z": round(z, 2), "cohort_size": peer.cohort_size}))

        if event.event_type == "dlp_outcome":
            detectors = event.metadata.get("detectors", [])
            count = int(event.metadata.get("match_count", 0))
            classification = event.metadata.get("classification", "unknown")
            if detectors and count:
                score = 50 if classification == "highly_confidential" else 30
                signals.append(Signal("sensitive_upload", _severity(score), score, "Controlled DLP outcome indicates sensitive-data detectors fired.", {"classification": str(classification), "detectors": ",".join(map(str, detectors)), "match_count": count}))
        return signals
