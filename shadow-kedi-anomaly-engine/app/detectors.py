from __future__ import annotations
from datetime import UTC
from .baselines import PeerBaseline, UserBaseline, circular_distance
from .config import Settings
from .models import Anomaly, SecurityEvent
from .privacy import domain_hash


def _severity(score: int) -> str:
    return "high" if score >= 75 else "medium" if score >= 50 else "low"


def _score(z: float) -> int:
    return min(100, round(max(0, z - 2) * 25))


def detect(event: SecurityEvent, user: UserBaseline | None, peer: PeerBaseline | None, cfg: Settings) -> list[Anomaly]:
    if not user:
        return []  # Cold-start behavior is not anomalous; surface it separately in the UI.
    findings: list[Anomaly] = []

    if event.event_type.value == "login" and user.login_hour_median is not None and user.login_hour_mad:
        instant = event.occurred_at.astimezone(UTC)
        hour = instant.hour + instant.minute / 60
        distance = circular_distance(hour, user.login_hour_median)
        z = distance / user.login_hour_mad
        if z >= 3:
            score = _score(z)
            findings.append(Anomaly(signal="time_anomaly", score=score, severity=_severity(score), explanation="Login time is outside the user's established pattern.", evidence={"robust_z": round(z, 2), "distance_hours": round(distance, 2)}))

    if event.event_type.value in {"activity", "transfer"} and event.bytes_transferred:
        z = abs(event.bytes_transferred - user.daily_volume_median) / user.daily_volume_mad
        if z >= 3:
            score = _score(z)
            findings.append(Anomaly(signal="volume_anomaly", score=score, severity=_severity(score), explanation="Transfer volume is outside the user's established daily range.", evidence={"robust_z": round(z, 2), "bytes": event.bytes_transferred}))

    if event.domain:
        hashed = domain_hash(event.domain, cfg.domain_hash_key)
        if hashed not in user.known_domain_hashes:
            findings.append(Anomaly(signal="new_domain", score=35, severity="low", explanation="Destination has not appeared in this user's baseline window.", evidence={"new_for_user": True, "baseline_domains": len(user.known_domain_hashes)}))

    if peer and peer.cohort_size >= cfg.min_peer_cohort and event.bytes_transferred:
        z = abs(event.bytes_transferred - peer.daily_volume_median) / peer.daily_volume_mad
        if z >= 3:
            score = _score(z)
            findings.append(Anomaly(signal="peer_comparison", score=score, severity=_severity(score), explanation="Transfer volume is unusual relative to the department cohort.", evidence={"robust_z": round(z, 2), "cohort_size": peer.cohort_size}))
    return findings
