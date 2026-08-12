from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from math import sqrt
from statistics import median
from .models import SecurityEvent
from .privacy import domain_hash


def _mad_scale(values: list[float]) -> float:
    if len(values) < 2:
        return 1.0
    centre = median(values)
    # 1.4826 makes MAD comparable to standard deviation for normal data.
    return max(1.4826 * median([abs(v - centre) for v in values]), 1.0)


def circular_distance(hour: float, centre: float) -> float:
    return abs((hour - centre + 12) % 24 - 12)


@dataclass(frozen=True)
class UserBaseline:
    user_id: str
    department: str
    login_hour_median: float | None
    login_hour_mad: float | None
    daily_volume_median: float
    daily_volume_mad: float
    known_domain_hashes: frozenset[str]
    sample_days: int
    computed_at: datetime


@dataclass(frozen=True)
class PeerBaseline:
    department: str
    daily_volume_median: float
    daily_volume_mad: float
    cohort_size: int
    computed_at: datetime


def build_baselines(events: list[SecurityEvent], secret: str) -> tuple[dict[str, UserBaseline], dict[str, PeerBaseline]]:
    """Build robust rolling baselines without retaining raw events."""
    per_user_days: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    login_hours: dict[str, list[float]] = defaultdict(list)
    domains: dict[str, set[str]] = defaultdict(set)
    department_by_user: dict[str, str] = {}

    for event in events:
        department_by_user[event.user_id] = event.department
        day = event.occurred_at.astimezone(UTC).date().isoformat()
        per_user_days[event.user_id][day] += event.bytes_transferred
        if event.event_type.value == "login":
            instant = event.occurred_at.astimezone(UTC)
            login_hours[event.user_id].append(instant.hour + instant.minute / 60)
        if event.domain:
            domains[event.user_id].add(domain_hash(event.domain, secret))

    now = datetime.now(UTC)
    users: dict[str, UserBaseline] = {}
    for user_id, department in department_by_user.items():
        hours = login_hours[user_id]
        # Median hour works except around midnight; use the hour minimizing circular distance.
        login_centre = min(hours, key=lambda candidate: sum(circular_distance(x, candidate) for x in hours)) if hours else None
        distances = [circular_distance(x, login_centre) for x in hours] if login_centre is not None else []
        volumes = list(per_user_days[user_id].values()) or [0]
        users[user_id] = UserBaseline(
            user_id=user_id, department=department,
            login_hour_median=login_centre,
            login_hour_mad=_mad_scale(distances) if distances else None,
            daily_volume_median=median(volumes), daily_volume_mad=_mad_scale(volumes),
            known_domain_hashes=frozenset(domains[user_id]), sample_days=len(per_user_days[user_id]), computed_at=now,
        )

    department_volumes: dict[str, list[float]] = defaultdict(list)
    for baseline in users.values():
        department_volumes[baseline.department].append(baseline.daily_volume_median)
    peers = {
        department: PeerBaseline(department, median(values), _mad_scale(values), len(values), now)
        for department, values in department_volumes.items()
    }
    return users, peers
