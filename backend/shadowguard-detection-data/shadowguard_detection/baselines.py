from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from statistics import median
from .catalogue import ApplicationCatalogue
from .models import CanonicalEvent
from .privacy import hmac_domain


def circular_distance(hour: float, centre: float) -> float:
    return abs((hour - centre + 12) % 24 - 12)


def robust_scale(values: list[float]) -> float:
    if len(values) < 2:
        return 1.0
    centre = median(values)
    return max(1.4826 * median([abs(value - centre) for value in values]), 1.0)


@dataclass(frozen=True)
class UserBaseline:
    user_id: str
    department: str | None
    login_hour_centre: float | None
    login_hour_scale: float | None
    login_samples: int
    daily_bytes_median: float
    daily_bytes_scale: float
    sample_days: int
    known_domain_hashes: frozenset[str]
    known_app_names: frozenset[str]


@dataclass(frozen=True)
class PeerBaseline:
    department: str
    daily_bytes_median: float
    daily_bytes_scale: float
    cohort_size: int


def build_baselines(events: list[CanonicalEvent], catalogue: ApplicationCatalogue, domain_hash_key: str, window_days: int = 7) -> tuple[dict[str, UserBaseline], dict[str, PeerBaseline]]:
    if not events:
        return {}, {}
    latest = max(event.occurred_at for event in events)
    cutoff = latest - timedelta(days=window_days)
    event_window = [event for event in events if event.occurred_at >= cutoff]
    day_bytes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    login_hours: dict[str, list[float]] = defaultdict(list)
    domains: dict[str, set[str]] = defaultdict(set)
    apps: dict[str, set[str]] = defaultdict(set)
    departments: dict[str, str | None] = {}
    for event in event_window:
        departments[event.user_id] = event.metadata.get("department")
        day_bytes[event.user_id][event.occurred_at.astimezone(UTC).date().isoformat()] += int(event.metadata.get("bytes_transferred", 0))
        if event.event_type == "login":
            instant = event.occurred_at.astimezone(UTC)
            login_hours[event.user_id].append(instant.hour + instant.minute / 60)
        domain = event.metadata.get("domain")
        if isinstance(domain, str):
            domains[event.user_id].add(hmac_domain(domain, domain_hash_key))
            app = catalogue.find(domain=domain)
            if app:
                apps[event.user_id].add(app.name)
        publisher = event.metadata.get("publisher")
        if isinstance(publisher, str):
            app = catalogue.find(publisher=publisher)
            if app:
                apps[event.user_id].add(app.name)

    users: dict[str, UserBaseline] = {}
    for user_id in departments:
        hours = login_hours[user_id]
        centre = min(hours, key=lambda candidate: sum(circular_distance(hour, candidate) for hour in hours)) if hours else None
        distances = [circular_distance(hour, centre) for hour in hours] if centre is not None else []
        volumes = list(day_bytes[user_id].values()) or [0]
        users[user_id] = UserBaseline(user_id, departments[user_id], centre, robust_scale(distances) if distances else None, len(hours), median(volumes), robust_scale(volumes), len(day_bytes[user_id]), frozenset(domains[user_id]), frozenset(apps[user_id]))

    by_department: dict[str, list[float]] = defaultdict(list)
    for baseline in users.values():
        if baseline.department:
            by_department[baseline.department].append(baseline.daily_bytes_median)
    peers = {department: PeerBaseline(department, median(volumes), robust_scale(volumes), len(volumes)) for department, volumes in by_department.items()}
    return users, peers
