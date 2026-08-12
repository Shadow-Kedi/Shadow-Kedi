from sqlalchemy.orm import Session
from .baselines import PeerBaseline, UserBaseline
from .database import PeerBaselineRow, UserBaselineRow


def save_baselines(session: Session, users: dict[str, UserBaseline], peers: dict[str, PeerBaseline]) -> None:
    for baseline in users.values():
        row = session.get(UserBaselineRow, baseline.user_id) or UserBaselineRow(user_id=baseline.user_id)
        row.department, row.login_hour_median, row.login_hour_mad = baseline.department, baseline.login_hour_median, baseline.login_hour_mad
        row.daily_volume_median, row.daily_volume_mad = baseline.daily_volume_median, baseline.daily_volume_mad
        row.known_domain_hashes, row.sample_days, row.computed_at = list(baseline.known_domain_hashes), baseline.sample_days, baseline.computed_at
        session.add(row)
    for baseline in peers.values():
        row = session.get(PeerBaselineRow, baseline.department) or PeerBaselineRow(department=baseline.department)
        row.daily_volume_median, row.daily_volume_mad = baseline.daily_volume_median, baseline.daily_volume_mad
        row.cohort_size, row.computed_at = baseline.cohort_size, baseline.computed_at
        session.add(row)
    session.commit()


def get_user_baseline(session: Session, user_id: str) -> UserBaseline | None:
    row = session.get(UserBaselineRow, user_id)
    if not row:
        return None
    return UserBaseline(row.user_id, row.department, row.login_hour_median, row.login_hour_mad, row.daily_volume_median, row.daily_volume_mad, frozenset(row.known_domain_hashes), row.sample_days, row.computed_at)


def get_peer_baseline(session: Session, department: str) -> PeerBaseline | None:
    row = session.get(PeerBaselineRow, department)
    return PeerBaseline(row.department, row.daily_volume_median, row.daily_volume_mad, row.cohort_size, row.computed_at) if row else None
