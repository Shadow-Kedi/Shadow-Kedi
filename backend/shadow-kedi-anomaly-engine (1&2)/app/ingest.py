from sqlalchemy.orm import Session
from .database import CanonicalEventRow
from .platform_models import CanonicalEvent, IngestResult


def ingest_event(session: Session, event: CanonicalEvent) -> IngestResult:
    """Idempotent event intake. Database primary key enforces replay safety."""
    if session.get(CanonicalEventRow, event.event_id):
        return IngestResult(event_id=event.event_id, status="duplicate")
    session.add(CanonicalEventRow(
        event_id=event.event_id, tenant_id=event.tenant_id, user_id=event.user_id,
        device_id=event.device_id, occurred_at=event.occurred_at, source=event.source,
        event_type=event.event_type, schema_version=event.schema_version, metadata_json=event.metadata,
    ))
    session.commit()
    return IngestResult(event_id=event.event_id, status="accepted")
