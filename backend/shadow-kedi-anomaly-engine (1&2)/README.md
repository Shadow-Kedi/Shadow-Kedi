# Shadow Kedi behavior baseline and anomaly engine

This service builds privacy-conscious behavioral baselines and evaluates four signals:

- unusual login time;
- anomalous transfer volume;
- a previously unseen destination domain; and
- activity unusual for a sufficiently large department cohort.

It is intended to sit behind the Wazuh/OpenSearch ingestion layer. Wazuh events should be normalized by an adapter before they reach this service; the dashboard reads the result from this service or its database, never from Wazuh directly.

## Privacy and security design

The API accepts a stable **pseudonymous** `user_id`; do not send names, emails, file names, URLs, message content, or full IP addresses. Domains are normalized and HMAC-SHA-256 hashed before being stored. Raw events are used only for the requested computation and are not persisted by this implementation. Baselines retain aggregates, bounded domain-hash sets, department labels, and timestamps only.

Set a strong, secret `DOMAIN_HASH_KEY` outside source control. Keep the user-to-identity mapping in your identity provider, apply least-privilege service credentials, TLS, encryption at rest, audit logging, and a documented retention/deletion policy. Department comparisons are suppressed for cohorts smaller than `MIN_PEER_COHORT` (default 5).

## Run

```bash
cp .env.example .env
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.api:app --reload
pytest
```

For production, set `DATABASE_URL` to PostgreSQL, run schema migrations through your normal deployment process, and invoke `app.tasks.recompute_baselines` nightly via Celery Beat (or your platform scheduler). SQLite is supplied only for local development.

## API flow

1. `POST /baselines/recompute` with normalized events from a trailing 30-day OpenSearch query.
2. On each newly normalized event, call `POST /anomalies/evaluate`.
3. Send the returned signal names/scores to the risk orchestrator; it owns final risk-score and recommendation policy.

OpenAPI is available at `/docs` while running.

## Platform & integrations (new)

The repository now includes the capstone's simulated platform layer:

- `docker-compose.yml` starts PostgreSQL, Redis, the API, and Celery worker. The simulator and frontend placeholder are opt-in profiles.
- `fixtures/raw_simulator_events.jsonl` is safe source telemetry; `scripts/normalize_events.py` converts it into the versioned canonical contract.
- `fixtures/canonical_events.jsonl` can be replayed into `POST /v1/events` by `scripts/replay_events.py`.
- `fixtures/application_catalogue.json` provides a starter app/AI catalogue to grow to 15-25 tools.
- Intake validates UTC timestamps, tenant header/payload agreement, event IDs, and rejects prohibited content/secret metadata keys. Replayed IDs return `duplicate` rather than creating a second record.

### Start the local stack

```bash
cp .env.example .env
# Set a non-default INGEST_API_KEY and DOMAIN_HASH_KEY in .env.
docker compose --profile simulator --profile frontend up --build
```

The demo API is at `http://localhost:8000/docs`; the frontend profile serves a deliberately minimal placeholder at `http://localhost:8080`. The frontend must be replaced by the React dashboard team and may only call the backend API.

### Normalize then replay fixture telemetry

```bash
python scripts/normalize_events.py fixtures/raw_simulator_events.jsonl /tmp/canonical.jsonl --tenant-id demo-acme
API_URL=http://localhost:8000 INGEST_API_KEY=your-key python scripts/replay_events.py /tmp/canonical.jsonl
```

The compose simulator profile replays `fixtures/canonical_events.jsonl` automatically. Run it a second time to confirm idempotency.

## Example event

```json
{
  "user_id": "idp-subject-opaque-42",
  "department": "finance",
  "occurred_at": "2026-08-10T23:30:00Z",
  "event_type": "transfer",
  "bytes_transferred": 540000000,
  "domain": "example-storage.invalid"
}
```
