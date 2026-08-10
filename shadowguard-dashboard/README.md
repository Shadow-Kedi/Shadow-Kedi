# ShadowGuard AI analyst dashboard

Mock-first React + TypeScript dashboard for reviewed Shadow IT triage. It calls only the configured REST API; it does not connect to Wazuh or OpenSearch.

## Run

1. Install Node 20+ and run `npm install`.
2. Copy `.env.example` to `.env` and set `VITE_USE_MOCKS=false` when the API is available.
3. Run `npm run dev`.

The API adapter expects `GET /overview`, `GET /alerts`, `GET /alerts/:id`, `GET /users/:id`, `GET /applications`, and `POST /exports`. All API responses are validated at the UI boundary before rendering.

### Safety choices

- Export is a server-side request only; the browser does not construct or cache an export.
- Evidence labels distinguish observed contributors from recommendations. No automatic enforcement is exposed.
- Viewer is read-only; analyst-only review actions are disabled and explained.
