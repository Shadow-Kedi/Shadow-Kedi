# Deployment boundary and data minimization

```
Devices / SaaS audit APIs / proxy DNS logs
                 │
          Wazuh + OpenSearch
                 │  (read-only, least-privilege service account)
       normalizer / scheduled export
                 │  pseudonymous events only
    Shadow Kedi anomaly API + worker ─── PostgreSQL baseline aggregates
                 │
        risk orchestrator / recommendation API
                 │
              React dashboard
```

## What belongs where

The device, Wazuh, SaaS-audit and network integrations belong in the **backend ingestion boundary**. They collect endpoint process/application inventory, authentication events, sanctioned SaaS audit logs, proxy/DNS destinations, and transfer-size metadata. Normalize those feeds into `SecurityEvent`; do not let a browser connect to Wazuh/OpenSearch or vendor APIs.

The React frontend should only show authorised alert summaries, explanations, and remediation actions from an authenticated backend API. It must not receive raw telemetry, unhashed domains, full URLs, file names, or identity mappings.

## Integration checklist

- Give the worker a read-only OpenSearch role restricted to the required Wazuh indices and date range.
- Use each SaaS provider's audited server-to-server API with narrowly scoped OAuth permissions; do not collect message/document contents for this detector.
- Collect endpoint application inventory as publisher/product/version and a device pseudonym. Compare it against an approved-app catalogue in the backend.
- Collect DNS/proxy telemetry as registrable domain and byte count. Do not retain request paths, query strings, or packet content.
- Tokenize identity at the ingest boundary. Keep the reversible employee lookup in a separate IAM-controlled system.
- Have a documented purpose, retention limit, access review, and employee/works-council approval process appropriate to the organisation and jurisdiction.

## Limits of this component

This engine detects behavioral deviations; it does not determine whether a product is approved. Pair it with an approved-software/SaaS catalogue so a new or unmanaged application can be labeled as a Shadow IT finding. The risk orchestrator should combine that policy result with these behavioral signals, rather than treating any single anomaly as proof of misconduct.
