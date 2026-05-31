# Historical Snapshot Persistence

Phase 111 adds metadata-only historical snapshot persistence for behavioral intelligence summaries. The snapshot layer lets PortMap-AI retain rolling operator summaries over time without storing packet payloads, credentials, raw logs, private runtime artifacts, or browsing history verbatim.

This feature is local-first, advisory-only, bounded by retention controls, and dry-run safe by default. It does not start collectors, call external services, modify firewall rules, install services, or perform enforcement.

## Snapshot Records

Historical snapshots are built from behavioral intelligence operator summaries and retain only compact metadata:

- Snapshot identifier and generated timestamp.
- Source label and source references.
- Component states and component record counts.
- Recommendation and explanation counts.
- Export-safe digest summaries.
- Privacy and safety fields.
- Dashboard/API-safe status dictionaries.

Snapshot identifiers are digest-based and retention-safe. Public examples must use placeholders such as `<snapshot-id>`, `<source-ref>`, and `<export-digest>`.

## Snapshot Store

The bounded snapshot store keeps the newest snapshot records up to an explicit limit. Rotation reports retained and dropped snapshot IDs but does not delete files automatically.

Write helpers are explicit and intended for operator-provided paths or temporary test directories. Dry-run write plans can be generated without touching the filesystem.

## Safety Fields

Historical snapshot outputs include explicit safety fields:

- `metadata_only: true`
- `bounded_retention: true`
- `dry_run_safe: true`
- `advisory_only: true`
- `raw_payload_stored: false`
- `packet_payloads_stored: false`
- `credentials_stored: false`
- `raw_logs_stored: false`
- `raw_browsing_history_stored: false`
- `external_services_used: false`
- `automatic_enforcement: false`
- `firewall_changes: false`

Malformed snapshot input is reported as a structured `malformed_historical_snapshot` record. The malformed handler stores only a digest of the supplied record and does not persist raw input.

## Validation

Use sanitized fixtures and temporary directories only:

- Build a snapshot from a behavioral intelligence summary.
- Serialize and deserialize the snapshot deterministically.
- Rotate a bounded snapshot set.
- Create a dry-run write plan.
- Write and read a snapshot only under a temporary directory.
- Confirm export summaries omit full payload data.
- Confirm no raw payloads, credentials, logs, screenshots, private paths, real IP addresses, hostnames, usernames, MAC addresses, databases, cache files, runtime artifacts, or private validation notes are staged.
