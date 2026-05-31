# Long-Term Topology Evolution

Phase 113 adds metadata-only long-term topology evolution tracking for PortMap-AI. The history layer summarizes recurring node relationships, stable and transient communication paths, dormant relationship returns, and topology drift over time.

This feature is local-first, advisory-only, dry-run safe, and bounded by retention controls. It does not store packet payloads, credentials, raw logs, private runtime artifacts, or full traffic captures. It does not call external services, modify firewall rules, inject traffic, or perform enforcement.

## Inputs

Topology evolution records reuse existing local summaries:

- Dynamic topology correlation output.
- Live topology records.
- Historical snapshot metadata context.
- Baseline aging and decay summaries.
- Behavioral intelligence summaries.

Public examples should use placeholders such as `node-alpha`, `node-bravo`, `<snapshot-id>`, and `<topology-digest>`.

## Relationship History

Relationship history records track metadata for each observed path:

- Source asset and target asset placeholders.
- Relationship type and protocol label.
- First-seen and last-seen timestamps.
- Observation and recurrence counts.
- Source references and node attribution.
- Stable, transient, dormant, and dormant-return flags.
- Topology maturity score.
- Relationship confidence score.

Malformed topology input is isolated into structured records with `raw_record_stored: false`.

## Evolution Outputs

Phase 113 provides dashboard/API/export-safe records:

- `long_term_topology_relationship`
- `relationship_history_summary`
- `long_term_topology_drift_summary`
- `recurring_communication_path_summary`
- `topology_maturity_summary`
- `topology_evolution_dashboard`
- `topology_evolution_api`
- `topology_evolution_export_summary`

Export summaries include record counts, status, and digests, not raw topology payloads.

## Validation

Use sanitized fixtures and deterministic timestamps:

- Track stable recurring relationships.
- Classify transient relationships.
- Detect added and removed topology relationships.
- Detect dormant relationship returns.
- Score relationship confidence and topology maturity.
- Bound relationship retention.
- Handle malformed topology input safely.
- Confirm no real IP addresses, domains, hostnames, usernames, MAC addresses, credentials, logs, screenshots, databases, cache files, runtime outputs, private paths, or private validation notes are staged.
