# Historical Replay Windows

Phase 114 adds replay-safe historical review windows for bounded offline operator review. Replay windows reconstruct metadata timelines from historical snapshots and optional component summaries without rerunning collectors, storing packet payloads, storing credentials, or replaying traffic.

This feature is local-first, advisory-only, dry-run safe, and bounded by explicit event limits. It does not call external services, modify firewall rules, install services, inject traffic, decrypt content, or perform enforcement.

## Replay Windows

Replay window records define:

- Window label.
- Start and end timestamps.
- Maximum event count.
- Replay cursor metadata.
- Bounded retention flags.
- Privacy and safety fields.

If no explicit window is provided, PortMap-AI can infer one from sanitized historical snapshot timestamps.

## Timeline Reconstruction

Historical replay builds timeline events from:

- Metadata-only historical snapshots.
- Behavioral component rollups.
- Temporal anomaly summaries.
- Long-term topology evolution summaries.
- Baseline aging and decay summaries.
- Service fingerprint summaries.
- DNS and destination behavior summaries.
- Adaptive risk summaries.

Malformed snapshots are isolated as structured records with `raw_record_stored: false`.

## Operator Outputs

Phase 114 emits dashboard/API/export-safe records:

- `historical_replay_window`
- `historical_snapshot_sequence_summary`
- `historical_timeline_event`
- `anomaly_replay_summary`
- `topology_replay_summary`
- `component_replay_summary`
- `offline_replay_review_helper`
- `historical_replay_dashboard`
- `historical_replay_api`
- `historical_replay_export_summary`

Export summaries include counts, event IDs, and digests. They do not include raw snapshot payloads, packet payloads, credentials, raw browsing history, logs, screenshots, private paths, or runtime artifacts.

## Validation

Use sanitized fixtures and deterministic timestamps:

- Replay ordered snapshots.
- Replay empty and missing snapshot sets.
- Isolate malformed snapshots.
- Bound replay event counts.
- Reconstruct anomaly and topology timeline summaries.
- Summarize baseline, service fingerprint, DNS/destination, and adaptive risk replay inputs.
- Confirm deterministic serialization.
- Confirm public docs contain no real IP addresses, domains, usernames, hostnames, MAC addresses, credentials, logs, screenshots, databases, cache files, runtime outputs, private paths, or private validation notes.
