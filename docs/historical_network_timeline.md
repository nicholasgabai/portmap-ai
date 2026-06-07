# Historical Network Timeline

Phase 142 adds visualization-ready historical timeline models for PortMap-AI. Timeline records convert bounded flow, topology, service, asset, drift, policy, remediation-preview, incident-candidate, and runtime-health records into replay-safe visual event windows.

This phase is model-only. It does not write timeline databases, start a GUI, start a browser UI, inspect packet payloads, store raw packets, retain raw DNS history, execute remediation, modify firewall/process/service state, or export private identifiers.

## Timeline Event Model

`core_engine.visualization.timeline_models` defines `TimelineEvent` records with:

- `event_id`
- `event_type`
- `event_category`
- `timestamp`
- `source_reference`
- `target_reference`
- `summary`
- `severity_level`
- `confidence_score`
- related flow, topology, asset, and policy references
- `source_mode`
- `preview_only`
- `destructive_action`
- advisory notes

All events are export-safe, preview-only, destructive-action false, metadata-only, replay-safe, and bounded. References are sanitized before export so raw hostnames, IP addresses, usernames, MAC addresses, private paths, credentials, certs, keys, raw DNS history, and packet payloads do not appear.

## Event Types

Phase 142 supports:

- `node_seen`
- `node_missing`
- `flow_started`
- `flow_changed`
- `service_seen`
- `service_changed`
- `topology_edge_seen`
- `topology_edge_changed`
- `asset_classified`
- `drift_detected`
- `policy_matched`
- `remediation_recommended`
- `guardrail_blocked`
- `runtime_degraded`
- `unknown`

Categories include topology, flow, service, asset, drift, policy, remediation, guardrail, runtime, and unknown.

## Timeline Window Model

`TimelineWindow` records include:

- `timeline_window_id`
- `start_timestamp`
- `end_timestamp`
- `event_count`
- `category_counts`
- `severity_counts`
- `events`
- `bounded`
- `max_events`
- `export_safe`

Windows deduplicate repeated events, sort them chronologically, and apply a `max_events` bound before serialization. Empty inputs produce safe empty timeline windows rather than failures.

## Builder Inputs

`core_engine.visualization.timeline_builder` can build timeline events from:

- Phase 141 topology graphs
- flow summaries
- asset classifications
- drift records
- policy evaluations
- remediation recommendations
- incident candidates
- runtime health summaries

Malformed collection inputs raise structured timeline errors. Malformed individual rows are ignored when they are not dictionaries.

## Replay Safety

Timeline windows are summaries for visual review. They do not replay collectors, re-run scans, store raw runtime artifacts, write databases, or perform response actions. They preserve `source_mode` so live, fixture, simulated, replay, and unknown records remain distinguishable in future dashboard/API/export views.

## Future UI Path

Phase 142 prepares the data contract for a future historical timeline UI or replay view. A later UI can render event windows, filter by category or severity, and align events with topology graphs without changing host/network state.

## Validation

Use sanitized fixtures only:

- Run `python -m pytest tests/test_historical_network_timeline.py`.
- Run the full test suite before committing.
- Run `git diff --check`.
- Run a sensitive-data scan.
- Confirm `docs/real_device_validation.md`, local test files, logs, artifacts, screenshots, caches, runtime outputs, and databases remain unstaged.
