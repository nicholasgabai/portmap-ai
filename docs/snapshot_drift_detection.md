# Snapshot Diff and Drift Detection

Phase 60 adds read-only comparison helpers for Phase 59 topology snapshots. The module compares baseline and current snapshots and reports asset, service, topology, and finding drift as structured local records.

The implementation is local-first and advisory. It does not run scans, collect new evidence, modify configuration, execute remediation, contact external systems, or transmit data.

## Modules

- `core_engine.topology.diff`
- `core_engine.topology.drift`

## What It Detects

Snapshot comparison can report:

- asset additions and removals
- asset label/category changes
- low-confidence asset matches
- service additions and removals
- service label changes
- topology edge additions and removals
- topology edge observation-count changes
- finding additions and removals
- repeated finding categories
- finding severity increases

## Basic Use

```python
from core_engine.topology.diff import compare_topology_snapshots

report = compare_topology_snapshots(
    baseline_snapshot,
    current_snapshot,
    generated_at="2026-01-03T00:00:00+00:00",
)
```

The report includes:

```json
{
  "status": "ok",
  "drift_count": 3,
  "event_ready": true,
  "storage_ready": true,
  "policy_review_ready": true,
  "timeline_ready": true,
  "correlation_ready": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Integration Records

Use `core_engine.topology.drift` builders to produce platform-ready records:

- `build_drift_event()`
- `build_drift_storage_record()`
- `build_drift_policy_records()`
- `build_drift_timeline_entries()`
- `build_drift_correlation_records()`

These records are suitable for later event bus, storage, policy review, timeline, and correlation wiring.

## Service Drift

When explicit service lists are available, service comparisons use asset/target and port keys. When a topology snapshot only contains graph nodes, the comparator can still detect service-count changes from node summaries.

## Invalid Inputs

Malformed topology snapshots return structured invalid reports with error details instead of raising unhandled exceptions.

## Safety Properties

Every report and generated record keeps these fields:

```json
{
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Phase 60 remains analysis-only. It does not trigger actions, install services, execute plugins, or send export bundles externally.
