# Resource-Aware Historical Retention

Phase 115 adds metadata-only retention planning for historical snapshots, replay windows, topology history, and behavioral baseline records. The helpers build deterministic local summaries that explain when retention should be reduced for constrained storage or memory budgets.

The retention layer is advisory and dry-run safe. It does not delete files, move records, start services, modify firewall rules, capture packets, store payload bytes, store credentials, or call external services.

## Records

`core_engine.history.retention_policies` provides retention policy records for:

- default local runtime retention
- edge-device retention
- Raspberry Pi retention

Policy records include category limits for snapshots, replay events, topology relationships, and behavioral baseline records. They also include storage and memory thresholds used by the resource retention planner.

`core_engine.history.resource_retention` provides:

- storage budget summaries
- memory budget summaries
- adaptive retention window summaries
- retention recommendation records
- export-safe retention summaries
- dashboard/API-ready dictionaries

All records include explicit safety fields such as `metadata_only`, `dry_run_safe`, `deletion_preview_only`, `automatic_deletion: false`, and `delete_performed: false`.

## Resource Behavior

The planner compares local resource summaries against the active retention policy.

- Supported budgets keep the configured retention windows.
- Unknown budgets use conservative recommendations.
- Low storage or memory budgets reduce future retention windows.
- Raspberry Pi and edge-device profiles use smaller default retention windows.
- Malformed resource summaries are isolated as unavailable and require operator review.

The output is a preview. Operators can use it to decide how to rotate or trim local metadata stores, but Phase 115 performs no destructive action.

## Example

```python
from core_engine.history import build_resource_aware_retention_report

report = build_resource_aware_retention_report(
    snapshots=[],
    storage_summary={"free_mb": 2048, "total_mb": 8192},
    memory_summary={"free_mb": 512, "total_mb": 2048},
    generated_at="2026-05-01T00:00:00+00:00",
)
```

The returned report contains `summary`, `recommendations`, `dashboard_status`, `api_status`, and `export_summary` dictionaries.

## Raspberry Pi Notes

Use the Raspberry Pi retention profile for edge devices with constrained storage or memory. It reduces snapshot, replay, topology, and baseline windows while preserving metadata-only historical review.

Validation on Raspberry Pi should use sanitized fixtures and temporary local paths only:

- Build the Raspberry Pi retention policy.
- Generate storage and memory budget summaries.
- Build adaptive retention windows.
- Confirm no deletion or file movement is performed.
- Confirm dashboard/API dictionaries serialize deterministically.

## Safety

Phase 115 public documentation and tests use sanitized placeholders only. Do not publish real hostnames, usernames, IP addresses, MAC addresses, packet payloads, raw DNS content, runtime logs, screenshots, database files, cache files, or private validation notes.
