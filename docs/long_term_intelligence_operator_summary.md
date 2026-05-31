# Long-Term Intelligence Operator Summary

Phase 116 adds a unified operator-facing summary for historical intelligence. It combines metadata-only historical snapshots, baseline aging and decay, topology evolution, replay windows, and resource-aware retention into dashboard/API/export-safe records.

The summary is advisory-only. It does not delete files, change retention stores, start services, modify firewall rules, capture packets, store payload bytes, store credentials, store raw browsing history, or call external services.

## Inputs

The summary can consume existing local records from:

- historical snapshot persistence
- bounded snapshot store summaries
- baseline aging and decay
- long-term topology evolution
- historical replay windows
- resource-aware historical retention
- behavioral intelligence summaries
- runtime health summaries

All inputs are optional. Missing inputs are reported as unavailable rather than hidden.

## Output Records

`core_engine.history.intelligence_summary` builds:

- unified long-term intelligence summary records
- historical snapshot rollups
- baseline aging and decay rollups
- topology evolution rollups
- replay window rollups
- retention and resource rollups
- supported, degraded, and unavailable state summaries
- operator recommendation records
- privacy and safety summaries
- export-ready dictionaries
- dashboard/API-safe dictionaries

`core_engine.history.operator_views` provides dashboard, API, export, and privacy/safety view helpers for the same summary model.

## States

The combined state is deterministic:

- `supported` means all provided components are available and no review hints are present.
- `degraded` means at least one component has stale, drifted, malformed, truncated, or low-resource metadata.
- `unavailable` means no usable historical intelligence inputs were provided.

Recommendations remain manual review hints. They do not perform enforcement, deletion, service changes, firewall changes, or external lookups.

## Example

```python
from core_engine.history import build_long_term_intelligence_summary

summary = build_long_term_intelligence_summary(
    historical_snapshots=[],
    generated_at="2026-05-15T00:00:00+00:00",
)
```

The returned record includes `component_rollups`, `state_summary`, `recommendations`, `privacy_safety_summary`, `dashboard_status`, `api_status`, and `export_summary`.

## Safety

Phase 116 remains:

- metadata-only
- local-first
- bounded by retention controls
- advisory-only
- dry-run safe
- dashboard/API safe
- export ready

Public examples must use sanitized placeholders only. Do not publish real hostnames, usernames, IP addresses, MAC addresses, DNS histories, packet payloads, raw logs, screenshots, database files, cache files, runtime outputs, or private validation notes.
