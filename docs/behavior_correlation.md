# Behavior Correlation Baseline

Phase 53 adds local baseline correlation helpers for comparing already-provided PortMap-AI records over time. The correlation layer can compare events, snapshots, visibility reports, and distributed visibility aggregation output to produce operator-readable advisory findings about local infrastructure visibility changes.

This phase is analysis-only. It does not collect new data, contact nodes, transmit data, modify routers, change configuration, or execute response actions.

## Baseline Windows

A baseline window summarizes a bounded set of local telemetry records:

- `baseline_id`
- `label`
- `start_time`
- `end_time`
- `event_count`
- `asset_count`
- `service_count`
- `topology_edge_count`
- `finding_count`
- `metadata`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

Builders are available for:

- `build_baseline_from_events()`
- `build_baseline_from_snapshots()`
- `build_baseline_from_visibility_reports()`
- `build_baseline_from_aggregated_reports()`

Sanitized example:

```python
from core_engine.correlation import (
    build_baseline_from_visibility_reports,
    compare_baselines,
)

baseline = build_baseline_from_visibility_reports([
    {
        "report_id": "visibility-report-before",
        "assets": [{"asset_id": "asset-sample-a", "label": "Sample Asset A"}],
        "services": [{"asset_id": "asset-sample-a", "port": 8443, "service": "HTTPS"}],
        "topology_edges": [],
        "findings": [],
    }
])

current = build_baseline_from_visibility_reports([
    {
        "report_id": "visibility-report-current",
        "assets": [{"asset_id": "asset-sample-b", "label": "Sample Asset B"}],
        "services": [{"asset_id": "asset-sample-b", "port": 9443, "service": "HTTPS"}],
        "topology_edges": [],
        "findings": [],
    }
])

result = compare_baselines(baseline, current)
```

## Delta Categories

The comparison helpers produce advisory findings for:

- `new_asset_observed`
- `asset_missing_from_current_window`
- `new_service_observed`
- `service_missing_from_current_window`
- `service_label_changed`
- `topology_relationship_added`
- `topology_relationship_removed`
- `repeated_finding_category`
- `severity_increase_observed`
- `low_confidence_identity_match`

Each advisory finding includes:

- `finding_id`
- `finding_type`
- `severity`
- `score`
- `title`
- `summary`
- `evidence_refs`
- `recommended_review`
- `source_refs`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

## Scoring

Scoring helpers are intentionally simple and local:

- `score_delta_finding()`
- `assign_advisory_severity()`
- `summarize_delta_scores()`

Scores help operators sort review work. They do not trigger automatic action.

## Safety Boundaries

- Local-only and operator-controlled.
- Compares already-provided records only.
- No node contact.
- No active collection.
- No external network transport.
- No cloud sync.
- No router or firewall modification.
- No automatic enforcement.
- No write endpoints.
- No raw payload storage.

Use placeholders in public examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
