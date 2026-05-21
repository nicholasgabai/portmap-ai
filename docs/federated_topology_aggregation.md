# Federated Topology Aggregation

Phase 72 adds local federated topology aggregation for trusted node snapshots. It merges already-provided topology snapshots and visibility summaries across nodes while preserving source-node attribution, confidence, conflict records, and dashboard/timeline/correlation-ready summaries.

This phase does not collect data, contact nodes, open network listeners, change configuration, execute remediation, or write a parallel persistence system.

## Scope

The federated topology helpers support:

- Multi-node topology snapshot ingestion.
- Asset, service, topology edge, and finding merge helpers.
- Source node IDs and source references on merged records.
- Confidence scoring across node reports.
- Conflict records for duplicate assets, label drift, service-name drift, and edge disagreement.
- Federated asset, service, edge, finding, graph node, and graph edge summaries.
- Timeline-ready records.
- Correlation-ready records.
- Dashboard provider-ready summaries.

## Modules

- `core_engine/topology/federated.py`
- `core_engine/topology/node_merge.py`

Primary helpers:

- `build_federated_topology()`
- `normalize_node_topology_snapshots()`
- `summarize_federated_topology()`
- `merge_federated_assets()`
- `merge_federated_services()`
- `merge_federated_topology_edges()`
- `merge_federated_findings()`
- `build_federated_timeline_entries()`
- `build_federated_correlation_records()`
- `build_federated_dashboard_summary()`

## Sanitized Example

```python
from core_engine.topology import build_federated_topology

federated = build_federated_topology(
    [
        {
            "node_id": "node-master",
            "snapshot": {
                "snapshot_id": "snapshot-master",
                "observed_at": "2026-01-01T00:00:00+00:00",
                "assets": [{"asset_id": "asset-sample", "label": "Sample Asset"}],
                "services": [{"asset_id": "asset-sample", "port": 443, "service_name": "https"}],
                "topology_edges": [
                    {
                        "source_asset": "asset-sample",
                        "target_asset": "asset-peer",
                        "relationship_type": "connects_to"
                    }
                ],
                "findings": []
            }
        }
    ],
    generated_at="2026-01-01T00:05:00+00:00",
)
```

Example output shape:

```json
{
  "record_type": "federated_topology",
  "source_node_ids": ["node-master"],
  "summary": {
    "source_node_count": 1,
    "asset_count": 1,
    "service_count": 1,
    "topology_edge_count": 1,
    "conflict_count": 0
  },
  "dashboard_summary": {
    "panel": "federated_topology",
    "status": "ok"
  },
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Conflict Reporting

Conflicts are explicit records and are not hidden. Phase 72 reports:

- Duplicate asset reports.
- Asset label drift.
- Duplicate service reports.
- Service-name drift.
- Duplicate topology edge reports.
- Edge protocol or service-label disagreement.
- Duplicate finding records.

Merged records keep:

- `source_node_ids`
- `source_refs`
- `first_seen_at`
- `last_seen_at`
- `confidence`

## Downstream Records

Federated topology output includes:

- `timeline_entries` for operator-readable chronology.
- `correlation_records` for later advisory correlation.
- `dashboard_summary` for local dashboard providers.
- `topology` graph output compatible with existing topology rendering helpers.

## Safety Fields

All public records include:

```json
{
  "local_only": true,
  "read_only": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Raspberry Pi Validation

Use sanitized fixtures and temporary local test locations only:

- Normalize two small node topology snapshots.
- Merge assets, services, edges, and findings with source attribution.
- Confirm conflicts are reported for duplicate assets and label drift.
- Confirm service-name drift and edge disagreement are reported.
- Confirm dashboard, timeline, and correlation records are generated.
- Confirm no node is contacted directly.
- Confirm no real hostnames, usernames, local paths, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.
