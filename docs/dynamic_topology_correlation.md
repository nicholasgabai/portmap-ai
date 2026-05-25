# Dynamic Topology Correlation

Phase 91 connects metadata-only telemetry records into bounded live topology summaries. It uses packet ingestion, flow reconstruction, protocol metadata, topology graph helpers, drift comparison, and federation-aware source attribution to produce dashboard/API-ready dictionaries for operator review.

This phase does not capture packets, retain payload bytes, inject traffic, block traffic, change router state, start listeners, or create a new topology persistence system.

## Modules

- `core_engine.telemetry.topology_correlation` converts reconstructed flow records into topology edge records, infers node relationships and roles, correlates drift against an optional baseline graph, and emits replay-safe topology update records.
- `core_engine.telemetry.live_topology` builds the high-level live topology record with graph, protocol, drift, temporal, health, cluster/federation, dashboard, and local API summaries.

The implementation reuses existing flow topology edges and `core_engine.topology.graph` normalization. Output records keep the same safety posture used by telemetry modules:

- `raw_payload_stored: false`
- `payload_bytes_stored: 0`
- `traffic_injected: false`
- `automatic_blocking: false`
- `administrator_controlled: true`
- `local_only: true`

## Workflow

```text
bounded packet metadata window
  -> bidirectional flow records
  -> safe protocol metadata records
  -> live relationship inference
  -> topology graph normalization
  -> drift, temporal, health, and replay-safe update summaries
  -> dashboard/API-ready live topology dictionaries
```

## Record Types

- `flow_topology_edge_correlation`
- `live_node_relationship_inference`
- `live_node_role_inference`
- `protocol_aware_topology_summary`
- `live_topology_drift_correlation`
- `temporal_live_topology_summary`
- `replay_safe_topology_update`
- `live_topology_health_summary`
- `cluster_federation_live_topology_summary`
- `live_topology_dashboard`
- `live_topology_api`
- `live_topology`

## Boundaries

Graph growth is controlled by `max_nodes` and `max_edges`. When limits are exceeded, the live topology record reports truncated counts and operator-readable warnings rather than growing unbounded state.

Replay protection is digest-based. A topology update record classifies an update as `accepted` or `duplicate` based on the deterministic graph digest and caller-provided previous digests.

Drift correlation is advisory only. A changed live topology produces review-oriented summaries and warnings; it never executes enforcement or blocking behavior.

## Sanitized Example

```python
from core_engine.telemetry import build_live_topology

record = build_live_topology(
    flows=sanitized_flow_records,
    protocol_records=sanitized_protocol_records,
    baseline_graph=sanitized_baseline_graph,
    cluster_node_id="node-alpha",
    federation_scope="trusted-local",
    generated_at="2026-01-01T00:00:00+00:00",
)

dashboard = record["dashboard_status"]
api_response = record["api_status"]
```

The example uses placeholder node labels and documentation IP ranges only. It does not require live capture or external network access.

## Validation Checklist

- Run `python -m pytest`.
- Run `git diff --check`.
- Confirm live topology records contain no raw payload bytes.
- Confirm graph growth limits produce warnings and bounded output.
- Confirm replay-safe update digests classify duplicate updates.
- Confirm drift summaries remain advisory and local-only.
- Confirm `docs/real_device_validation.md`, logs, screenshots, archives, database files, and runtime artifacts are not staged.
