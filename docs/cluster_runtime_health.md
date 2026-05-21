# Cluster Runtime Health

Phase 73 adds local cluster health summaries for trusted master and worker node records. It rolls up already-provided node runtime health summaries, distributed node state, service-readiness previews, and resource budget warnings into deterministic records for CLI, dashboard provider, event storage, and export workflows.

This module does not contact nodes, open listeners, run probes, start services, install components, change host configuration, approve reviews, or transmit data externally.

## Inputs

Cluster health accepts sanitized trusted-node summaries that follow the distributed node state shape:

- `node_id` and `role`.
- `last_seen_at` and lifecycle or sync status.
- runtime session summary.
- runtime profile summary.
- runtime health summary.
- checkpoint summary.
- source references such as `node-health:node-worker-a`.

Inputs can also be previously normalized distributed node state records. Malformed node records are isolated into `malformed` rollups instead of crashing the cluster summary.

## Output Records

`build_cluster_runtime_health()` returns a JSON-serializable record with:

- `record_type: cluster_runtime_health`
- deterministic `cluster_health_id`
- per-node health rollups
- master and worker availability summaries
- component rollups for scheduler, storage, event queue, review queue, export readiness, service readiness, and runtime sessions
- resource budget warning summaries
- a local event record using the existing `runtime_health` event type with `metadata.health_scope: cluster`
- a dashboard provider-ready panel dictionary

Every public record includes:

- `local_only: true`
- `trusted_node_scoped: true`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `remote_control_enabled: false`

## Node Classifications

Cluster health classifies nodes as:

- `healthy` when sync state is current and runtime health has no degraded or high-severity checks.
- `degraded` when runtime health reports degraded checks, high or critical severity, or conflicting sync state.
- `stale` when the node state is older than the operator-provided staleness threshold.
- `unavailable` when an expected node is missing or a node explicitly reports missing health.
- `malformed` when a submitted node health record cannot be normalized.

Classifications are advisory. They do not trigger remediation or remote command execution.

## Dashboard Panel Shape

Dashboard-ready output is a dictionary, not a web server:

```json
{
  "panel": "cluster_runtime_health",
  "status": "degraded",
  "metrics": {
    "node_count": 2,
    "healthy_node_count": 1,
    "degraded_node_count": 1,
    "stale_node_count": 0,
    "unavailable_node_count": 0,
    "resource_warning_count": 1
  },
  "recommended_review": true,
  "remote_control_enabled": false
}
```

## Resource Budgets

The default resource budgets reuse the local runtime health monitor thresholds. Raspberry Pi mode uses the lower edge-device thresholds for event queue depth, storage record counts, and pending review counts.

Resource warnings are review signals only. They are intended to help operators decide whether to inspect queue depth, storage growth, review backlog, or degraded local subsystems.

## Raspberry Pi Validation

Use sanitized fixture records and temporary local paths only.

- Build a cluster health summary from one master and one worker record.
- Verify stale worker classification with a short staleness threshold.
- Verify missing expected-node classification.
- Verify malformed input is isolated as a malformed rollup.
- Verify edge-device resource thresholds generate advisory warnings.
- Confirm the health event can be inserted into local event storage.
- Confirm dashboard panel output is JSON serializable.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest with small fixture inputs.
- Confirm no raw payload bytes, private identifiers, logs, screenshots, database files, cache files, environment files, archives, or runtime artifacts are staged.
