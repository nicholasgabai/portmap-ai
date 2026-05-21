# Distributed Node State Sync

Phase 71 adds local distributed node state synchronization models for trusted PortMap-AI master and worker summaries. The implementation normalizes already-provided node, runtime session, profile, health, checkpoint, capability, and component records into deterministic cluster state summaries.

This phase does not contact nodes, open listeners, start services, run remote commands, change host configuration, or write a parallel persistence system.

## Scope

The Phase 71 helpers support:

- Node runtime state records.
- Master and worker role summaries.
- Runtime session references per node.
- Runtime profile references per node.
- Runtime health references per node.
- Runtime checkpoint references per node.
- Capability and component summaries.
- Stale, missing, duplicate, and conflicting node-state detection.
- Source references and node attribution.
- Deterministic cluster runtime state summaries.

## Modules

- `core_engine/runtime/distributed_state.py`
- `core_engine/runtime/node_sync.py`

Primary helpers:

- `normalize_node_runtime_state()`
- `normalize_node_runtime_states()`
- `build_cluster_runtime_state()`
- `merge_node_runtime_states()`
- `detect_missing_node_states()`
- `detect_stale_node_states()`
- `summarize_cluster_runtime_state()`
- `classify_node_sync_status()`

## Sanitized Example

```python
from core_engine.runtime import build_cluster_runtime_state

cluster = build_cluster_runtime_state(
    [
        {
            "node_id": "node-master",
            "node_label": "master-node",
            "role": "master",
            "lifecycle_state": "online",
            "last_seen_at": "2026-01-01T00:05:00+00:00",
            "source_refs": ["node-report:node-master"],
            "capabilities": {
                "platform": "linux",
                "architecture": "arm64",
                "supported_features": ["runtime", "health"]
            }
        }
    ],
    expected_nodes=["node-master", "node-worker"],
    generated_at="2026-01-01T00:06:00+00:00",
    stale_after_seconds=300,
)
```

Example output shape:

```json
{
  "record_type": "distributed_cluster_runtime_state",
  "summary": {
    "node_count": 1,
    "current_node_count": 1,
    "missing_node_count": 1,
    "administrator_review_required": true
  },
  "conflicts": [
    {
      "conflict_type": "missing_node",
      "affected_ref": "node:node-worker",
      "recommended_review": true
    }
  ],
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Conflict Reporting

Conflicts are explicit records and are not hidden. Phase 71 reports:

- Duplicate node state records.
- Conflicting node roles.
- Conflicting node labels.
- Conflicting runtime profile references.
- Conflicting runtime health statuses.
- Missing expected trusted nodes.
- Stale trusted nodes.

Each conflict includes:

- `conflict_id`
- `conflict_type`
- `affected_ref`
- `source_node_ids`
- `source_refs`
- `summary`
- `severity`
- `recommended_review`

## Safety Fields

Distributed node state records include explicit safety fields:

```json
{
  "local_only": true,
  "trusted_node_scoped": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true,
  "remote_control_enabled": false
}
```

## Raspberry Pi Validation

Use sanitized fixtures and temporary local test locations only:

- Normalize one sanitized master summary and one sanitized worker summary.
- Build a cluster state summary from small fixture records.
- Confirm stale and missing node records are reported.
- Confirm duplicate node summaries produce conflict records.
- Confirm source attribution remains attached to merged records.
- Confirm no node is contacted directly.
- Confirm no real hostnames, usernames, local paths, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.
