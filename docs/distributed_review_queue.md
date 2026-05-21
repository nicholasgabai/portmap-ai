# Distributed Review Queue

Phase 74 adds trusted-node review aggregation for local master-side operator views. It consumes sanitized review drafts, review history, and finding status records that have already been produced by trusted local nodes.

This module does not contact nodes, propagate approvals, execute remediation, change review state on remote nodes, start services, open listeners, or transmit data outside the operator-controlled local environment.

## Inputs

Each node summary can include:

- `node_id`, `node_label`, and `role`.
- `source_refs` such as `node-review:node-worker-a`.
- `reviews`, `review_records`, `review_drafts`, or an existing review export payload.
- `review_history` transition records.
- `finding_statuses` produced by the persistent review store.

Review drafts are loaded through the existing review import/storage conversion helpers and remain `ReviewRecord`-compatible. Node attribution is added as summary metadata, not as a new persistence system.

## Output Records

`build_distributed_review_summary()` returns:

- `record_type: distributed_review_summary`
- per-node review summaries
- node-owned review draft records
- duplicate review conflict records
- repeated category records
- cross-node finding status summaries
- recommended local operator review records for conflicts
- export-ready review aggregation
- dashboard provider-ready panel data

Every output includes safety fields:

- `local_only: true`
- `trusted_node_scoped: true`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `remote_control_enabled: false`

## Duplicate And Repeated Category Handling

Duplicate detection reports:

- repeated `review_id` values across nodes
- repeated `source_ref` and `category` pairs across nodes

Repeated category detection reports categories that appear across multiple node review queues or meet the configured count threshold.

These records only recommend operator review. They do not resolve conflicts and do not change review state.

## Export-Ready Aggregation

The export-ready payload keeps source node attribution and embeds an existing `operator_review_records` export for compatibility with local export bundle workflows. It is deterministic and local-only.

## Dashboard Panel Shape

```json
{
  "panel": "distributed_review_queue",
  "status": "review_required",
  "metrics": {
    "node_count": 2,
    "review_count": 3,
    "duplicate_review_count": 1,
    "repeated_category_count": 1,
    "recommended_review_count": 2
  },
  "remote_state_changes_enabled": false
}
```

## Raspberry Pi Validation

Use sanitized records and temporary local test locations only.

- Aggregate one master and one worker review summary.
- Import review drafts from a sanitized node review export.
- Verify per-node counts by status, severity, and category.
- Verify duplicate review and repeated category records are deterministic.
- Verify cross-node finding status summaries preserve source node IDs.
- Verify export-ready aggregation is JSON serializable.
- Confirm no approvals, dismissals, remediations, or remote commands are propagated.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest with small fixture inputs.
- Confirm no raw payload bytes, private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.
