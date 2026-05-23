# Coordinated Export Bundles

Phase 75 adds coordinated export bundle planning for trusted local nodes. It combines per-node evidence manifests into a deterministic multi-node export manifest while preserving node attribution, redaction status, record counts, and digest summaries.

This phase does not contact nodes, send bundles externally, approve reviews, execute remediation, start services, or write archives by default.

## Inputs

Each trusted-node payload can include:

- `node_id`, `node_label`, `role`, and `source_refs`
- topology snapshots
- topology assets, services, edges, and conflicts
- findings
- review records or distributed review summaries
- runtime summaries
- health summaries

The implementation reuses the existing export redaction and placeholder validation helpers. It does not introduce a new persistence system.

## Node Evidence Manifests

`build_node_evidence_manifest()` creates a local manifest with:

- per-node record counts for snapshots, topology, findings, reviews, runtime, and health
- section digests
- a node manifest digest
- placeholder validation status
- redaction status
- source node attribution

All public records include:

- `local_only: true`
- `trusted_node_scoped: true`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `remote_control_enabled: false`

## Coordinated Bundle Plan

`build_coordinated_export_bundle_plan()` returns:

- `record_type: coordinated_export_bundle_plan`
- multi-node bundle manifest
- node evidence manifests
- cross-node digest summary
- record counts by node and total
- placeholder validation by node
- export conflict records
- missing-node records
- optional archive plan

The optional archive plan records only the intended archive name and digest reference. It does not store the operator path in public output and does not write the archive.

## Conflict Records

Coordinated export planning reports:

- duplicate node manifests
- malformed node manifests
- missing expected nodes
- placeholder validation failures

Conflict records are advisory and require operator review. They do not block local inspection and do not trigger external delivery.

## Deterministic JSON

Use `export_coordinated_bundle_plan_json()` for deterministic JSON output. Keys are sorted and generated examples should use fixed timestamps.

## Raspberry Pi Validation

Use sanitized records and temporary local paths only.

- Build two small node evidence manifests.
- Build a coordinated export plan from one master and one worker payload.
- Verify snapshot, topology, finding, review, runtime, and health counts by node.
- Verify missing-node records for expected nodes without evidence.
- Verify malformed node payloads are isolated.
- Verify private identifiers are redacted before placeholder validation.
- Verify the optional archive plan does not write archives or store local paths.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest with small fixture inputs.
- Confirm no raw payload bytes, private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.
