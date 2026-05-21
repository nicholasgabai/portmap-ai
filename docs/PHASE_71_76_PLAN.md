# Phase 71-76 Distributed Runtime Intelligence Plan

Milestone L defines the next implementation milestone for extending PortMap-AI from a cohesive single-node runtime into coordinated multi-node runtime intelligence. The focus is master/worker runtime state consistency, node summaries, topology merging across nodes, cluster health, distributed review aggregation, coordinated export bundles, and operator visibility across local trusted nodes.

This is a planning document only. It does not implement runtime behavior, start services, open network listeners, change host configuration, contact untrusted systems, perform automatic enforcement, or transmit data outside the operator-controlled local environment.

## Milestone L: Distributed Runtime Intelligence

Goal:
Extend PortMap-AI from a single cohesive runtime into coordinated multi-node runtime intelligence while preserving the local-first, operator-controlled, advisory-by-default posture.

Milestone L should connect existing node identity, runtime session, profile, recovery, health, topology, review, dashboard provider, and export bundle primitives into distributed summaries for trusted local master and worker nodes.

All work should remain:

- local-first
- trusted-node scoped
- operator-controlled
- advisory by default
- policy-aware
- source-attributed
- bounded and resource-conscious
- macOS/Linux development friendly
- Raspberry Pi/Linux compatible
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 71:

- Local event model, queue, and event bus.
- SQLite-backed local storage repositories.
- Runtime sessions, profiles, checkpoints, recovery, CLI, health, and service-readiness previews.
- Local node identity and coordination primitives.
- Local read-only API primitives.
- Persistent topology state and snapshot drift detection.
- Runtime pipeline workflow primitives.
- Persistent operator review records and history.
- Dashboard rendering and provider foundations.
- Operational export bundle helpers.
- Distributed visibility aggregation with source attribution.
- Dry-run service lifecycle template records.

Milestone L should build distributed views from already-provided trusted node summaries and operator-approved local runtime records. It should not add automatic discovery, cloud sync, active background probing, or remote command execution.

## Phase 71 - Distributed Node State Sync

Goal:
Create trusted-node runtime state synchronization models that normalize master and worker runtime summaries into consistent local cluster state records.

Build:

- `core_engine/runtime/distributed_state.py`
- `core_engine/runtime/node_sync.py`
- `tests/test_distributed_node_state.py`
- `docs/distributed_node_state_sync.md`

Features:

- Node runtime state records.
- Master and worker role summaries.
- Runtime session references per node.
- Runtime profile references per node.
- Last health summary references per node.
- Last checkpoint references per node.
- Capability and component summaries.
- Stale, missing, and conflicting node-state detection.
- Source references and node attribution.
- Local-only cluster state summaries.

Acceptance:

- Sanitized master and worker summaries normalize into deterministic cluster state records.
- Duplicate node summaries merge predictably with source attribution.
- Stale and conflicting records are reported, not hidden.
- Outputs include safety fields and do not store raw payload bytes.
- No node is contacted directly by this phase.

## Phase 72 - Federated Topology Aggregation

Goal:
Merge topology snapshots and visibility summaries across trusted local nodes into a federated topology model with source attribution and conflict reporting.

Build:

- `core_engine/topology/federated.py`
- `core_engine/topology/node_merge.py`
- `tests/test_federated_topology.py`
- `docs/federated_topology_aggregation.md`

Features:

- Multi-node topology snapshot ingestion.
- Asset, service, topology edge, and finding merge helpers.
- Source node IDs and source references on merged records.
- Confidence scoring across node reports.
- Conflict records for duplicate assets, label drift, service-name drift, and edge disagreement.
- Federated node and edge count summaries.
- Timeline and correlation-ready records.
- Dashboard provider-ready summaries.

Acceptance:

- Federated topology can be built from sanitized node snapshots.
- Duplicate and conflicting topology records are deterministic and reviewable.
- Source attribution survives every merge step.
- Outputs remain local-only and advisory.
- No active collection or topology probing is added.

## Phase 73 - Cluster Runtime Health

Goal:
Summarize runtime health across trusted master and worker nodes using already-provided local health summaries.

Build:

- `core_engine/runtime/cluster_health.py`
- `tests/test_cluster_runtime_health.py`
- `docs/cluster_runtime_health.md`

Features:

- Cluster health summary records.
- Per-node health rollups.
- Master/worker availability summaries.
- Scheduler, storage, event queue, review, export, service-readiness, and runtime session health rollups.
- Resource budget warnings for edge devices.
- Degraded, unavailable, and stale node classification.
- Health events suitable for local storage.
- Dashboard provider-ready health panels.

Acceptance:

- Cluster health summaries are deterministic and JSON serializable.
- Failed or malformed node health records are isolated and reported.
- Stale nodes are visible in summary counts.
- No active probing or external calls are added.
- Tests cover healthy, degraded, stale, and malformed node states.

## Phase 74 - Distributed Review Queue

Goal:
Aggregate advisory review records from trusted local nodes into a master-side operator review view while preserving node ownership and local review history.

Build:

- `core_engine/policy/distributed_review.py`
- `tests/test_distributed_review_queue.py`
- `docs/distributed_review_queue.md`

Features:

- Distributed review summary records.
- Per-node review counts by status, severity, and category.
- Review draft import from sanitized node summaries.
- Duplicate review detection.
- Source node ownership fields.
- Cross-node finding status summaries.
- Recommended operator review records for conflicts and repeated categories.
- Export-ready review aggregation.

Acceptance:

- Review summaries from multiple trusted nodes aggregate deterministically.
- Duplicate reviews are reported with source attribution.
- State changes remain local review-state changes only.
- No remote approval propagation, remediation, or command execution is added.
- Tests use sanitized review records only.

## Phase 75 - Coordinated Export Bundles

Goal:
Create coordinated export bundle plans that combine selected evidence from trusted local nodes while preserving source attribution and redaction requirements.

Build:

- `core_engine/export/coordinated_bundle.py`
- `core_engine/export/node_manifest.py`
- `tests/test_coordinated_export_bundle.py`
- `docs/coordinated_export_bundles.md`

Features:

- Multi-node export bundle manifest.
- Per-node evidence manifest records.
- Snapshot, topology, finding, review, runtime, and health record counts by node.
- Cross-node digest summaries.
- Redaction and placeholder validation across node manifests.
- Optional local archive plan under explicit operator-provided output path.
- Export conflict and missing-node records.
- Deterministic JSON ordering.

Acceptance:

- Coordinated export plans are deterministic for sanitized input.
- Export plans preserve node attribution and source references.
- Redaction requirements are enforced before public examples are emitted.
- No bundle is sent externally.
- Optional archive creation remains local and operator-triggered only.

## Phase 76 - Remote Operator Visibility Prep

Goal:
Prepare local trusted-node visibility models for future operator views without adding public exposure, cloud sync, or remote control behavior.

Build:

- `core_engine/runtime/operator_visibility.py`
- `gui/web/distributed_views.py`
- `tests/test_remote_operator_visibility.py`
- `docs/remote_operator_visibility_prep.md`

Features:

- Trusted-node visibility summary models.
- Cluster runtime status panels.
- Federated topology status panels.
- Distributed review status panels.
- Coordinated export status panels.
- Service-readiness status panels by node.
- API-compatible dictionaries for future local dashboard use.
- Empty-state and stale-node rendering models.
- Explicit remote-control disabled fields.

Acceptance:

- Operator visibility summaries build from sanitized distributed records.
- Empty and stale-node states render cleanly.
- Output is dashboard/API-ready without starting a web server.
- Remote control, public exposure, and cloud sync fields remain disabled.
- Existing Textual terminal dashboard is not replaced.

## Cross-Phase Data Flow

```text
trusted local node summaries
  -> distributed node state sync
  -> federated topology aggregation
  -> cluster runtime health
  -> distributed review aggregation
  -> coordinated export bundle plans
  -> local operator visibility models
```

No step should add untrusted discovery, background collection, remote command execution, router changes, service installation, public internet exposure, or external data transmission.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, environment files, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm new docs are included in package metadata when applicable.
- Confirm examples use sanitized placeholders only.
- Confirm node identifiers are placeholders and not real hostnames.
- Confirm source attribution is present on merged distributed records.
- Confirm no implementation contacts nodes directly unless a later phase explicitly adds an operator-approved transport.

## macOS Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Run the full test suite in the repo-local environment.
- Normalize one sanitized master summary and two sanitized worker summaries.
- Build a federated topology from sanitized node snapshots.
- Build cluster health from fixture health summaries.
- Aggregate review summaries from trusted-node fixtures.
- Generate a coordinated export plan to a temporary directory.
- Build operator visibility models without starting a web server.
- Confirm no external network calls are required.
- Confirm no real hostnames, usernames, local paths, logs, screenshots, archives, database files, cache files, or runtime artifacts are staged.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Run focused distributed runtime tests on the target device.
- Normalize a small master and worker node-state set.
- Build a small federated topology with low record counts.
- Build cluster health with Raspberry Pi resource thresholds.
- Aggregate a small distributed review queue.
- Generate a coordinated export plan without writing large archives.
- Build operator visibility summaries from small fixture inputs.
- Confirm CPU and memory use remain modest.
- Confirm no external network calls are required.
- Confirm no raw payload bytes are stored in public outputs.
- Confirm no private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/distributed_node_state_sync.md`
- `docs/federated_topology_aggregation.md`
- `docs/cluster_runtime_health.md`
- `docs/distributed_review_queue.md`
- `docs/coordinated_export_bundles.md`
- `docs/remote_operator_visibility_prep.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Hosted SaaS.
- Cloud billing.
- Public internet exposure.
- Untrusted node discovery.
- Automatic enforcement.
- Remote command execution.
- Router modification.
- Automatic service installation or startup.
- Heavy ML training.
- Third-party export delivery.
- Background collection without explicit operator opt-in.
- Replacement of the existing Textual terminal dashboard.
