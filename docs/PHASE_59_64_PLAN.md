# Phase 59-64 Runtime Topology Integration Plan

Milestone J defines the next implementation milestone for turning PortMap-AI from modular local subsystems into a cohesive operational platform. The focus is persistent topology state, historical visibility comparison, runtime workflow wiring, operator review flow, dashboard-backed visibility, and import/export of operational evidence.

This is a planning document only. It does not implement runtime behavior, start services, execute remediation, contact external systems, install components, or transmit data outside the local operator environment.

## Milestone J: Runtime Pipeline and Persistent Topology Integration

Milestone J should connect the already implemented platform primitives into explicit, operator-controlled workflows:

- Persistent topology state.
- Historical snapshot comparison.
- Runtime event and storage pipeline wiring.
- Operator review queue persistence.
- Dashboard data providers backed by local APIs and storage.
- Operational evidence import/export bundles.

All work should remain:

- local-first
- operator-controlled
- advisory by default
- policy-aware
- bounded and resource-conscious
- Raspberry Pi/Linux compatible
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 59:

- Event model, local event bus, and queue primitives.
- SQLite storage repositories for events, snapshots, assets, services, topology edges, and findings.
- Runtime scheduler primitives.
- Node identity and local coordination primitives.
- Local read-only API primitives.
- Static dashboard rendering foundation.
- Topology graph and timeline view models.
- Policy review engine and review queue.
- Distributed visibility aggregation.
- Behavior correlation baselines.
- Schema validation, stream metadata, plugin registry, relay orchestration, and service template records.

Milestone J should wire these into coherent workflows without bypassing safety boundaries.

## Phase 59 — Persistent Topology State

Goal:
Build persistent topology storage, topology snapshot records, import/export helpers, and topology history summaries.

Build:

- `core_engine/topology/state.py`
- `core_engine/topology/snapshots.py`
- `core_engine/topology/import_export.py`
- `tests/test_topology_state.py`
- `docs/persistent_topology_state.md`

Features:

- Persistent topology snapshot records.
- Topology state summaries for assets, services, edges, and findings.
- Snapshot IDs and generated timestamps.
- Source references and confidence fields.
- Import helpers for sanitized topology records.
- Export helpers for local topology snapshots.
- History summaries across stored snapshots.
- Storage-ready payloads with explicit safety fields.

Acceptance:

- Topology snapshots can be created from existing assets, services, and edges.
- Snapshots can be serialized and loaded from sanitized local records.
- Topology history summaries are deterministic.
- Output includes `raw_payload_stored: false`, `automatic_changes: false`, and `administrator_controlled: true`.
- Tests use temporary paths and sanitized fixtures only.

## Phase 60 — Snapshot Diff and Drift Detection

Goal:
Compare baseline/current snapshots and report asset, service, topology, and finding drift in structured outputs.

Build:

- `core_engine/topology/diff.py`
- `core_engine/topology/drift.py`
- `tests/test_snapshot_drift.py`
- `docs/snapshot_drift_detection.md`

Features:

- Baseline/current snapshot comparison.
- Asset added, removed, and changed summaries.
- Service added, removed, and label-change summaries.
- Topology edge added and removed summaries.
- Finding category and severity drift summaries.
- Operator-readable explanations.
- Severity and confidence scoring.
- Advisory finding generation.

Acceptance:

- Snapshot diffs are deterministic.
- Drift findings include evidence references and source references.
- Results remain advisory and local-only.
- No scans, collection, enforcement, or external transport is added.

## Phase 61 — Runtime Pipeline Wiring

Goal:
Connect visibility, events, storage, policy review, topology, and correlation modules into a single explicit operator workflow.

Build:

- `core_engine/runtime/pipeline.py`
- `core_engine/runtime/workflows.py`
- `tests/test_runtime_pipeline.py`
- `docs/runtime_pipeline.md`

Features:

- Operator-triggered workflow runner.
- Event creation from visibility, topology, drift, and diagnostic records.
- Optional local storage writes through repositories.
- Policy review draft creation from advisory findings.
- Correlation input generation from stored or provided records.
- Structured workflow result summaries.
- Dry-run mode by default.
- Explicit write mode for local storage only.

Acceptance:

- A sanitized workflow input can produce events, findings, review drafts, and summaries.
- Dry-run mode performs no storage writes.
- Explicit local write mode stores only selected local records.
- Failed steps are isolated and reported.
- No automatic remediation, plugin execution, service installation, or external transmission is added.

## Phase 62 — Operator Review Queue Integration

Goal:
Persist review drafts, approval states, finding status, and review history.

Build:

- `core_engine/policy/review_store.py`
- `core_engine/policy/history.py`
- `tests/test_review_queue_integration.py`
- `docs/operator_review_queue_integration.md`

Features:

- Persistent review draft records.
- Review state history.
- Finding status tracking.
- Reviewed-by and review-note metadata.
- Local audit-ready transition records.
- Filters by status, severity, category, and source reference.
- JSON import/export for review records.

Acceptance:

- Review records can be stored and listed locally.
- State transitions preserve history.
- Invalid transitions are rejected safely.
- Approval remains a state change only.
- No action execution is triggered by review state changes.

## Phase 63 — Dashboard Data Provider Integration

Goal:
Connect dashboard models to local API/storage/runtime state instead of static sample data.

Build:

- `gui/web/providers.py`
- `gui/web/views.py`
- `tests/test_dashboard_providers.py`
- `docs/dashboard_data_providers.md`

Features:

- Provider interface for API-compatible dictionaries.
- Storage-backed provider helpers.
- Runtime state provider helpers.
- Topology and snapshot summary providers.
- Review queue summary providers.
- Diagnostic summary providers.
- Empty-state handling.
- Sanitized rendering examples.

Acceptance:

- Dashboard models can be built from local provider data.
- Empty-state rendering remains clean.
- Providers do not require external network access.
- Provider output contains no raw payload bytes.
- Existing Textual TUI behavior is not replaced.

## Phase 64 — Operational Export Bundle

Goal:
Create export bundles for snapshots, findings, topology, review records, and runtime summaries.

Build:

- `core_engine/export/bundle.py`
- `core_engine/export/redaction.py`
- `tests/test_operational_export_bundle.py`
- `docs/operational_export_bundle.md`

Features:

- Local export bundle manifest.
- Snapshot export.
- Topology export.
- Finding export.
- Review record export.
- Runtime summary export.
- Redaction and placeholder validation.
- Bundle integrity digest.
- JSON output with deterministic ordering.
- Optional archive creation under explicit operator-provided output path.

Acceptance:

- Export bundles are deterministic for sanitized input.
- Redaction removes private identifiers from exported public examples.
- Bundle manifests include generated timestamp, record counts, and digest.
- No export is sent externally.
- Tests use temporary directories only.

## Cross-Phase Data Flow

```text
local visibility and diagnostic records
  -> persistent topology snapshots
  -> baseline/current snapshot diff
  -> drift findings and advisory summaries
  -> runtime pipeline workflow
  -> event and storage records
  -> policy review queue
  -> local API providers
  -> dashboard panels
  -> operator-controlled export bundle
```

No step should add automatic enforcement, router changes, service installation, public internet exposure, or external data transmission.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local paths only.

- Run full tests in the repo-local environment.
- Create a small topology snapshot from sanitized records.
- Compare two sanitized snapshots for deterministic drift output.
- Run the runtime pipeline in dry-run mode.
- Persist review records to a temporary local database.
- Build dashboard provider output from sanitized local records.
- Generate an operational export bundle in a temporary directory.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest.
- Confirm no raw payload bytes are stored in public outputs.
- Confirm no real IPs, MACs, hostnames, usernames, tokens, logs, screenshots, local paths, database files, cache files, or runtime artifacts are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/persistent_topology_state.md`
- `docs/snapshot_drift_detection.md`
- `docs/runtime_pipeline.md`
- `docs/operator_review_queue_integration.md`
- `docs/dashboard_data_providers.md`
- `docs/operational_export_bundle.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Hosted SaaS.
- Cloud billing.
- Public internet exposure.
- Automatic enforcement.
- Router modification.
- Automatic plugin execution.
- Automatic service installation.
- Heavy ML training.
- Third-party export delivery.
- Background collection without explicit operator opt-in.
