# Milestone J Integration

Milestone J covers Phases 59-64: Runtime Pipeline and Persistent Topology Integration. It turns the Phase 44-58 platform primitives into an explicit local operations path for topology state, drift comparison, runtime workflow wiring, review persistence, dashboard-backed visibility, and operational evidence export.

This milestone remains local-first, operator-controlled, advisory by default, and read-only unless an operator explicitly enables local writes. It does not start services, execute remediation, install components, modify routers, contact external systems, or transmit data.

## Completed Phases

| Phase | Area | Implemented Baseline |
| --- | --- | --- |
| 59 | Persistent topology state | Topology snapshots, storage-ready records, local import/export helpers, and history summaries. |
| 60 | Snapshot drift detection | Baseline/current topology comparison for asset, service, topology, and finding drift. |
| 61 | Runtime pipeline | Explicit dry-run workflow wiring across visibility, events, topology, drift, policy review, correlation, and optional local storage writes. |
| 62 | Review persistence | Persistent review drafts, review state history, finding status tracking, transition records, filters, and JSON import/export. |
| 63 | Dashboard providers | Local API-compatible, storage-backed, runtime-backed, topology, review, and diagnostic dashboard provider helpers. |
| 64 | Operational export bundle | Deterministic local export bundles for snapshots, topology, findings, reviews, runtime summaries, diagnostics, redaction, and archive output. |

## Module Map

| Layer | Modules | Role |
| --- | --- | --- |
| Topology State | `core_engine.topology.snapshots`, `core_engine.topology.state`, `core_engine.topology.import_export` | Build persistent topology snapshots and summarize topology history. |
| Drift Detection | `core_engine.topology.diff`, `core_engine.topology.drift` | Compare topology snapshots and emit event, storage, policy, timeline, and correlation-ready drift records. |
| Runtime Pipeline | `core_engine.runtime.pipeline`, `core_engine.runtime.workflows` | Coordinate explicit operator workflows with dry-run defaults and isolated step results. |
| Review Persistence | `core_engine.policy.review_store`, `core_engine.policy.history` | Persist advisory review records and state transitions through existing storage repositories. |
| Dashboard Providers | `gui.web.providers`, `gui.web.views` | Build dashboard models from API-compatible dictionaries, storage repositories, runtime state, topology summaries, reviews, and diagnostics. |
| Export Bundle | `core_engine.export.bundle`, `core_engine.export.redaction` | Build deterministic local evidence bundles, redact local identifiers, validate placeholders, and optionally write local archives. |

## Integrated Data Flow

```text
operator-provided visibility and diagnostic evidence
  -> topology snapshot builders
  -> persistent local topology state
  -> baseline/current snapshot drift detection
  -> runtime pipeline workflow
  -> event, finding, timeline, and correlation-ready records
  -> policy review draft generation
  -> persistent review store and finding status history
  -> dashboard provider summaries
  -> operational export bundle
```

The flow is explicit and local. Automatic collection, automatic enforcement, router modification, public exposure, hosted services, and external delivery are outside this milestone.

## How The Pieces Connect

Persistent topology state is the durable representation of asset, service, topology edge, and finding evidence. Phase 59 builds topology snapshots from existing records and stores them through the existing local snapshot repository.

Snapshot drift detection compares a baseline snapshot with a current snapshot. Phase 60 produces structured drift records, advisory findings, timeline entries, policy-ready records, and correlation-ready records without running scans or collecting new evidence.

The runtime pipeline coordinates the local workflow. Phase 61 accepts already-collected records, builds visibility summaries and snapshots, compares drift when baseline/current snapshots are provided, creates local events, prepares policy reviews, and optionally writes selected records to the existing local repository. Dry-run mode remains the default.

Review persistence stores advisory review records and state transitions through the existing findings repository. Phase 62 records approval, defer, dismiss, and resolve transitions as state changes only. No review state executes an action.

Dashboard providers expose local status models for operator views. Phase 63 reads from API-compatible dictionaries, storage, runtime state, topology summaries, review stores, and diagnostic summaries. It does not replace the Textual TUI.

Operational export bundles package local evidence for operator-controlled review. Phase 64 exports snapshots, topology, findings, reviews, runtime summaries, and diagnostics with deterministic JSON ordering, integrity digests, redaction, and optional local archive creation.

## Raspberry Pi Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Run the full Python test suite in the repo-local environment.
- Create a topology snapshot from sanitized asset, service, edge, and finding records.
- Persist the snapshot to a temporary SQLite database.
- Compare sanitized baseline and current topology snapshots.
- Run the runtime pipeline in dry-run mode and confirm no storage writes occur.
- Run the runtime pipeline with explicit local write mode against a temporary database.
- Create review drafts and persist review state transitions.
- Track a sample finding status through the persistent review store.
- Build dashboard provider output from the temporary database.
- Render a dashboard view from provider-backed data.
- Build an operational export bundle from the temporary database.
- Write a JSON export bundle to a temporary output path.
- Write an optional ZIP archive to a temporary output path.
- Confirm export outputs include `raw_payload_stored: false`.
- Confirm export outputs include `automatic_changes: false`.
- Confirm export outputs include `administrator_controlled: true`.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest.
- Confirm no logs, screenshots, database files, archives, environment files, cache folders, runtime data, or private validation notes are staged.

## Current Boundaries

Milestone J does not add:

- hosted SaaS
- cloud billing
- public internet exposure
- automatic enforcement
- router or firewall changes
- automatic plugin execution
- automatic service installation
- background collection without explicit operator opt-in
- third-party export delivery

## Next Direction

Recommended next milestone: Operational UX and Runtime Hardening.

Suggested areas:

- CLI commands for running the Phase 61 runtime workflow.
- CLI commands for generating Phase 64 operational export bundles.
- Storage-backed local API startup documentation.
- Dashboard preview generation from stored local evidence.
- Review queue operator commands for listing and updating review state.
- Raspberry Pi validation notes kept private unless fully scrubbed.
