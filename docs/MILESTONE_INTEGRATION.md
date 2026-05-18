# Milestone Integration

This document is the consolidated integration guide for the completed Phase 44-58 milestone work. It replaces the phase-specific planning docs as the primary implementation map. Archived planning files remain under `docs/archive/` for historical reference.

This is documentation planning only. It does not add runtime behavior, start services, execute plugins automatically, open relay listeners, install service units, transmit data externally, or modify host configuration.

The integration posture remains local-first, operator-controlled, read-only by default, bounded, auditable, and suitable for lightweight Linux and Raspberry Pi deployments.

## Completed Milestones

| Milestone | Phases | Focus | Current State |
| --- | --- | --- | --- |
| Local Intelligence Platform | 44-46 | Event model, local storage, scheduler primitives | Complete baseline |
| Coordinated Node Platform | 47-48 | Node identity, capabilities, local read-only API | Complete baseline |
| Operator Dashboard | 49-50 | Static dashboard foundation, topology and timeline models | Complete baseline |
| Policy and Correlation Engine | 51-53 | Policy review, distributed aggregation, baseline correlation | Complete baseline |
| Advanced Diagnostics and Deployment Readiness | 54-58 | Schema validation, stream metadata, plugin governance, relay orchestration, service templates | Complete baseline |

## Module Map

| Area | Modules | Role |
| --- | --- | --- |
| Events | `core_engine.events` | Normalize local telemetry into event objects, queue events in memory, and publish through a local event bus. |
| Storage | `core_engine.storage` | Store events, snapshots, assets, services, topology edges, and findings in local SQLite databases. |
| Runtime | `core_engine.runtime` | Provide lightweight scheduler primitives and runtime state counters without always-on wiring. |
| Nodes | `core_engine.nodes` | Manage stable node identity, capabilities, heartbeat metadata, lifecycle state, and summaries. |
| API | `core_engine.api` | Provide local read-only API primitives for health, events, assets, snapshots, nodes, and topology. |
| Dashboard | `gui.web` | Render lightweight local HTML dashboard models from API-compatible dictionaries. |
| Topology and Timeline | `core_engine.topology` | Build topology graph models and timeline summaries from stored or in-memory records. |
| Policy | `core_engine.policy` | Convert findings, events, and deltas into local advisory review records. |
| Aggregation | `core_engine.aggregation` | Merge authorized local node reports while preserving source attribution and reported conflicts. |
| Correlation | `core_engine.correlation` | Compare baseline windows and emit advisory drift findings. |
| Schema Diagnostics | `core_engine.diagnostics.schema_validation`, `core_engine.diagnostics.fixture_mutation` | Validate structured inputs and generate deterministic bounded fixture variants. |
| Stream Metadata | `core_engine.streams.metadata_parser`, `core_engine.streams.patterns` | Parse fixtures and explicit local byte streams into metadata-only records. |
| Plugin Governance | `core_engine.plugins` | Validate plugin manifests, register allowlisted utilities, and produce dry-run-first execution records. |
| Relay Orchestration | `core_engine.diagnostics.relay_simulator` | Simulate bounded local relay sessions and produce session metadata records. |
| Service Templates | `core_engine.installers.service_templates` | Generate dry-run Linux and Windows service lifecycle template text for operator review. |

## Consolidated Data Flow

Target record flow:

```text
operator-provided evidence and definitions
  -> validation, parsing, plugin, relay, and template modules
  -> normalized event and finding records
  -> local storage repositories
  -> topology and timeline views
  -> policy review queue
  -> baseline correlation and aggregation summaries
  -> local read-only API
  -> dashboard status panels
```

Distributed local target flow:

```text
authorized node summaries
  -> node report normalization
  -> aggregation merger
  -> conflict records and source attribution
  -> baseline correlation
  -> policy review queue
  -> local read-only API
  -> operator dashboard panels
```

Advanced diagnostics target flow:

```text
sanitized fixtures and operator definitions
  -> schema validation
  -> stream metadata parsing
  -> plugin manifest and execution records
  -> relay orchestration metadata
  -> service lifecycle template records
  -> event, storage, policy, timeline, topology, correlation, dashboard layers
```

No step in this plan adds cloud sync, public internet exposure, automatic enforcement, router modification, service installation, or background collection.

## Events Into Storage

Planned connection:

1. Local modules produce event-shaped dictionaries or normalized event objects.
2. Events are published through the local event bus only when an explicit caller does so.
3. A future operator-enabled flush job reads from the in-memory queue.
4. The flush job writes serialized events to the local storage repositories.
5. Stored payloads keep safety fields intact:
   - `raw_payload_stored: false`
   - `automatic_changes: false`
   - `administrator_controlled: true`

Important boundary: scheduler primitives exist, but they are not wired into always-on event flushing yet.

## Snapshots To Topology And Timeline

Planned connection:

1. Stored visibility snapshots are read from the storage layer.
2. Snapshot assets, services, and topology edges feed `core_engine.topology.graph`.
3. Snapshot events and baseline deltas feed `core_engine.topology.timeline`.
4. Graph output provides local relationship summaries.
5. Timeline output groups changes into operator-readable entries.

The topology and timeline modules remain read-only. They do not trigger scans, collection, policy changes, or response actions.

## Diagnostics To Platform Layers

Phase 54-58 modules already expose structured records for platform integration:

- Schema validation can emit event, finding, timeline, and correlation records.
- Stream parsing can emit event, finding, storage, topology, timeline, and correlation records.
- Plugin governance can emit manifest and execution records for events, storage, policy, timeline, and correlation.
- Relay orchestration can emit event, finding, storage, topology, dashboard, timeline, and correlation records.
- Service lifecycle templates can emit event, finding, storage, dashboard, timeline, and correlation records.

Target connection:

1. Operator-triggered diagnostics produce local result objects.
2. Result builders convert them into platform records.
3. Storage adapters persist summaries rather than raw payload bytes.
4. Policy evaluators create advisory review records for non-successful classifications.
5. Dashboard and API layers display status counts and summaries.

## Policy Review Path

Advisory findings can originate from:

- Visibility summaries.
- Baseline comparisons.
- Aggregation conflicts.
- Correlation findings.
- Schema validation issues.
- Stream parser malformed or limited input records.
- Plugin execution failures or timeouts.
- Relay orchestration timeouts or bound limits.
- Service-template validation issues.

Target connection:

1. Result builders produce finding records.
2. `core_engine.policy.evaluator` maps findings to enabled policies.
3. Matching records are added to `core_engine.policy.review_queue`.
4. Operators move review records through safe states:
   - `open`
   - `approved`
   - `deferred`
   - `dismissed`
   - `resolved`

Approval is only a review-state transition. It does not execute plugins, install services, start services, alter routers, contact external systems, or change PortMap-AI configuration.

## Aggregation Into Correlation

Planned connection:

1. Authorized node summaries are provided to the local coordinator as already-collected records.
2. Aggregation validates and normalizes node reports.
3. Assets, services, topology edges, and findings are merged with source attribution.
4. Conflicts are explicit records rather than hidden.
5. Merged records feed behavior-correlation baseline builders.
6. Baseline comparison emits advisory delta findings.

Source attribution should remain present through:

- `source_node_ids`
- `source_refs`
- `first_seen_at`
- `last_seen_at`
- `confidence`

## Local API To Dashboard

Planned connection:

1. The local API reads from storage repositories or in-memory provider dictionaries.
2. Read-only endpoints expose local JSON summaries.
3. Dashboard model builders consume API-compatible dictionaries.
4. Dashboard renderers display status cards and metric panels.

Default binding should remain localhost-only whenever a runtime API is explicitly started in a future phase. The static dashboard foundation does not replace the existing Textual TUI.

## What Is Already Implemented

- Event model, serializer, queue, and local event bus.
- SQLite schema and repository helpers.
- Runtime scheduler primitives and state counters.
- Stable node identity and registry primitives.
- Local read-only API route primitives.
- Static dashboard model and HTML rendering helpers.
- Topology graph and timeline view models.
- Policy model, evaluator, and review queue.
- Distributed visibility aggregation with conflict reporting.
- Behavior correlation baseline builders and advisory scoring.
- Schema validation and fixture mutation.
- Metadata-only stream parser.
- Manifest-based plugin registry and dry-run-first runner.
- Bounded relay orchestration simulator.
- Dry-run service lifecycle template generation.

## What Is Not Wired Together Yet

- Event bus to automatic SQLite persistence.
- Scheduler jobs to recurring event flushes or snapshot refreshes.
- Node registry to existing orchestrator runtime behavior.
- Local API to default persisted SQLite repositories.
- Dashboard to a running local API.
- Snapshot storage to automatic topology/timeline materialization.
- Aggregation output to automatic baseline creation.
- Correlation findings to automatic policy review creation.
- Policy approvals to remediation, plugin execution, or configuration changes.
- Plugin execution through scheduler jobs.
- Relay orchestration as a listener or background service.
- Service template output to file writes or service installation.

These remain future explicit implementation tasks with focused tests.

## Raspberry Pi Validation Checklist

Use sanitized fixtures and placeholder metadata only.

- Import all Phase 44-58 modules in the local virtual environment.
- Run the full Python test suite on the target device.
- Initialize a temporary SQLite database and run storage repository checks.
- Publish and consume a sample event through the local event bus.
- Create a sample node identity using placeholder metadata.
- Build a topology graph and timeline from sanitized records.
- Render a static dashboard preview from sanitized sample data.
- Merge two sanitized node reports and confirm source attribution.
- Compare two sanitized baseline windows and inspect advisory deltas.
- Validate a small schema against a sanitized fixture.
- Parse a small byte fixture and confirm metadata-only output.
- Validate a sample plugin manifest without executing it.
- Run a plugin dry-run preview and confirm no subprocess launches.
- Simulate a short relay session with mock payloads.
- Generate systemd and Windows service template text using placeholders.
- Confirm no service files are written by the template module.
- Confirm no service enable/start command is executed by PortMap-AI.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest during focused tests.
- Confirm generated records keep `raw_payload_stored: false`.
- Confirm generated records keep `automatic_changes: false`.
- Confirm generated records keep `administrator_controlled: true`.
- Confirm no private validation notes, logs, screenshots, database files, cache folders, environment files, or generated artifacts are staged.

## Next Milestone Direction

Recommended next milestone: Integrated Local Operations.

Suggested implementation phases:

1. Diagnostic record adapters.
   Add reusable adapters that convert visibility, correlation, schema, stream, plugin, relay, and service-template results into event, storage, policy, timeline, topology, dashboard, and correlation records through a single local interface.

2. Storage-backed local history.
   Persist selected event, visibility, diagnostic, and review summaries locally and add query helpers for recent records.

3. Policy review wiring.
   Connect advisory findings and diagnostic issues to the local review queue without executing actions.

4. Local API repository providers.
   Serve events, assets, snapshots, diagnostics, nodes, topology, and review summaries from storage-backed providers.

5. Dashboard integration panels.
   Render local dashboard panels for visibility, diagnostics, node health, reviews, and baseline deltas without introducing a heavy frontend build system.

6. Opt-in scheduler wiring.
   Add operator-enabled jobs for event flushing, local health summaries, snapshot refreshes, and policy review refreshes.

7. Integrated Raspberry Pi smoke path.
   Validate the end-to-end local-only path on lightweight Linux hardware using sanitized records.

## Safety Requirements

- Local-first behavior only.
- Operator-controlled workflows only.
- Advisory and read-only behavior by default.
- No automatic configuration changes.
- No automatic enforcement.
- No automatic plugin execution.
- No automatic service installation.
- No service enable/start execution.
- No router or firewall modification.
- No cloud sync or external transport.
- No live relay listener in this consolidation plan.
- No raw payload persistence.
- No real IP addresses, MAC addresses, hostnames, usernames, tokens, screenshots, local paths, logs, or private validation data in public docs, tests, or examples.
