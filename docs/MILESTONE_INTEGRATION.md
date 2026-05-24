# Milestone Integration

This document is the consolidated integration guide for the completed Phase 44-88 milestone work. It replaces the phase-specific planning docs as the primary implementation map. Archived planning files remain under `docs/archive/` for historical reference, `docs/MILESTONE_J_INTEGRATION.md` provides the detailed Phase 59-64 integration summary, `docs/MILESTONE_K_INTEGRATION.md` provides the detailed Phase 65-70 integration summary, `docs/MILESTONE_L_INTEGRATION.md` provides the detailed Phase 71-76 integration summary, `docs/MILESTONE_M_INTEGRATION.md` provides the detailed Phase 77-82 integration summary, `docs/MILESTONE_N_INTEGRATION.md` provides the detailed Phase 83-86 integration summary, and `docs/PHASE_87_92_PLAN.md` tracks Milestone O live telemetry phases.

This is documentation summary only. It does not add runtime behavior, start services, execute plugins automatically, open relay listeners, install service units, transmit data externally, or modify host configuration.

The integration posture remains local-first, operator-controlled, read-only by default, bounded, auditable, and suitable for lightweight Linux and Raspberry Pi deployments.

The remaining end-to-end completion path is tracked in `docs/COMPLETION_ROADMAP.md`, covering active federation runtime, live telemetry, gateway/router-adjacent modes, production security, installer packaging, AI security intelligence, and future commercial readiness.

## Completed Milestones

| Milestone | Phases | Focus | Current State |
| --- | --- | --- | --- |
| Local Intelligence Platform | 44-46 | Event model, local storage, scheduler primitives | Complete baseline |
| Coordinated Node Platform | 47-48 | Node identity, capabilities, local read-only API | Complete baseline |
| Operator Dashboard | 49-50 | Static dashboard foundation, topology and timeline models | Complete baseline |
| Policy and Correlation Engine | 51-53 | Policy review, distributed aggregation, baseline correlation | Complete baseline |
| Advanced Diagnostics and Deployment Readiness | 54-58 | Schema validation, stream metadata, plugin governance, relay orchestration, service templates | Complete baseline |
| Runtime Pipeline and Persistent Topology Integration | 59-64 | Persistent topology, snapshot drift, runtime workflow wiring, review persistence, dashboard providers, operational export bundles | Complete baseline |
| Unified Runtime Operations | 65-70 | Runtime sessions, profiles, recovery, CLI, health monitoring, and service-mode readiness previews | Complete baseline |
| Distributed Runtime Intelligence | 71-76 | Distributed node state, federated topology, cluster health, distributed reviews, coordinated exports, and operator visibility prep | Complete baseline |
| Trusted Runtime Transport and Live Federation | 77-82 | Trusted transport models, signed summary exchange, live cluster synchronization, distributed event propagation, diagnostics, and dashboard/API readiness | Complete baseline |
| Active Federation Runtime | 83-86 | Runtime manager records, trusted peer lifecycle, runtime exchange scheduler, active federation validation, readiness scores, recommendations, and dashboard/API-ready dictionaries | Complete baseline |
| Live Network Telemetry | 87-88 | Passive interface discovery, dry-run capture planning, bounded packet metadata windows, transport summaries, replay-safe counters, and dashboard/API-ready dictionaries | Complete baseline |

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
| Milestone J Runtime Pipeline | `core_engine.runtime.pipeline`, `core_engine.runtime.workflows` | Coordinate explicit dry-run local workflows across visibility, topology, drift, policy review, correlation, and optional local storage writes. |
| Persistent Review Store | `core_engine.policy.review_store`, `core_engine.policy.history` | Persist review drafts, state transitions, finding status records, and review imports/exports through existing storage. |
| Dashboard Providers | `gui.web.providers`, `gui.web.views` | Build dashboard models from storage, runtime state, topology, review, diagnostic, and API-compatible provider data. |
| Operational Export | `core_engine.export` | Build deterministic local evidence bundles with redaction, placeholder validation, digests, and explicit local archive output. |
| Runtime Sessions | `core_engine.runtime.session`, `core_engine.runtime.session_state` | Track explicit operator-started runtime sessions and expose CLI, API, dashboard, recovery, health, and service-preview summaries. |
| Runtime Profiles | `core_engine.runtime.profiles`, `core_engine.runtime.profile_loader` | Compose default, edge-device, and operator-provided runtime settings across scheduler, storage, API, dashboard, and export layers. |
| Runtime Recovery | `core_engine.runtime.checkpoints`, `core_engine.runtime.recovery` | Summarize prior sessions, incomplete workflows, pending reviews, failed steps, and export-ready records without automatic restart. |
| Runtime CLI | `cli.runtime`, `cli.main` | Expose explicit `portmap runtime` status, run, recover, reviews, and export commands with dry-run defaults. |
| Runtime Health | `core_engine.runtime.health` | Summarize storage, event queue, scheduler, review, dashboard, export, session, and resource-budget health. |
| Service Readiness | `core_engine.runtime.service_mode` | Generate dry-run service-mode preflight summaries, service command previews, and manual operator checklist records. |
| Distributed Runtime State | `core_engine.runtime.distributed_state`, `core_engine.runtime.node_sync` | Normalize trusted master and worker runtime summaries with stale, missing, duplicate, and conflict reporting. |
| Federated Topology | `core_engine.topology.federated`, `core_engine.topology.node_merge` | Merge trusted node topology snapshots with source attribution, confidence scoring, conflicts, timeline records, and correlation records. |
| Cluster Runtime Health | `core_engine.runtime.cluster_health` | Roll up trusted node health into cluster availability, component readiness, resource warnings, local events, and dashboard panels. |
| Distributed Reviews | `core_engine.policy.distributed_review` | Aggregate trusted node reviews, finding status records, duplicates, repeated categories, and export-ready review summaries. |
| Coordinated Exports | `core_engine.export.node_manifest`, `core_engine.export.coordinated_bundle` | Build per-node evidence manifests and coordinated export plans with redaction validation and cross-node digests. |
| Operator Visibility | `core_engine.runtime.operator_visibility`, `gui.web.distributed_views` | Build read-only trusted-node API-compatible visibility panels without public exposure or remote control. |
| Federation Trust and Transport | `core_engine.federation.trust`, `core_engine.federation.transport` | Model approved peers, trusted transport sessions, handshake summaries, expiration, trust scopes, and replay-window metadata without opening listeners. |
| Federation Signed Exchange | `core_engine.federation.signing`, `core_engine.federation.exchange` | Build canonical JSON, deterministic digests, signature metadata, signed summary envelopes, verification records, and exchange summaries. |
| Federation Live Sync | `core_engine.federation.synchronization`, `core_engine.federation.cluster_state` | Apply signed summaries to synchronization windows, classify updates, track per-node last-seen state, and produce merged cluster state summaries. |
| Federation Event Propagation | `core_engine.federation.event_window`, `core_engine.federation.event_propagation` | Build trusted event envelopes, replay-window summaries, propagation classifications, event batch summaries, and cluster event rollups. |
| Federation Diagnostics and Views | `core_engine.federation.health`, `core_engine.federation.diagnostics`, `core_engine.federation.operator_views`, `gui.web.federation_views` | Summarize federation health, readiness, recommendations, counters, dashboard panels, and local API-compatible dictionaries. |
| Federation Runtime Manager | `core_engine.federation.runtime_manager`, `core_engine.federation.runtime_state` | Build active federation runtime manager records, runtime state summaries, trusted peer enrollment summaries, planned exchange loops, per-peer counters, and dashboard/API-ready runtime state. |
| Trusted Peer Lifecycle | `core_engine.federation.peer_lifecycle`, `core_engine.federation.peer_registry` | Manage trusted peer lifecycle states, trust scope updates, transport session linkage, stale/expired/revoked peer summaries, and dashboard/API-ready registry records. |
| Runtime Exchange Scheduler | `core_engine.federation.exchange_jobs`, `core_engine.federation.exchange_scheduler` | Convert federation loop plans into signed-summary, cluster-sync, and event-propagation job schedules with bounded backoff and dashboard/API-ready status. |
| Active Federation Validation | `core_engine.federation.runtime_checks`, `core_engine.federation.validation` | Validate active federation readiness across peers, signed exchanges, sync windows, event propagation, replay windows, scheduler state, runtime manager state, recommendations, and dashboard/API dictionaries. |
| Telemetry Interface Discovery | `core_engine.telemetry.interfaces`, `core_engine.telemetry.capture_sessions` | Normalize local interface metadata, classify address families and interface capabilities, and build dry-run passive capture plans without capturing packets. |
| Packet Metadata Ingestion | `core_engine.telemetry.ingestion`, `core_engine.telemetry.packet_window` | Normalize operator-provided packet metadata into bounded dry-run windows with source attribution, transport summaries, replay-safe counters, malformed/unsupported classification, and no raw payload storage. |

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

Milestone J target flow:

```text
local evidence and snapshots
  -> persistent topology state
  -> snapshot drift detection
  -> explicit runtime pipeline
  -> persistent review history
  -> dashboard provider summaries
  -> operational export bundle
```

Milestone K target flow:

```text
runtime profile
  -> runtime session manager
  -> scheduler, event queue, storage, topology, review, dashboard, and export summaries
  -> runtime recovery and health summaries
  -> runtime CLI output
  -> service-mode readiness preview
  -> manual operator review
```

Milestone L target flow:

```text
trusted local node summaries
  -> distributed node state sync
  -> federated topology aggregation
  -> cluster runtime health
  -> distributed review aggregation
  -> coordinated export bundle plans
  -> read-only local operator visibility models
```

Milestone M target flow:

```text
operator-approved trusted node descriptors
  -> trusted transport session records
  -> signed runtime summary envelopes
  -> synchronization windows
  -> live cluster state update classifications
  -> distributed event propagation summaries
  -> federation diagnostics
  -> local dashboard/API federation views
  -> active federation runtime manager records
  -> trusted peer lifecycle registry summaries
  -> runtime exchange scheduler job summaries
  -> active federation validation summaries
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
- Runtime sessions can summarize event, storage, scheduler, topology, review, export, health, and service-preview status.
- Runtime health can emit local health events suitable for storage and dashboard display.
- Service-mode readiness can reuse service templates and runtime health summaries for manual operator review.
- Distributed node state can preserve runtime session, profile, health, and checkpoint references from trusted nodes.
- Federated topology can turn trusted node snapshots into source-attributed topology, timeline, and correlation-ready records.
- Cluster runtime health can summarize trusted node health records into dashboard panels and local health events.
- Distributed reviews can aggregate node-owned review drafts and finding status records without propagating approvals.
- Coordinated export plans can combine per-node evidence manifests while preserving redaction and digest checks.
- Operator visibility can expose read-only API-compatible distributed panels without starting a web server.
- Federation transport records can describe trusted sessions, handshake summaries, expiration windows, and replay metadata without starting listeners or contacting peers.
- Signed summary exchange can wrap runtime, health, topology, review, export, service-readiness, and event records in deterministic digest and verification metadata.
- Live cluster synchronization can classify signed summaries and produce accepted, rejected, stale, replayed, untrusted, malformed, conflict, and drift records.
- Distributed event propagation can build local event storage-ready records while preserving duplicate, stale, malformed, rejected, and untrusted propagation states.
- Federation diagnostics and dashboard views can expose readiness, recommendations, stale counters, rejected counters, duplicate counters, and read-only local API-compatible panels.
- Federation runtime manager records can summarize active, inactive, paused, and error runtime states with planned loops and counters without starting listeners or daemons.
- Trusted peer lifecycle records can validate enroll, approve, pause, resume, revoke, expire, and trust scope update transitions while linking transport sessions and reporting stale, expired, and revoked peers.
- Runtime exchange scheduler records can plan signed-summary exchange, cluster-state synchronization, and event propagation jobs with interval/backoff metadata and failure counters without executing background jobs.
- Active federation validation records can score peer, exchange, sync, event, replay, scheduler, and runtime readiness before any live loop execution is enabled.

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
- Persistent topology state and snapshot history.
- Snapshot drift reports with event, storage, policy, timeline, and correlation-ready records.
- Explicit runtime pipeline workflow with dry-run defaults and optional local writes.
- Persistent review store and finding status history.
- Storage-backed dashboard data providers.
- Operational export bundle generation with redaction and deterministic JSON output.
- Runtime session records and deterministic summaries.
- Unified runtime profiles for default, edge-device, and operator-merged settings.
- Runtime recovery checkpoints and advisory recovery summaries.
- Integrated runtime CLI commands for status, run, recover, reviews, and export.
- Runtime health summaries across storage, scheduler, event queue, review, dashboard, export, and sessions.
- Service-mode readiness previews with dry-run command previews and manual operator checklist records.
- Distributed node state sync for trusted master and worker runtime summaries.
- Federated topology aggregation across trusted node snapshots.
- Cluster runtime health rollups across trusted nodes.
- Distributed review queue aggregation with duplicate and repeated-category reporting.
- Coordinated export bundle planning with per-node manifests and cross-node digests.
- Operator visibility preparation for read-only trusted-node panels.
- Trusted node transport models with local trust profiles and replay-window metadata.
- Signed runtime summary exchange envelopes with deterministic digests and verification status records.
- Live cluster state synchronization windows with update classifications and merged cluster summaries.
- Distributed event propagation summaries with event digest, sequence, and replay metadata.
- Federation diagnostics with readiness scoring, recommendation records, and local health events.
- Federation dashboard/API readiness views for trusted peers, transports, signed exchanges, sync windows, events, diagnostics, readiness, and counters.
- Federation runtime manager records with peer enrollment summaries, planned signed exchange/sync/event loops, per-peer counters, and runtime dashboard/API state.

## What Is Not Wired Together Yet

- Event bus to automatic SQLite persistence.
- Scheduler jobs to recurring event flushes or snapshot refreshes.
- Node registry to existing orchestrator runtime behavior.
- Local API to default persisted SQLite repositories.
- Dashboard to a running local API.
- Snapshot storage to automatic topology/timeline materialization outside explicit workflow calls.
- Aggregation output to automatic baseline creation.
- Correlation findings to automatic policy review creation.
- Policy approvals to remediation, plugin execution, or configuration changes.
- Plugin execution through scheduler jobs.
- Relay orchestration as a listener or background service.
- Service template output to file writes or service installation.
- Runtime session records to an always-on daemon supervisor.
- Service-mode readiness previews to automatic service installation, enablement, or startup.
- Runtime health events to automatic background persistence unless explicitly invoked.
- Trusted transport models to live network listeners.
- Signed summary exchange to automatic peer delivery.
- Federation synchronization to background polling.
- Distributed event propagation to remote execution or remediation.
- Federation dashboard/API views to a public web server.
- Federation runtime manager records to background daemon execution.

These remain future explicit implementation tasks with focused tests.

## Raspberry Pi Validation Checklist

Use sanitized fixtures and placeholder metadata only.

- Import all Phase 44-64 modules in the local virtual environment.
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
- Build a persistent topology snapshot and compare two sanitized snapshots.
- Run the runtime pipeline in dry-run mode.
- Persist review records and review state transitions to a temporary database.
- Build dashboard provider output from stored local records.
- Generate an operational export bundle and optional local archive in a temporary directory.
- Create and stop a dry-run runtime session.
- Load and validate default, edge-device, and sanitized operator runtime profiles.
- Run runtime recovery against temporary checkpoint records.
- Run runtime CLI commands in dry-run mode.
- Build runtime health summaries from temporary local records.
- Generate service-mode readiness previews with sanitized placeholders.
- Build trusted transport session records with placeholder nodes.
- Validate signed runtime summary envelopes with replay-safe metadata.
- Apply signed summaries to a small synchronization window.
- Build distributed event propagation summaries from sanitized local events.
- Build federation diagnostics and dashboard/API federation views.
- Build trusted peer lifecycle registries and peer state review summaries.
- Build runtime exchange scheduler summaries from trusted peer lifecycle and runtime loop plans.
- Build active federation validation summaries and operator recommendations from existing federation records.
- Confirm no service files are written by the template module.
- Confirm no service enable/start command is executed by PortMap-AI.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest during focused tests.
- Confirm generated records keep `raw_payload_stored: false`.
- Confirm generated records keep `automatic_changes: false`.
- Confirm generated records keep `administrator_controlled: true`.
- Confirm no private validation notes, logs, screenshots, database files, cache folders, environment files, or generated artifacts are staged.

## Next Milestone Direction

Recommended next direction: follow the completion roadmap in `docs/COMPLETION_ROADMAP.md`.

Suggested implementation phases:

1. Active federation runtime.
   Turn trusted transport and signed exchange models into operator-approved runtime exchange loops between approved nodes.

2. Live network telemetry.
   Ingest approved interface, socket, process, flow, and protocol metadata into the existing runtime pipeline.

3. Gateway and router-adjacent modes.
   Support router logs, SPAN/mirror-port metadata, Raspberry Pi edge profiles, DNS/flow visibility, and gateway-mode validation.

4. Production security and access control.
   Harden local auth, RBAC, TLS, secure node enrollment, audit chains, retention, and redaction policies.

5. Installer, service, and release packaging.
   Deliver Linux, macOS, and Windows installer/service workflows with upgrade, rollback, and release validation.

6. AI security intelligence and commercial readiness.
   Add telemetry-backed behavior intelligence, explainable review summaries, fleet architecture, tenant modeling, licensing hooks, and enterprise API blueprints.

7. Integrated Raspberry Pi smoke path.
   Validate the live local and federation path on lightweight Linux hardware using sanitized lab records.

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
- No live relay or federation listener in this consolidation plan.
- No raw payload persistence.
- No real IP addresses, MAC addresses, hostnames, usernames, tokens, screenshots, local paths, logs, or private validation data in public docs, tests, or examples.
