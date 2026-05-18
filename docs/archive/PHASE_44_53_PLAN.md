# PortMap-AI Phase 44-53 Implementation Plan

This plan defines the next implementation path for evolving PortMap-AI from a CLI-first visibility toolkit into a local-first infrastructure visibility platform with event history, persistent baselines, distributed node coordination, local API access, and dashboard foundations.

The plan is documentation only. It does not implement these phases.

## Guiding Principles

- Keep workflows local-first, operator-controlled, and opt-in.
- Preserve advisory and read-only behavior by default.
- Do not add automatic configuration changes.
- Do not transmit data externally by default.
- Preserve Raspberry Pi and Linux compatibility with lightweight defaults.
- Preserve existing CLI behavior while adding new capabilities.
- Keep modules isolated, reusable, and testable.
- Add tests for each phase.
- Use placeholders only in docs, tests, and examples.
- Do not include real IPs, MAC addresses, hostnames, usernames, screenshots, secrets, tokens, or local paths.

Preferred terminology:

- local infrastructure visibility
- asset inventory
- service metadata
- event history
- topology relationships
- operator review
- policy-controlled workflow
- advisory finding
- baseline comparison
- local telemetry

Avoid unsafe or misleading language around offensive activity, autonomous attack behavior, or exploit-oriented capability claims.

## Milestones

### Milestone E: Local Intelligence Platform - Phases 44-46

Build the local event model, durable storage, and lightweight runtime scheduler needed for recurring visibility, event history, and baseline refresh workflows.

### Milestone F: Coordinated Node Platform - Phases 47-48

Strengthen local node identity, node coordination, and read-only API access for future multi-node visibility and operator tooling.

### Milestone G: Operator Dashboard - Phases 49-50

Introduce a local dashboard foundation and historical topology/timeline views backed by local API and stored visibility data.

### Milestone H: Policy and Correlation Engine - Phases 51-53

Formalize advisory policy review, distributed visibility aggregation, and safe behavior correlation over local event and snapshot history.

## Phase 44 - Event Model and Local Event Pipeline

Goal: Create a unified internal event model so existing visibility, service, asset, flow, and snapshot logic can emit normalized local events.

Build:

- `core_engine/events/__init__.py`
- `core_engine/events/models.py`
- `core_engine/events/bus.py`
- `core_engine/events/queue.py`
- `core_engine/events/serializer.py`
- `tests/test_events.py`
- `docs/event_pipeline.md`

Features:

- Normalized event objects.
- Event type registry.
- Severity field.
- Source subsystem field.
- Asset, service, and flow references.
- JSON serialization.
- In-memory queue.
- Local-only event bus.
- No external transport.

Acceptance:

- Events can be created, serialized, queued, consumed, and tested.
- Malformed events are rejected safely.
- Existing code is not broken.

## Phase 45 - Persistent Local Storage

Goal: Add durable local storage for snapshots, events, assets, services, topology relationships, and operator findings.

Build:

- `core_engine/storage/__init__.py`
- `core_engine/storage/sqlite_store.py`
- `core_engine/storage/schema.py`
- `core_engine/storage/repositories.py`
- `tests/test_storage.py`
- `docs/local_storage.md`

Features:

- SQLite-backed local database.
- Schema initialization.
- Event storage.
- Snapshot storage.
- Asset and service storage.
- Topology edge storage.
- Safe migrations and versioning.
- Local-only by default.

Acceptance:

- Database initializes locally.
- Events and snapshots can be stored and queried.
- Tests use temporary databases.
- No private local paths appear in docs or tests.

## Phase 46 - Continuous Local Runtime Scheduler

Goal: Create a lightweight scheduler for recurring local visibility tasks and baseline refreshes.

Build:

- `core_engine/runtime/__init__.py`
- `core_engine/runtime/scheduler.py`
- `core_engine/runtime/jobs.py`
- `core_engine/runtime/runtime_state.py`
- `tests/test_runtime_scheduler.py`
- `docs/runtime_scheduler.md`

Features:

- Periodic local jobs.
- Snapshot refresh job.
- Event generation job.
- Health heartbeat job.
- Dry-run operator workflow job.
- Start and stop controls.
- Safe defaults for Raspberry Pi.

Acceptance:

- Scheduler can start and stop cleanly.
- Jobs run at configured intervals.
- Failed jobs do not crash the runtime.
- Resource usage remains lightweight.

## Phase 47 - Node Identity and Local Coordination Hardening

Goal: Strengthen distributed node identity and coordination without changing the local-first posture.

Build:

- `core_engine/nodes/__init__.py`
- `core_engine/nodes/identity.py`
- `core_engine/nodes/registry.py`
- `core_engine/nodes/capabilities.py`
- `tests/test_node_identity.py`
- `docs/node_coordination.md`

Features:

- Stable node IDs.
- Node capability records.
- Registration metadata.
- Heartbeat metadata.
- Node status lifecycle.
- Operator-readable node summaries.
- No external sync by default.

Acceptance:

- Node identity persists locally.
- Node state transitions are tested.
- Stale nodes are marked correctly.
- No private hostnames or IPs are committed.

## Phase 48 - Local API Layer

Goal: Expose local read-only API endpoints for dashboard and operator tooling.

Build:

- `core_engine/api/__init__.py`
- `core_engine/api/app.py`
- `core_engine/api/routes_health.py`
- `core_engine/api/routes_events.py`
- `core_engine/api/routes_assets.py`
- `core_engine/api/routes_snapshots.py`
- `tests/test_local_api.py`
- `docs/local_api.md`

Features:

- Health endpoint.
- Event list endpoint.
- Asset list endpoint.
- Snapshot list endpoint.
- Topology summary endpoint.
- Local-only binding by default.
- Configurable host and port.
- No external transmission.

Acceptance:

- API starts locally.
- Endpoints return JSON.
- Tests use local test client.
- Default bind is localhost.

## Phase 49 - Dashboard Foundation

Goal: Add a minimal local dashboard foundation that reads from the local API.

Build:

- `gui/web/`
- `gui/web/README.md`
- `docs/dashboard_foundation.md`
- Tests where applicable.

Features:

- Local dashboard shell.
- Health and status panel.
- Asset count panel.
- Event count panel.
- Snapshot count panel.
- Operator review count panel.
- No cloud dependency.

Acceptance:

- Dashboard can be launched locally.
- Documentation explains local use.
- Dashboard examples do not expose private data.

## Phase 50 - Topology and Timeline Views

Goal: Add operator-friendly views for topology relationships and historical changes.

Build:

- `core_engine/topology/timeline.py`
- `core_engine/topology/graph.py`
- Dashboard components, docs, and tests.

Features:

- Topology node and edge summaries.
- Timeline event grouping.
- Baseline/current comparison view.
- Service change summaries.
- Relationship drift summaries.

Acceptance:

- Topology and timeline data can be rendered from stored snapshots and events.
- Output remains sanitized in docs and examples.
- No automatic changes are triggered.

## Phase 51 - Policy Review Engine

Goal: Formalize advisory policy evaluation and operator review workflows.

Build:

- `core_engine/policy/__init__.py`
- `core_engine/policy/models.py`
- `core_engine/policy/evaluator.py`
- `core_engine/policy/review_queue.py`
- `tests/test_policy_review.py`
- `docs/policy_review_engine.md`

Features:

- Policy objects.
- Finding-to-policy mapping.
- Review states.
- Approval-required markers.
- Draft workflow records.
- Audit-ready state transitions.
- No automatic execution by default.

Acceptance:

- Findings can generate review records.
- Review records can move through safe states.
- Automatic execution remains false by default.

## Phase 52 - Distributed Visibility Aggregation

Goal: Allow multiple authorized local nodes to contribute visibility summaries to a coordinator.

Build:

- `core_engine/aggregation/__init__.py`
- `core_engine/aggregation/collector.py`
- `core_engine/aggregation/merger.py`
- `core_engine/aggregation/conflict_resolution.py`
- `tests/test_visibility_aggregation.py`
- `docs/distributed_visibility_aggregation.md`

Features:

- Collect node summaries.
- Merge sanitized snapshots.
- Identify duplicate assets.
- Preserve source node attribution.
- Local coordinator mode.
- No cloud sync by default.

Acceptance:

- Multiple sample node reports merge correctly.
- Conflicts are reported, not hidden.
- Source attribution is preserved.

## Phase 53 - Behavior Correlation Baseline

Goal: Add safe local baseline correlation that identifies changes over time using stored events and snapshots.

Build:

- `core_engine/correlation/__init__.py`
- `core_engine/correlation/baseline.py`
- `core_engine/correlation/delta.py`
- `core_engine/correlation/scoring.py`
- `tests/test_behavior_correlation.py`
- `docs/behavior_correlation.md`

Features:

- Baseline windows.
- Service drift summaries.
- Asset appearance and disappearance summaries.
- Topology relationship changes.
- Severity scoring.
- Operator-readable explanations.
- No automatic enforcement.

Acceptance:

- Baseline/current windows can be compared.
- Findings include explanations and evidence references.
- Results are advisory and local-only.

## Cross-Phase Requirements

- Keep public examples sanitized with documentation-safe placeholders.
- Use reserved documentation networks such as TEST-NET ranges when IP examples are unavoidable.
- Do not commit real IPs, MAC addresses, hostnames, usernames, local paths, screenshots, logs, archives, secrets, tokens, or runtime data.
- Keep generated data out of public docs unless it is fully sanitized.
- Preserve current CLI behavior and add new commands or flags in a backward-compatible way.
- Maintain focused tests for new modules and update package metadata only when needed.
- Keep Raspberry Pi and small Linux deployments in scope by default.

## Do Not Build Yet

- Cloud billing.
- Hosted SaaS.
- Public internet exposure.
- Automatic enforcement.
- Heavy ML training.
- Third-party data export.
- Installer packaging beyond local documentation.
