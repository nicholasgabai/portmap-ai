# Phase 44-53 Integration Plan

This document consolidates the Phase 44-53 local infrastructure visibility modules into a planned integration path. It is documentation planning only. It does not add runtime behavior, start services, contact nodes, transmit data, modify configuration, or execute response actions.

The integration posture remains local-first, operator-controlled, read-only by default, and suitable for lightweight Linux and Raspberry Pi deployments.

## Module Map

| Phase | Module | Role |
| --- | --- | --- |
| 44 | `core_engine.events` | Normalize local telemetry into event objects, queue events in memory, and publish them through a local event bus. |
| 45 | `core_engine.storage` | Store local events, snapshots, assets, services, topology edges, and findings in SQLite. |
| 46 | `core_engine.runtime` | Provide scheduler primitives for future recurring local jobs without wiring them into always-on execution yet. |
| 47 | `core_engine.nodes` | Manage stable local node identity, capabilities, heartbeat metadata, and lifecycle summaries. |
| 48 | `core_engine.api` | Expose local read-only API primitives for health, events, assets, snapshots, nodes, and topology. |
| 49 | `gui.web` | Render lightweight local dashboard HTML from local API-compatible dictionaries. |
| 50 | `core_engine.topology` | Build topology graph models and event timeline summaries from stored/local records. |
| 51 | `core_engine.policy` | Convert events, findings, and deltas into advisory operator review records. |
| 52 | `core_engine.aggregation` | Merge authorized local node visibility reports while preserving source-node attribution and conflicts. |
| 53 | `core_engine.correlation` | Compare baseline windows and emit advisory findings about asset, service, topology, and finding drift. |

## Data Flow Diagram

Text-form target flow:

```text
local evidence records
  -> event model and event bus
  -> SQLite storage repositories
  -> visibility snapshots and stored summaries
  -> topology graph and timeline view models
  -> baseline comparison and advisory delta findings
  -> policy review queue
  -> local read-only API
  -> lightweight dashboard rendering
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

No step in this plan adds external transport, cloud sync, automatic enforcement, router modification, or active background collection.

## Events Into Storage

Planned connection:

1. Local modules create normalized event objects through `core_engine.events.models`.
2. Events are published to the local-only event bus.
3. A future operator-enabled flush job reads from the in-memory queue.
4. The flush job writes serialized events to `core_engine.storage` repositories.
5. Storage keeps safety fields intact:
   - `raw_payload_stored: false`
   - `automatic_changes: false`
   - `administrator_controlled: true`

Important boundary: Phase 46 only provides scheduler primitives. It is not yet wired into service execution, event flushing, or automatic persistence.

## Snapshots To Topology And Timeline

Planned connection:

1. Stored snapshots are read from the local storage layer.
2. Snapshot assets, services, and topology edges are passed to `core_engine.topology.graph`.
3. Snapshot-related events and baseline delta findings are passed to `core_engine.topology.timeline`.
4. The graph model provides local relationship summaries.
5. The timeline model groups changes into operator-readable entries.

The topology and timeline modules remain read-only. They do not trigger scans, collection, policy changes, or response actions.

## Policy Reviews From Findings And Deltas

Planned connection:

1. Advisory findings are produced by visibility summaries, baseline comparisons, aggregation conflicts, or event correlation.
2. `core_engine.policy.evaluator` maps findings and deltas against enabled local policies.
3. Matching records become review records in `core_engine.policy.review_queue`.
4. Operators can move review records through safe states:
   - `open`
   - `approved`
   - `deferred`
   - `dismissed`
   - `resolved`

Approval is only a review-state transition in this plan. It does not execute actions, modify devices, alter routers, contact external systems, or change PortMap-AI configuration.

## Aggregation Into Baseline Correlation

Planned connection:

1. Authorized node summaries are provided to the local coordinator as already-collected records.
2. `core_engine.aggregation.collector` validates and normalizes node reports.
3. `core_engine.aggregation.merger` merges assets, services, topology edges, and findings.
4. Conflicts are reported through explicit conflict records instead of being hidden.
5. The merged report feeds `core_engine.correlation.build_baseline_from_aggregated_reports()`.
6. Baseline comparison emits advisory delta findings.

Source-node attribution must remain present on merged records through:

- `source_node_ids`
- `source_refs`
- `first_seen_at`
- `last_seen_at`
- `confidence`

## Local API To Dashboard

Planned connection:

1. The local API reads from storage repositories or in-memory provider dictionaries.
2. Read-only endpoints expose local JSON summaries:
   - `/health`
   - `/events`
   - `/assets`
   - `/snapshots`
   - `/nodes`
   - `/topology`
3. Dashboard model builders consume API-compatible dictionaries.
4. `gui.web.render` renders status cards and metric panels.

Default binding remains localhost-only when a runtime API is used in a future phase. The Phase 49 dashboard foundation does not replace the Textual TUI.

## Already Implemented

The following Phase 44-53 primitives exist:

- Normalized local event objects, JSON serialization, in-memory queue, and local event bus.
- SQLite schema and repository helpers for local events, snapshots, assets, services, topology edges, and findings.
- Lightweight scheduler primitives and runtime state counters.
- Stable node identity, capability records, registry lifecycle helpers, and heartbeat metadata.
- Local read-only API app and route primitives.
- Static dashboard model and HTML rendering helpers.
- Topology graph and timeline view models.
- Advisory policy model, evaluator, and review queue.
- Distributed visibility aggregation helpers with source attribution and conflict records.
- Behavior correlation baseline builders, delta helpers, and advisory scoring.

## Not Wired Together Yet

The following integrations are intentionally not active yet:

- Event bus to SQLite persistence.
- Scheduler jobs to recurring event flush, snapshot refresh, policy review refresh, or health updates.
- Node registry to existing orchestrator runtime behavior.
- Local API to default persisted SQLite repositories.
- Dashboard to a running local API.
- Snapshot storage to topology/timeline generation.
- Aggregation output to automatic baseline creation.
- Correlation findings to automatic policy review creation.
- Policy approvals to remediation or configuration changes.

These are future explicit implementation tasks and should be added incrementally with tests.

## Raspberry Pi Validation Checklist

Use sanitized local test data and operator-controlled commands only.

- Confirm package import of each Phase 44-53 module on the target device.
- Run the full Python test suite in the supported local environment.
- Create a temporary SQLite database and initialize the local storage schema.
- Insert and list sample events, assets, services, topology edges, snapshots, and findings.
- Build a sample event queue and verify local publish/consume behavior.
- Create a sample node identity using placeholder metadata.
- Build a sample topology graph from sanitized records.
- Render a static dashboard preview from sanitized sample data.
- Merge two sanitized node reports and confirm source attribution is preserved.
- Build two sanitized baseline windows and compare advisory deltas.
- Confirm CPU and memory use remain modest during tests.
- Confirm no external network calls are required.
- Confirm no raw payload bytes, local identifiers, secrets, screenshots, logs, or runtime artifacts are committed.

## Suggested Next Implementation Phases

Suggested consolidation phases after Phase 44-53:

1. Phase 54 - Storage-backed local event pipeline.
   Wire event serialization and queue flushing into explicit local storage operations.

2. Phase 55 - Snapshot persistence and topology materialization.
   Store visibility snapshots and build reusable topology/timeline summaries from persisted data.

3. Phase 56 - Policy review integration.
   Convert correlation findings and aggregation conflicts into local operator review records.

4. Phase 57 - Local API repository providers.
   Serve events, assets, snapshots, nodes, topology, and review summaries from the storage layer.

5. Phase 58 - Dashboard API integration.
   Read from the local API and render operator panels without introducing a heavy frontend build system.

6. Phase 59 - Runtime scheduler opt-in wiring.
   Add operator-enabled scheduler jobs for event flushes, health summaries, snapshot refreshes, and policy review refreshes.

7. Phase 60 - Integrated Raspberry Pi smoke path.
   Validate the end-to-end local-only path on a lightweight Linux device using sanitized test records.

## Safety Requirements

- Local-only by default.
- Operator-controlled workflows only.
- Advisory and read-only behavior by default.
- No automatic configuration changes.
- No automatic enforcement.
- No router or firewall modification.
- No cloud sync or external transport.
- No active background collection in this consolidation plan.
- No real IP addresses, MAC addresses, hostnames, usernames, tokens, screenshots, local paths, logs, or private validation data in public docs, tests, or examples.
