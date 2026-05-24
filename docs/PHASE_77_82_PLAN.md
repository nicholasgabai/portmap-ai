# Phase 77-82 Trusted Federation Plan

Milestone M defines the next implementation milestone for moving PortMap-AI from distributed-ready summaries into live trusted runtime federation between operator-approved nodes. The focus is trusted transport models, signed runtime summary exchange, synchronization windows, replay-safe records, live cluster updates, distributed event summaries, federation diagnostics, and dashboard/API-ready federation views.

This is a planning document only. It does not implement runtime behavior, open network listeners, start services, discover untrusted nodes, change host configuration, perform automatic enforcement, execute remote commands, or transmit data outside the operator-controlled trusted environment.

## Milestone M: Trusted Runtime Transport and Live Federation

Goal:
Move PortMap-AI from distributed-ready summaries into live trusted runtime federation between operator-approved nodes while preserving the local-first, operator-controlled, advisory-by-default posture.

Milestone M should connect existing node identity, runtime sessions, distributed node state, cluster health, federated topology, distributed review, coordinated export, operator visibility, local API, and dashboard provider primitives into explicit trusted-node transport workflows.

All work should remain:

- local-first
- trusted-node scoped
- operator-approved
- advisory by default
- policy-aware
- source-attributed
- replay-safe
- bounded and resource-conscious
- macOS/Linux development friendly
- Raspberry Pi/Linux compatible
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 77:

- Local event model, queue, and event bus.
- SQLite-backed local storage repositories.
- Runtime sessions, profiles, checkpoints, recovery, CLI, health, and service-readiness previews.
- Node identity, capability, heartbeat, and local coordination primitives.
- Local read-only API primitives.
- Persistent topology state and snapshot drift detection.
- Runtime pipeline workflow primitives.
- Persistent operator review records and history.
- Dashboard rendering and provider foundations.
- Operational and coordinated export bundle helpers.
- Distributed node state summaries.
- Federated topology aggregation.
- Cluster runtime health summaries.
- Distributed review aggregation.
- Read-only operator visibility models.

Milestone M should add transport and exchange models for operator-approved trusted nodes. It should not add untrusted discovery, cloud sync, public internet exposure, remote command execution, or automatic remediation.

## Phase 77 - Trusted Node Transport Models

Status: Complete Baseline

Goal:
Define trusted-node transport session records, endpoint descriptors, trust boundaries, and operator-approved exchange plans without opening network listeners or contacting nodes.

Build:

- `core_engine/federation/transport.py`
- `core_engine/federation/trust.py`
- `tests/test_trusted_node_transport.py`
- `docs/trusted_node_transport.md`

Features:

- Trusted node transport endpoint records.
- Operator-approved node allowlist summaries.
- Transport session identifiers.
- Session start, stop, and expiry timestamps.
- Master/worker role and capability references.
- Transport mode labels such as local-file, loopback-api, and trusted-lan-preview.
- Trust boundary and replay window fields.
- Source node attribution.
- Safety fields for local-only and remote-control-disabled behavior.

Acceptance:

- Transport session records are deterministic and JSON serializable.
- Endpoint descriptors use sanitized placeholders in tests and docs.
- Session records do not open sockets, contact nodes, or start services.
- Invalid or unapproved node descriptors are rejected safely.
- Tests use sanitized fixtures only.

## Phase 78 - Signed Runtime Summary Exchange

Status: Complete Baseline

Goal:
Create signed runtime summary exchange envelopes for trusted node state, health, topology, review, export, and service-readiness summaries.

Build:

- `core_engine/federation/signing.py`
- `core_engine/federation/exchange.py`
- `tests/test_signed_runtime_summary_exchange.py`
- `docs/signed_runtime_summary_exchange.md`

Features:

- Signed summary envelope records.
- Node identity and key reference fields.
- Payload digest and signature metadata.
- Timestamp, nonce, sequence, and replay-window fields.
- Source attribution for exchanged summaries.
- Validation result records.
- Rejection records for stale, replayed, unsigned, malformed, and untrusted envelopes.
- Redaction-safe validation summaries.

Acceptance:

- Signed summary envelopes are deterministic for sanitized input.
- Validation accepts well-formed trusted envelopes and rejects malformed ones.
- Replay-safe fields are present on every exchange record.
- No private keys, real tokens, or raw payload bytes appear in public examples.
- No network transport is added by this phase.

## Phase 79 - Live Cluster State Synchronization

Status: Complete Baseline

Goal:
Use trusted signed summary envelopes to update local cluster state windows and produce live synchronization summaries for approved nodes.

Build:

- `core_engine/federation/synchronization.py`
- `core_engine/federation/cluster_state.py`
- `tests/test_live_cluster_state_sync.py`
- `docs/live_cluster_state_synchronization.md`

Features:

- Synchronization window records.
- Last accepted sequence per node.
- Last accepted summary digest per node.
- Live cluster state update summaries.
- Stale, missing, duplicate, out-of-order, and conflicting update detection.
- Source-attributed accepted and rejected update records.
- Runtime session references for sync windows.
- Dashboard/API-ready sync summaries.

Acceptance:

- Sanitized signed node summaries update cluster windows deterministically.
- Replay and out-of-order updates are rejected safely.
- Conflicts are reported, not hidden.
- No automatic remote fetch or background polling is added.
- Tests use temporary records and sanitized fixtures only.

## Phase 80 - Distributed Event Propagation

Status: Complete Baseline

Goal:
Create trusted distributed event propagation records and summaries for live federation without automatic enforcement or remote execution.

Build:

- `core_engine/federation/event_propagation.py`
- `core_engine/federation/event_window.py`
- `tests/test_distributed_event_propagation.py`
- `docs/distributed_event_propagation.md`

Features:

- Distributed event envelope records.
- Source node and destination node attribution.
- Event digest and replay metadata.
- Propagation window summaries.
- Accepted, rejected, duplicate, stale, and malformed event summaries.
- Local event storage-ready records.
- Cluster health and operator visibility integration fields.
- Advisory-only propagation summaries.

Acceptance:

- Distributed event summaries are deterministic and JSON serializable.
- Replay-safe metadata is present on propagated event records.
- Rejected events preserve source attribution and rejection reason.
- No remediation, plugin execution, service installation, or remote command behavior is triggered.
- Tests use sanitized local events only.

## Phase 81 - Federation Diagnostics

Status: Complete Baseline

Goal:
Add local federation diagnostics for trusted transport sessions, signed exchange validation, sync windows, distributed events, and resource-conscious operation.

Build:

- `core_engine/federation/diagnostics.py`
- `core_engine/federation/health.py`
- `tests/test_federation_diagnostics.py`
- `docs/federation_diagnostics.md`

Features:

- Federation diagnostic summary records.
- Transport session diagnostics.
- Signature validation diagnostics.
- Replay-window diagnostics.
- Synchronization lag summaries.
- Distributed event propagation diagnostics.
- Per-node warning and error summaries.
- Raspberry Pi-friendly threshold fields.
- Local event and dashboard/API-ready diagnostic records.

Acceptance:

- Diagnostics are deterministic and JSON serializable.
- Failed checks are isolated and reported without crashing.
- Diagnostics do not perform active probing or external calls.
- Output includes explicit safety fields.
- Tests cover healthy, degraded, stale, replayed, malformed, and unavailable states.

## Phase 82 - Federation Dashboard/API Readiness

Goal:
Prepare dashboard and local API provider models for trusted runtime federation without adding public exposure or remote-control behavior.

Build:

- `gui/web/federation_providers.py`
- `gui/web/federation_views.py`
- `tests/test_federation_dashboard_api_readiness.py`
- `docs/federation_dashboard_api_readiness.md`

Features:

- Provider interface for federation API-compatible dictionaries.
- Trusted transport status panels.
- Signed exchange validation panels.
- Live cluster synchronization panels.
- Distributed event propagation panels.
- Federation diagnostic panels.
- Empty-state and stale-node rendering models.
- Explicit remote-control disabled fields.
- Textual TUI compatibility notes.

Acceptance:

- Federation dashboard/API models build from sanitized local records.
- Empty and stale states render cleanly.
- Providers do not require external network access.
- Output contains no raw payload bytes.
- Existing Textual terminal dashboard is not replaced.

## Cross-Phase Data Flow

```text
operator-approved trusted node descriptors
  -> trusted transport session records
  -> signed runtime summary envelopes
  -> synchronization windows
  -> live cluster state updates
  -> distributed event propagation summaries
  -> federation diagnostics
  -> local dashboard/API federation views
```

No step should add untrusted discovery, public internet exposure, cloud sync, background collection without opt-in, remote command execution, router changes, service installation, automatic enforcement, or external export delivery.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, environment files, private keys, tokens, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm new docs are included in package metadata when applicable.
- Confirm examples use sanitized placeholders only.
- Confirm node identifiers are placeholders and not real hostnames.
- Confirm source attribution is present on exchanged and synchronized records.
- Confirm replay-safe fields are present on signed and propagated records.
- Confirm no implementation contacts nodes directly unless explicitly operator-triggered in a later transport phase.

## macOS Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Build a trusted transport session for one master and two workers.
- Create signed summary envelopes with placeholder key references.
- Validate accepted, stale, replayed, malformed, and untrusted envelopes.
- Apply signed summaries to a synchronization window.
- Build distributed event propagation summaries from sanitized local events.
- Build federation diagnostics from fixture transport and sync records.
- Build federation dashboard/API models without starting a web server.
- Confirm no external network calls are required.
- Confirm no real hostnames, usernames, local paths, logs, screenshots, archives, database files, cache files, environment files, runtime artifacts, private keys, tokens, or private validation notes are staged.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Run focused federation tests on the target device.
- Build small trusted transport session records.
- Validate a small set of signed runtime summary envelopes.
- Apply a small synchronization window with low record counts.
- Build distributed event summaries with small fixture event batches.
- Build federation diagnostics with Raspberry Pi resource thresholds.
- Build dashboard/API federation summaries from small fixture inputs.
- Confirm CPU and memory use remain modest.
- Confirm no external network calls are required.
- Confirm no raw payload bytes are stored in public outputs.
- Confirm no private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, private keys, tokens, or private validation notes are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/trusted_node_transport.md`
- `docs/signed_runtime_summary_exchange.md`
- `docs/live_cluster_state_synchronization.md`
- `docs/distributed_event_propagation.md`
- `docs/federation_diagnostics.md`
- `docs/federation_dashboard_api_readiness.md`

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
- Storage or publication of private keys, raw tokens, or raw payload bytes.
