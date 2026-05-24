# Milestone M Integration

Milestone M covers Phases 77-82: Trusted Runtime Transport and Live Federation. It moves the distributed-ready summaries from Milestone L into trusted federation records for operator-approved local nodes.

This milestone remains local-first, trusted-node scoped, operator-approved, advisory by default, source-attributed, replay-safe, and read-only unless a later explicit local workflow says otherwise. It does not add untrusted discovery, public exposure, live network listeners, remote command execution, cloud sync, automatic remediation, service installation, or external export delivery.

## Completed Phases

| Phase | Area | Implemented Baseline |
| --- | --- | --- |
| 77 | Trusted node transport models | Local trust profiles, approved peer records, trusted transport session records, handshake summaries, expiration timestamps, trust scopes, replay-window metadata, and deterministic transport JSON. |
| 78 | Signed runtime summary exchange | Canonical JSON, deterministic digests, signed runtime summary envelopes, signature metadata, signing and verification status records, trusted peer validation hooks, replay-window hooks, and exchange-ready summary records. |
| 79 | Live cluster state synchronization | Synchronization windows, signed update envelopes, accepted/rejected/stale/replayed classifications, per-node last-seen tracking, conflict and drift summaries, merged cluster state, and dashboard/API-ready sync status records. |
| 80 | Distributed event propagation | Distributed event envelopes, event propagation windows, source node attribution, sequence numbers, event digests, replay validation, signed exchange verification integration, event batch summaries, and cluster event rollups. |
| 81 | Federation diagnostics | Trusted peer, transport session, signed exchange, synchronization window, event propagation, replay-window, distributed runtime, readiness score, recommendation, local event, and dashboard/API diagnostic records. |
| 82 | Federation dashboard/API readiness | Read-only federation dashboard and API view models for trusted peers, transport sessions, signed exchanges, sync windows, distributed events, diagnostics, readiness, counters, and empty states. |

## Module Map

| Layer | Modules | Role |
| --- | --- | --- |
| Trust and Transport | `core_engine.federation.trust`, `core_engine.federation.transport` | Build approved peer records, local trust profiles, transport session metadata, handshake summaries, and replay-window metadata without opening listeners. |
| Signed Exchange | `core_engine.federation.signing`, `core_engine.federation.exchange` | Build canonical JSON digests, signature metadata, signed runtime summary envelopes, and verification records for trusted summary exchange. |
| Live Sync | `core_engine.federation.synchronization`, `core_engine.federation.cluster_state` | Classify signed updates, maintain synchronization windows, track per-node last-seen state, report conflicts and drift, and produce merged cluster summaries. |
| Event Federation | `core_engine.federation.event_window`, `core_engine.federation.event_propagation` | Wrap local events in trusted exchange envelopes, classify propagation records, summarize event batches, and produce cluster event rollups. |
| Diagnostics | `core_engine.federation.health`, `core_engine.federation.diagnostics` | Summarize federation readiness, transport health, signature verification, replay-window status, distributed runtime state, recommendations, and local health events. |
| Dashboard/API Views | `core_engine.federation.operator_views`, `gui.web.federation_views` | Convert trusted federation records into read-only dashboard panels and local API-compatible dictionaries without replacing the Textual TUI. |

## Integrated Data Flow

```text
operator-approved trusted node descriptors
  -> trusted transport session records
  -> signed runtime summary envelopes
  -> synchronization windows
  -> live cluster state update classifications
  -> distributed event propagation summaries
  -> federation diagnostics
  -> local dashboard/API federation views
```

Every step consumes already-provided trusted-node records or local event objects. No step discovers nodes, starts listeners, contacts peers directly, writes service files, modifies routers, or executes remote commands.

## Connections To Platform Layers

Node identity:
Trusted transport and signed exchange records reuse existing node identity references, node IDs, roles, labels, capabilities, and source references. Milestone M does not create a parallel node identity schema.

Distributed runtime state:
Signed summaries carry runtime, health, topology, review, export, and service-readiness payloads that can feed distributed runtime state and operator visibility records while preserving source attribution.

Signed summaries:
Phase 78 establishes canonical JSON, digest, signature metadata, verification status, sequence, nonce, and replay-window fields. Later synchronization and event propagation phases consume those same envelope records.

Cluster sync:
Live synchronization windows classify signed summaries as accepted, rejected, stale, replayed, untrusted, or malformed. Accepted updates feed deterministic merged cluster state summaries; rejected updates remain reviewable conflict records.

Event propagation:
Distributed event envelopes reuse the local event model and signed exchange verification path. Accepted records are local event storage-ready, while rejected, duplicate, stale, malformed, and untrusted records preserve source node attribution.

Federation diagnostics:
Diagnostics summarize trusted peer health, transport session readiness, signed exchange verification, synchronization counters, distributed event counters, replay-window status, distributed runtime health, and readiness score.

Dashboard/API readiness:
Federation operator views expose local API-compatible dictionaries and lightweight web sections for trusted peers, transport sessions, signed exchanges, sync windows, event propagation, diagnostics, readiness, and stale/rejected/duplicate counters. They do not start a server or replace the Textual terminal dashboard.

## Safety Boundaries

Milestone M does not add:

- untrusted node discovery
- public internet exposure
- live network listeners
- background collection without explicit operator opt-in
- remote command execution
- automatic remediation or enforcement
- router or firewall modification
- service installation, enablement, or startup
- cloud synchronization
- external export delivery
- storage or publication of private signing material
- replacement of the Textual terminal dashboard

## macOS Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Run the full test suite in the repo-local environment.
- Build trusted transport session records for one placeholder master and worker.
- Create signed runtime summary envelopes with placeholder key references.
- Validate accepted, stale, replayed, malformed, and untrusted envelopes.
- Apply signed summaries to a synchronization window.
- Build distributed event propagation summaries from sanitized local events.
- Build federation diagnostics from fixture transport, sync, and event records.
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
- Build federation diagnostics using Raspberry Pi resource thresholds.
- Build dashboard/API federation summaries from small fixture inputs.
- Confirm CPU and memory use remain modest.
- Confirm no external network calls are required.
- Confirm no raw payload bytes are stored in public outputs.
- Confirm no private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, private keys, tokens, or private validation notes are staged.

## Next Direction

Recommended next direction: federation operational hardening and local operator experience.

Suggested areas:

- Storage-backed history for selected federation sessions, exchanges, sync windows, and diagnostics.
- Local API provider endpoints for federation status dictionaries.
- Dashboard panels for stale, rejected, duplicate, and replayed federation records.
- Manual trusted-node import/export workflows.
- Operator-controlled transport execution only after explicit safety review.
- Raspberry Pi validation notes kept private unless scrubbed for public documentation.
