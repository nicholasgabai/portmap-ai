# Phase 87-92 Live Network Telemetry Plan

Milestone O defines the next implementation milestone for transitioning PortMap-AI from coordinated runtime and trusted federation intelligence into real live network telemetry ingestion, passive flow reconstruction, protocol metadata extraction, and dynamic topology correlation.

This is a planning document only. It does not implement collectors, capture packets, start services, open network listeners, change host networking, modify traffic, transmit telemetry externally, or persist runtime data outside explicit operator control.

## Milestone O: Live Network Telemetry

Goal:
Transition PortMap-AI from coordinated runtime/federation intelligence into real live network telemetry ingestion, passive flow reconstruction, protocol metadata extraction, and dynamic topology correlation.

Milestone O should connect the existing event model, runtime pipeline, topology state, federation summaries, review queues, dashboard providers, export bundles, and runtime health primitives to passive live telemetry records.

All work should remain:

- passive-first
- operator-controlled
- advisory by default
- local-first
- Raspberry Pi compatible
- resource-conscious
- testable with sanitized fixtures
- safe for dry-run operation

## Do Not Build In This Milestone

- Inline packet modification.
- MITM functionality.
- Traffic injection.
- Automatic blocking.
- Credential interception.
- Hidden monitoring.
- Persistence outside operator control.
- Kernel drivers.
- External telemetry transmission.
- Router exploitation functionality.
- Automatic firewall or router changes.
- Public internet exposure.
- Background collection without explicit operator opt-in.

## Current Starting Point

Implemented foundation available before Phase 87:

- Local event model, queue, and event bus.
- SQLite-backed storage repositories.
- Runtime sessions, profiles, health, scheduler primitives, recovery, service-readiness previews, and runtime CLI.
- Persistent topology state, snapshot drift detection, and dynamic topology-ready graph/timeline models.
- Runtime pipeline workflow primitives.
- Persistent policy review records and history.
- Dashboard rendering and provider foundations.
- Operational and coordinated export bundle helpers.
- Distributed runtime intelligence, federated topology, cluster health, distributed review, coordinated export, and operator visibility records.
- Trusted federation transport/trust, signed exchange, synchronization, event propagation, diagnostics, runtime manager, peer lifecycle, exchange scheduler, and active federation validation records.

Milestone O should add passive telemetry record models and operator-approved ingestion paths without bypassing safety boundaries.

## Phase 87 - Passive Interface Discovery

Goal:
Build local interface discovery and dry-run capture planning records without capturing packets.

Build:

- `core_engine/telemetry/interfaces.py`
- `core_engine/telemetry/capture_sessions.py`
- `tests/test_passive_interface_discovery.py`
- `docs/passive_interface_discovery.md`

Features:

- Local interface enumeration.
- Interface metadata summaries.
- Capture session models.
- Dry-run capture planning.
- Operator-selected interface targeting.
- Passive-mode enforcement.
- Loopback, broadcast, and multicast classification.
- Resource budget summaries.

Acceptance:

- No packets are captured yet.
- No raw payload bytes are persisted.
- No privileged escalation attempts are made.
- Interface summaries are deterministic for sanitized fixtures.
- Output remains local-only and operator-controlled.

## Phase 88 - Live Packet Ingestion

Goal:
Add bounded packet ingestion windows that convert allowed packet fixtures or operator-approved inputs into metadata-only telemetry summaries.

Build:

- `core_engine/telemetry/ingestion.py`
- `core_engine/telemetry/packet_window.py`
- `tests/test_live_packet_ingestion.py`
- `docs/live_packet_ingestion.md`

Features:

- Bounded packet ingestion windows.
- Packet metadata extraction.
- Transport classification.
- IPv4 and IPv6 support.
- TCP, UDP, and ICMP summaries.
- Packet rate summaries.
- Replay-safe ingestion tracking.
- Dry-run telemetry summaries.

Acceptance:

- Metadata only.
- No payload storage by default.
- Bounded memory usage.
- Deterministic fixture tests.
- No external telemetry transmission.

## Phase 89 - Flow Reconstruction

Goal:
Reconstruct bounded local flow summaries from packet metadata and generate topology-ready flow edges.

Build:

- `core_engine/telemetry/flows.py`
- `core_engine/telemetry/session_tracker.py`
- `tests/test_flow_reconstruction.py`
- `docs/flow_reconstruction.md`

Features:

- Bidirectional flow reconstruction.
- Flow timeout handling.
- Transport and session summaries.
- Ephemeral versus persistent flow classification.
- Service association helpers.
- Flow digest tracking.
- Topology edge generation.
- Local-only flow summaries.

Acceptance:

- Reconstructed flows are deterministic.
- No DPI payload retention.
- Resource behavior remains bounded.
- Malformed flow records are isolated and reported.
- Flow summaries remain advisory and local-only.

## Phase 90 - Protocol Metadata Extraction

Goal:
Extract safe protocol metadata and service fingerprints from allowed telemetry records without credential or content capture.

Build:

- `core_engine/telemetry/protocol_metadata.py`
- `core_engine/telemetry/fingerprints.py`
- `tests/test_protocol_metadata_extraction.py`
- `docs/protocol_metadata_extraction.md`

Features:

- HTTP, TLS, and DNS metadata extraction.
- Service fingerprint summaries.
- Encrypted-session metadata handling.
- Protocol confidence scoring.
- Application-layer hints.
- Safe metadata truncation.
- Metadata governance fields.
- Protocol anomaly summaries.

Acceptance:

- Metadata-only extraction.
- No credential extraction.
- No content persistence.
- Protocol summaries are deterministic.
- Public docs and tests use sanitized placeholders only.

## Phase 91 - Dynamic Topology Correlation

Goal:
Correlate live packet, flow, protocol, and federation-aware summaries into bounded dynamic topology records.

Build:

- `core_engine/telemetry/topology_correlation.py`
- `core_engine/telemetry/live_topology.py`
- `tests/test_dynamic_topology_correlation.py`
- `docs/dynamic_topology_correlation.md`

Features:

- Live node relationship inference.
- Topology drift correlation.
- Active flow edge correlation.
- Temporal topology summaries.
- Node role inference.
- Cluster topology rollups.
- Live federation-aware topology summaries.
- Operator-readable topology health summaries.

Acceptance:

- Topology state remains local-only.
- Graph growth is bounded.
- Updates are replay-safe.
- Test fixtures are deterministic.
- No automatic enforcement or router modification is added.

## Phase 92 - Real-Time Telemetry Dashboard Integration

Goal:
Expose live telemetry summaries through dashboard/API-ready models while preserving existing Textual TUI compatibility.

Build:

- `gui/web/live_telemetry_views.py`
- `core_engine/telemetry/operator_views.py`
- `tests/test_realtime_telemetry_dashboard.py`
- `docs/realtime_telemetry_dashboard.md`

Features:

- Live telemetry summaries.
- Packet and flow rate dashboards.
- Live topology rendering models.
- Interface telemetry summaries.
- Protocol distribution summaries.
- Resource usage telemetry.
- Operator visibility rollups.
- Federation-aware telemetry summaries.

Acceptance:

- Dashboard-safe summaries only.
- No raw payload rendering.
- Update frequency remains bounded.
- Existing TUI compatibility is preserved.
- No web server is started by model builders.

## Cross-Phase Data Flow

```text
operator-selected local interface records
  -> passive capture session plans
  -> bounded packet metadata windows
  -> flow reconstruction summaries
  -> protocol metadata and fingerprints
  -> dynamic topology correlation
  -> live telemetry dashboard/API models
  -> review, export, and federation-aware summaries
```

No step should add inline modification, credential capture, traffic injection, automatic blocking, MITM behavior, kernel drivers, router exploitation, or external telemetry transmission.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, packet captures, archives, database files, cache folders, environment files, runtime artifacts, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm examples use sanitized placeholders only.
- Confirm no raw packet payloads are stored in public fixtures.
- Confirm no automatic enforcement, blocking, injection, MITM, or external telemetry transmission is added.
- Confirm new docs are included in package metadata when applicable.

## macOS Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Run the full test suite in the repo-local environment.
- Build deterministic interface summaries from sanitized fixture records.
- Build dry-run passive capture session plans without starting capture.
- Process bounded packet metadata fixture windows.
- Reconstruct small deterministic flow summaries.
- Extract HTTP, TLS, and DNS metadata from sanitized fixtures only.
- Build dynamic topology correlation summaries.
- Build live telemetry dashboard/API dictionaries without starting a web server.
- Confirm no privileged escalation attempts are made.
- Confirm no external network calls are required.
- Confirm no packet payloads, hostnames, usernames, local paths, logs, screenshots, archives, database files, cache files, environment files, or private validation notes are staged.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Run focused telemetry tests on the target device.
- Build small interface and dry-run capture session summaries.
- Process low-volume packet metadata fixtures.
- Reconstruct flow summaries with low record counts.
- Build protocol metadata summaries with bounded truncation.
- Build dynamic topology summaries with bounded graph size.
- Build dashboard/API telemetry models from small fixture inputs.
- Confirm CPU and memory use remain modest.
- Confirm no privileged capture or escalation is attempted by default.
- Confirm no external network calls are required.
- Confirm no raw payload bytes are stored in public outputs.
- Confirm no private identifiers, packet captures, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/passive_interface_discovery.md`
- `docs/live_packet_ingestion.md`
- `docs/flow_reconstruction.md`
- `docs/protocol_metadata_extraction.md`
- `docs/dynamic_topology_correlation.md`
- `docs/realtime_telemetry_dashboard.md`

Docs must use sanitized placeholders only.
