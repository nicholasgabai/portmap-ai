# Milestone O Integration

Milestone O covers Phases 87-92: Live Network Telemetry. It moves PortMap-AI from coordinated runtime and federation records into passive-first telemetry models, bounded metadata ingestion, flow reconstruction, protocol metadata extraction, dynamic topology correlation, and read-only real-time telemetry dashboard/API summaries.

This milestone remains passive-first, local-first, operator-controlled, advisory by default, metadata-only, bounded, and resource-conscious. It does not add inline packet modification, packet replay, traffic injection, automatic blocking, credential interception, hidden monitoring, kernel drivers, external telemetry transmission, router exploitation, or raw payload persistence.

## Completed Phases

| Phase | Area | Implemented Baseline |
| --- | --- | --- |
| 87 | Passive interface discovery | Local interface summary records, normalized interface metadata, IPv4/IPv6/address-family summaries, loopback/broadcast/multicast capability fields, passive capture session planning records, operator-selected targeting, dry-run capture plans, resource budgets, deterministic serialization, and dashboard/API-ready dictionaries. |
| 88 | Live packet ingestion | Bounded packet ingestion windows, packet metadata records, source/interface attribution, IPv4/IPv6 classification, TCP/UDP/ICMP summaries, packet size and rate summaries, malformed/unsupported classification, replay-safe counters, dry-run ingestion summaries, and dashboard/API-ready dictionaries. |
| 89 | Flow reconstruction | Bidirectional flow records, flow key normalization, session tracking records, timeout handling, ephemeral/persistent classification, service association helpers, flow digest tracking, topology edge generation, malformed/partial flow handling, local-only summaries, and dashboard/API-ready dictionaries. |
| 90 | Protocol metadata extraction | HTTP/TLS/DNS metadata summaries, protocol fingerprint records, service fingerprint summaries, encrypted-session metadata handling, protocol confidence scoring, application-layer hints, safe truncation, governance fields, protocol anomaly summaries, and dashboard/API-ready dictionaries. |
| 91 | Dynamic topology correlation | Live node relationship inference, flow-to-topology edge correlation, protocol-aware topology summaries, topology drift correlation, temporal topology summaries, node role inference, bounded graph growth controls, replay-safe topology update records, cluster/federation-aware summaries, topology health summaries, and dashboard/API-ready dictionaries. |
| 92 | Real-time telemetry dashboard | Live telemetry dashboard summary models, packet and flow rate summaries, live topology rendering summaries, interface telemetry summaries, protocol distribution summaries, resource usage summaries, federation-aware telemetry rollups, telemetry health status summaries, bounded update interval controls, empty/stale-state rendering models, and dashboard/API-ready telemetry dictionaries. |

## Module Map

| Layer | Modules | Role |
| --- | --- | --- |
| Interface discovery | `core_engine.telemetry.interfaces`, `core_engine.telemetry.capture_sessions` | Normalize local interface metadata, summarize address families and capabilities, and plan passive dry-run capture sessions without starting packet capture. |
| Packet ingestion | `core_engine.telemetry.ingestion`, `core_engine.telemetry.packet_window` | Convert operator-provided packet metadata into bounded windows with transport, address-family, size, rate, replay, malformed, unsupported, and dashboard/API summaries. |
| Flow reconstruction | `core_engine.telemetry.flows`, `core_engine.telemetry.session_tracker` | Build bidirectional flow and session records from metadata, classify flow state, associate likely services, generate deterministic digests, and emit topology-ready observed-flow edges. |
| Protocol metadata | `core_engine.telemetry.protocol_metadata`, `core_engine.telemetry.fingerprints` | Extract safe HTTP/TLS/DNS metadata summaries, remove sensitive fields, truncate long values, score confidence, build fingerprints, and report protocol anomalies. |
| Dynamic topology | `core_engine.telemetry.topology_correlation`, `core_engine.telemetry.live_topology` | Correlate flow and protocol summaries into bounded topology graph records, drift summaries, temporal summaries, node roles, replay-safe topology updates, and federation-aware topology dictionaries. |
| Telemetry views | `core_engine.telemetry.operator_views`, `gui.web.live_telemetry_views` | Compose interface, packet, flow, topology, protocol, resource, federation, update-control, empty-state, stale-state, and health panels into read-only dashboard/API models. |

## Integrated Data Flow

```text
operator-selected interface metadata
  -> dry-run passive capture planning
  -> bounded packet metadata windows
  -> bidirectional flow reconstruction
  -> safe protocol metadata and fingerprints
  -> dynamic topology correlation and drift summaries
  -> live telemetry dashboard/API summaries
```

The flow accepts sanitized fixtures or explicit operator-provided metadata. It does not start capture loops, retain payload bytes, replay packets, inject traffic, block traffic, or transmit telemetry externally.

## Connections To Platform Layers

Runtime pipeline:
Milestone O records are shaped for explicit runtime workflows. Packet windows, flow summaries, protocol summaries, live topology summaries, and telemetry dashboard records can be passed into existing dry-run/local-write pipeline wiring without adding background collection.

Event pipeline:
Telemetry summaries preserve event-ready counts, classifications, source references, and safety fields. Future operators can choose which metadata summaries become local events; Milestone O itself does not automatically publish or flush events.

Storage:
Outputs remain JSON-serializable and local-only. They can be stored by existing repositories through explicit local-write workflows, while raw payload bytes remain excluded from public outputs.

Topology state:
Flow reconstruction emits topology-edge-compatible records. Dynamic topology correlation reuses existing topology graph helpers and does not create a parallel topology persistence path.

Snapshot drift:
Live topology records can be compared with baseline graph records to produce advisory drift summaries. Drift output is review-oriented and does not trigger enforcement or network changes.

Federation:
Telemetry records include source and cluster/federation-aware summaries suitable for trusted-node rollups. Milestone O can feed federation diagnostics and operator visibility models, but it does not contact peers or open listeners.

Dashboard/API:
Phase 92 exposes dashboard/API-ready dictionaries for live telemetry panels using existing web rendering conventions. It does not start a web server and does not replace the Textual terminal dashboard.

Operator visibility:
Telemetry rollups can sit alongside distributed runtime, federation, review, export, and service-readiness panels. Empty and stale states are explicit so operators can distinguish no data from old data.

## Safety Boundaries

Milestone O does not add:

- inline packet modification
- packet replay features
- traffic injection
- automatic blocking or enforcement
- credential extraction
- payload content retention
- hidden monitoring
- kernel drivers
- external telemetry transmission
- router exploitation functionality
- replacement of the existing Textual TUI
- parallel storage, topology, or dashboard schemas

## macOS Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Run the full test suite in the repo-local environment.
- Enumerate sanitized interface fixtures and build dry-run capture plans.
- Build bounded packet metadata windows from sanitized records.
- Reconstruct bidirectional flow records and topology edges.
- Build HTTP/TLS/DNS metadata summaries without credential or content retention.
- Build live topology summaries with bounded graph size and replay-safe updates.
- Build real-time telemetry dashboard/API records without starting a web server.
- Confirm no packet capture loop, replay, traffic injection, automatic blocking, or external transmission is started.
- Confirm no real hostnames, usernames, local paths, packet captures, logs, screenshots, archives, database files, cache files, environment files, runtime artifacts, tokens, credentials, or private validation notes are staged.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Run focused telemetry tests on the target device.
- Build small interface inventories and dry-run capture plans.
- Process low-volume packet metadata fixtures with edge-device bounds.
- Reconstruct a small set of flow summaries.
- Build protocol metadata summaries with bounded truncation.
- Build dynamic topology summaries with low node and edge counts.
- Build live telemetry dashboard/API summaries from small fixture inputs.
- Confirm CPU and memory use remain modest.
- Confirm no privileged capture or escalation is attempted by default.
- Confirm no external network calls are required.
- Confirm no raw payload bytes are stored or rendered.
- Confirm no private identifiers, packet captures, logs, screenshots, database files, cache files, environment files, archives, runtime artifacts, credentials, tokens, or private validation notes are staged.

## Next Direction

Recommended next direction: continue the completion roadmap with gateway/router-adjacent modes and production security hardening.

Suggested areas:

- Storage-backed retention policies for selected telemetry metadata.
- Operator CLI/API workflows for live telemetry status and import.
- Router log, SPAN/mirror-port, Raspberry Pi gateway, DNS/flow visibility, and transparent bridge readiness planning.
- Security controls for local authentication, TLS, secure node enrollment, retention, and redaction.
- Raspberry Pi and macOS live validation notes kept private unless scrubbed for public documentation.
