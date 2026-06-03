# Phase 129-134 Deep Network Flow Intelligence Plan

Milestone V extends PortMap-AI from telemetry snapshots and security readiness records into deeper metadata-only flow intelligence. The focus is bidirectional flow reconstruction, packet metadata correlation, cross-node relationship mapping, dynamic application attribution, behavioral drift detection, and topology intelligence.

This is a planning document. It does not inspect packet payloads, store packet payloads, generate PCAPs, require kernel drivers, inject traffic, modify traffic, decrypt traffic, collect credentials, enforce blocking, or transmit telemetry externally.

## Milestone V: Deep Network Flow Intelligence

Goal:
Move from socket and metadata visibility into deeper behavior-aware network intelligence without storing payloads or credentials.

All work should remain:

- local-first
- metadata-only
- advisory by default
- dry-run safe
- source-mode aware
- privacy-preserving
- resource-conscious
- Raspberry Pi/Linux ARM compatible
- macOS/Linux/Windows aware
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 129:

- Live packet metadata ingestion and bounded packet windows.
- Flow reconstruction from packet metadata.
- Flow telemetry enrichment.
- Process and service attribution.
- DNS visibility and destination behavior learning.
- Dynamic topology correlation.
- Behavioral baselines, anomalies, service fingerprints, adaptive risk, and long-term intelligence summaries.
- Distributed runtime federation, trusted transport readiness, and Milestone U security foundation records.

## Phase 129 - Bidirectional Flow Reconstruction

Status: Complete Baseline

Goal:
Introduce bidirectional flow reconstruction and session-aware relationship modeling so PortMap-AI can correlate ingress/egress socket observations into normalized flow sessions without performing packet payload inspection.

Build:

- `core_engine/flows/session_tracking.py`
- `core_engine/flows/flow_reconstruction.py`
- `core_engine/flows/__init__.py`
- `tests/test_bidirectional_flow_reconstruction.py`
- `docs/bidirectional_flow_reconstruction.md`

Features:

- Normalized session tracking records.
- Inbound, outbound, local-loopback, and unknown-direction support.
- Process and service attribution fields.
- Source-mode preservation.
- Active, transient, recurring, dormant, and unknown session states.
- Flow pairs, flow relationships, inferred sessions, transient sessions, and recurring sessions.
- Relationship strength, recurrence score, drift detection, reconstruction confidence, and session classification.
- Dashboard/API/export-safe dictionaries.
- Metadata-only safety fields.

Acceptance:

- Inbound, outbound, and loopback reconstruction works with sanitized fixtures.
- Repeated socket observations normalize deterministically.
- Transient and recurring session classification is deterministic.
- Relationship strength and reconstruction confidence are bounded.
- Source mode is preserved.
- No packet payload inspection, packet payload storage, PCAP generation, DPI, credential storage, or automatic enforcement is added.

## Phase 130 - Packet Metadata Correlation

Goal:
Correlate process, destination, protocol, flow, timing, and topology metadata into unified relationship evidence records.

Build:

- `core_engine/flows/packet_correlation.py`
- `core_engine/flows/metadata_relationships.py`
- `tests/test_packet_metadata_correlation.py`
- `docs/packet_metadata_correlation.md`

Features:

- Packet metadata correlation records.
- Flow-to-process and flow-to-service evidence links.
- Destination and DNS timing correlation.
- Protocol hint correlation.
- Source-mode-aware confidence scoring.
- Export-safe relationship dictionaries.

Acceptance:

- Correlation is deterministic for sanitized fixtures.
- Missing or malformed records are isolated.
- No payload inspection or PCAP generation is added.

## Phase 131 - Cross-Node Relationship Mapping

Goal:
Map metadata-only relationships across trusted local nodes while preserving node attribution and source confidence.

Build:

- `core_engine/flows/cross_node_relationships.py`
- `core_engine/flows/node_relationship_index.py`
- `tests/test_cross_node_relationship_mapping.py`
- `docs/cross_node_relationship_mapping.md`

Features:

- Cross-node flow relationship records.
- Master/worker/orchestrator relationship summaries.
- Source node attribution.
- Recurring path summaries.
- Lateral relationship hints.
- Federated topology hooks.

Acceptance:

- Node attribution survives all merge steps.
- Conflicts and stale nodes are reported.
- No remote probing or command execution is added.

## Phase 132 - Dynamic Application Attribution

Goal:
Replace static labels with probabilistic metadata-only application attribution, confidence models, and continuous learning support.

Build:

- `core_engine/flows/application_attribution.py`
- `core_engine/flows/application_profiles.py`
- `tests/test_dynamic_application_attribution.py`
- `docs/dynamic_application_attribution.md`

Features:

- Application attribution profiles.
- Browser, SSH client, database, update agent, remote access, cloud sync, and unknown behavior hints.
- Confidence and evidence summaries.
- Source-mode-aware attribution.
- Safe unknown/unattributed fallbacks.

Acceptance:

- Attribution uses metadata-only evidence.
- No command-line secrets or payload contents are stored.
- Low-confidence attribution remains explicit.

## Phase 133 - Behavioral Drift Detection

Goal:
Detect environment drift, evolving anomalies, and deviations from historical baselines using metadata-only relationship records.

Build:

- `core_engine/flows/behavioral_drift.py`
- `core_engine/flows/drift_windows.py`
- `tests/test_flow_behavioral_drift.py`
- `docs/flow_behavioral_drift.md`

Features:

- Flow drift records.
- Relationship novelty scoring.
- Recurring path drift.
- Service/process attribution drift.
- DNS/destination drift links.
- Advisory drift explanations.

Acceptance:

- Drift output is deterministic and advisory-only.
- Historical baselines remain metadata-only.
- No enforcement or blocking is added.

## Phase 134 - Network Topology Intelligence

Goal:
Infer trust zones, subnet relationships, service dependencies, and adaptive topology models from metadata-only flow intelligence.

Build:

- `core_engine/flows/topology_intelligence.py`
- `core_engine/flows/trust_zones.py`
- `tests/test_network_topology_intelligence.py`
- `docs/network_topology_intelligence.md`

Features:

- Trust-zone inference summaries.
- Service dependency records.
- Adaptive topology confidence scoring.
- Flow-derived topology relationship rollups.
- Dashboard/API/export-safe topology intelligence dictionaries.

Acceptance:

- Topology intelligence remains advisory and local-only.
- Bounded graph growth is preserved.
- No network scanning, traffic injection, or enforcement is added.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no packet payloads, PCAPs, logs, screenshots, archives, database files, cache folders, runtime artifacts, environment files, credentials, certs, keys, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm public docs use sanitized placeholders only.
- Confirm source-mode labels are preserved.
- Confirm no payload inspection, kernel driver requirement, automatic enforcement, or external telemetry transmission is added.

## macOS Validation Checklist

- Run the full suite from the Mac source-of-truth repo.
- Build bidirectional flow summaries from sanitized socket fixtures.
- Validate source-mode preservation.
- Validate dashboard/API/export serialization.
- Confirm no local private artifacts are staged.

## Raspberry Pi/Linux ARM Validation Checklist

- Pull only after Mac push succeeds.
- Run focused flow intelligence tests on constrained hardware.
- Build small bidirectional session summaries.
- Confirm CPU and memory use remain modest.
- Confirm no payloads, PCAPs, logs, screenshots, runtime databases, private paths, credentials, certs, or keys are staged.

## Windows Compatibility Fixture Checklist

- Validate Windows-style socket fixture records without hostnames or usernames.
- Confirm degraded or unknown states remain explicit.
- Confirm path, service, process, and source-mode fields serialize safely.
- Confirm no driver, capture, firewall, service, registry, or installer action is performed.

## Do Not Build In This Milestone

- Packet payload inspection.
- Payload storage.
- PCAP generation.
- Kernel drivers.
- Traffic injection.
- MITM behavior.
- Credential collection.
- Automatic blocking.
- Router or firewall modification.
- External telemetry transmission.
