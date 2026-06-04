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

Status: Complete Baseline

Goal:
Add metadata-only packet/flow correlation models that connect packet-derived metadata, socket observations, process/service attribution, DNS/destination behavior, and reconstructed flow sessions without inspecting payload contents or storing raw packets.

Build:

- `core_engine/flows/metadata_correlation.py`
- `core_engine/flows/process_correlation.py`
- `tests/test_packet_metadata_correlation.py`
- `docs/packet_metadata_correlation.md`

Features:

- Metadata correlation records connecting packet metadata, socket observations, reconstructed sessions, DNS/destination behavior, protocol metadata, and topology relationships.
- Correlated, partially-correlated, uncorrelated, conflicting, and unknown states.
- Source-mode preservation across live, simulated, fixture, replay, and unknown inputs.
- Session and flow reference preservation.
- DNS and topology correlation states.
- Process/service attribution correlation records.
- Unknown and Unattributed live fallbacks for unresolved attribution.
- Fixture/simulated-only demo labels.
- Metadata confidence scoring.
- Dashboard/API/export-safe dictionaries.

Acceptance:

- Correlation is deterministic for sanitized fixtures.
- Missing or malformed records are isolated.
- Source modes are preserved.
- `dummy_app` and `dummy_db` remain fixture/simulated-only.
- No payload inspection, raw packet storage, raw DNS browsing-history logging, PCAP generation, DPI, credential storage, or automatic enforcement is added.

## Phase 131 - Cross-Node Relationship Mapping

Status: Complete Baseline

Goal:
Introduce cross-node relationship mapping and lateral relationship inference so PortMap-AI can model node-to-node communication patterns, shared service relationships, recurring peer interactions, and topology adjacency without requiring payload inspection or centralized packet capture.

Build:

- `core_engine/topology/relationship_graphs.py`
- `core_engine/topology/lateral_analysis.py`
- `tests/test_cross_node_relationship_mapping.py`
- `docs/cross_node_relationship_mapping.md`

Features:

- Normalized node relationship graph records.
- Orchestrator, master, worker, edge, external, and unknown node classes.
- Active, recurring, transient, dormant, and unknown relationship states.
- Flow and session references.
- Shared service states.
- Recurring interaction scoring.
- Topology distance handling.
- Relationship strength and confidence scoring.
- Lateral relationship analysis with expected, unusual, suspicious, isolated, and unknown states.
- Dashboard/API/export-safe dictionaries.

Acceptance:

- Cross-node relationships are deterministic for sanitized fixtures.
- Recurring peer interaction scoring is bounded.
- Transient and recurring relationships classify predictably.
- Source mode is preserved.
- Lateral analysis remains advisory and does not produce threat verdicts.
- No payload inspection, packet storage, graph database dependency, enforcement logic, threat verdict engine, remote probing, or command execution is added.

## Phase 132 - Dynamic Application Attribution

Status: Complete Baseline

Goal:
Introduce metadata-only dynamic application attribution models so PortMap-AI can infer probable application/service identities from process hints, service hints, protocol metadata, destination behavior, flow/session behavior, and recurring behavioral signatures without relying on dummy labels, payload inspection, or hardcoded live identities.

Build:

- `core_engine/attribution/probabilistic_apps.py`
- `core_engine/attribution/signature_learning.py`
- `core_engine/attribution/confidence_models.py`
- `core_engine/attribution/__init__.py`
- `tests/test_dynamic_application_attribution.py`
- `docs/dynamic_application_attribution.md`

Features:

- Probable application attribution records.
- Multiple candidates per observation.
- Generic candidate app and service classes.
- Process, service, protocol, destination, flow, and recurrence confidence scoring.
- Conflict penalties.
- Metadata-only behavioral signature records.
- Recurring port, protocol, destination, timing, process/service, and flow relationship patterns.
- Source-mode-aware attribution.
- Unknown and Unattributed live fallbacks.
- Fixture/simulated-only demo labels.
- Dashboard/API/export-safe dictionaries.

Acceptance:

- Attribution uses metadata-only evidence.
- Confidence scores are bounded and deterministic.
- Strong repeated metadata signals increase confidence.
- Conflicting signals reduce confidence.
- Live/default unresolved attribution remains Unknown or Unattributed.
- `dummy_app` and `dummy_db` remain fixture/simulated-only.
- No payload inspection, packet storage, PCAP generation, raw DNS browsing-history storage, host/IP/user/MAC identifier storage, hardcoded fake live app labels, or automatic enforcement is added.

## Phase 133 - Behavioral Drift Detection

Status: Complete Baseline

Goal:
Detect gradual and sudden changes in learned network, service, application, flow, destination, and topology behavior by comparing current observations against historical baselines without generating threat verdicts or enforcement actions.

Build:

- `core_engine/behavior/drift_detection.py`
- `core_engine/behavior/environment_drift.py`
- `core_engine/behavior/__init__.py`
- `tests/test_behavioral_drift_detection.py`
- `docs/behavioral_drift_detection.md`

Features:

- Behavioral drift records for application, service, destination, flow, topology, and protocol behavior.
- Baseline and current observation references.
- Stable, minor drift, moderate drift, major drift, and unknown states.
- Drift score, severity, recurrence state, confidence score, source mode, and advisory notes.
- Evidence summaries that compare metadata-only baseline and current scores, frequencies, and labels.
- Environment drift aggregation with affected categories, stability score, drift trend, recurring change detection, unusual change detection, confidence score, and operator summaries.
- Dashboard/API/export-safe dictionaries.
- Explicit safety fields for no payload inspection, no raw packet storage, no raw DNS browsing history, no threat verdicts, and no enforcement.

Acceptance:

- Stable and drifted behavior classify deterministically with sanitized fixtures.
- Drift and confidence scores remain bounded.
- Recurring changes are reported separately from one-off drift.
- Environment summaries aggregate multiple drift records without producing threat verdicts.
- Malformed baseline or comparison input is isolated with structured errors.
- Source mode is preserved.
- No payload inspection, packet storage, PCAP generation, credential storage, threat verdict engine, or automatic enforcement is added.

## Phase 134 - Network Topology Intelligence

Status: Complete Baseline

Goal:
Infer trust zones, service dependencies, topology adjacency, and network structure intelligence from historical observations, reconstructed flows, and cross-node relationships.

Build:

- `core_engine/topology/trust_zones.py`
- `core_engine/topology/dependency_mapping.py`
- `tests/test_network_topology_intelligence.py`
- `docs/network_topology_intelligence.md`

Features:

- Internal, management, service, external, and unknown trust-zone inference.
- Trust-zone records with relationship counts, confidence scores, drift flags, source modes, and advisory notes.
- Service dependency, recurring communication chain, node dependency, topology adjacency, management dependency, external dependency, and unknown dependency records.
- Relationship strength, recurrence score, confidence score, topology distance, source mode, and advisory notes.
- Topology adjacency classification from normalized relationship records.
- Dashboard/API/export-safe trust-zone and dependency dictionaries.
- Metadata-only safety fields for no payload inspection, no packet storage, no graph database dependency, and no enforcement.

Acceptance:

- Trust-zone inference is deterministic for sanitized relationship fixtures.
- Dependency mapping and topology adjacency classify predictably.
- Relationship and confidence scores remain bounded.
- Malformed topology inputs are isolated with structured errors.
- Source mode is preserved.
- Topology intelligence remains advisory and local-only.
- No payload inspection, packet storage, PCAP generation, active probing, graph database dependency, traffic injection, or enforcement is added.

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
