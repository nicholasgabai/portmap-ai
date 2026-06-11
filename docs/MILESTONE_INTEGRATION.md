# Milestone Integration

This document is the consolidated integration guide for the completed Phase 44-152 milestone work and the pre-Milestone W Milestone V live runtime bridge. It replaces the phase-specific planning docs as the primary implementation map. Archived planning files remain under `docs/archive/` for historical reference, `docs/MILESTONE_J_INTEGRATION.md` provides the detailed Phase 59-64 integration summary, `docs/MILESTONE_K_INTEGRATION.md` provides the detailed Phase 65-70 integration summary, `docs/MILESTONE_L_INTEGRATION.md` provides the detailed Phase 71-76 integration summary, `docs/MILESTONE_M_INTEGRATION.md` provides the detailed Phase 77-82 integration summary, `docs/MILESTONE_N_INTEGRATION.md` provides the detailed Phase 83-86 integration summary, `docs/MILESTONE_O_INTEGRATION.md` provides the detailed Phase 87-92 integration summary, `docs/MILESTONE_P_INTEGRATION.md` provides the detailed Phase 93-98 integration summary, `docs/MILESTONE_Q_INTEGRATION.md` provides the detailed Phase 99-104 integration summary, `docs/MILESTONE_R_INTEGRATION.md` provides the detailed Phase 105-110 integration summary, `docs/MILESTONE_S_INTEGRATION.md` provides the detailed Phase 111-116 integration summary, `docs/MILESTONE_T_INTEGRATION.md` provides the detailed Phase 117-122 integration summary, `docs/MILESTONE_U_INTEGRATION.md` provides the detailed Phase 123-128 integration summary for security foundation and trusted runtime work, `docs/MILESTONE_V_INTEGRATION.md` provides the detailed Phase 129-134 integration summary for deep network flow intelligence, `docs/MILESTONE_W_INTEGRATION.md` provides the detailed Phase 135-140 integration summary for autonomous response and policy engine work, `docs/MILESTONE_X_INTEGRATION.md` provides the detailed Phase 141-146 integration summary for visual intelligence layer work, and `docs/MILESTONE_Y_INTEGRATION.md` provides the detailed Phase 147-152 integration summary for threat intelligence and detection expansion. The live bridge is documented in `docs/milestone_v_live_runtime_integration.md`.

This is documentation summary only. It does not add runtime behavior, start services, execute plugins automatically, open relay listeners, install service units, transmit data externally, or modify host configuration.

The integration posture remains local-first, operator-controlled, read-only by default, bounded, auditable, and suitable for lightweight Linux and Raspberry Pi deployments.

The remaining end-to-end completion path is tracked in `docs/COMPLETION_ROADMAP.md`, covering production hardening, future installer/executable packaging, AI security intelligence, commercial readiness, and deeper gateway/router-adjacent operation beyond the current readiness layer. The extended production-launch roadmap from Milestone U through commercial launch readiness is tracked in `docs/PORTMAP_AI_FINAL_ROADMAP.md`. Milestone R integration is summarized in `docs/MILESTONE_R_INTEGRATION.md`, Milestone S integration is summarized in `docs/MILESTONE_S_INTEGRATION.md`, Milestone T integration is summarized in `docs/MILESTONE_T_INTEGRATION.md`, Milestone U integration is summarized in `docs/MILESTONE_U_INTEGRATION.md`, Milestone V integration is summarized in `docs/MILESTONE_V_INTEGRATION.md`, Milestone W integration is summarized in `docs/MILESTONE_W_INTEGRATION.md`, Milestone X integration is summarized in `docs/MILESTONE_X_INTEGRATION.md`, Milestone Y integration is summarized in `docs/MILESTONE_Y_INTEGRATION.md`, Milestone W planning is tracked in `docs/PHASE_135_140_PLAN.md`, Milestone X planning is tracked in `docs/PHASE_141_146_PLAN.md`, Milestone Y planning is tracked in `docs/PHASE_147_152_PLAN.md`, and Milestone Z planning is tracked in `docs/PHASE_153_158_PLAN.md`.

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
| Live Network Telemetry | 87-92 | Passive interface discovery, dry-run capture planning, bounded packet metadata windows, transport summaries, replay-safe counters, bidirectional flow reconstruction, service association, topology edges, protocol metadata, fingerprints, confidence scoring, anomaly summaries, dynamic topology correlation, bounded graph controls, replay-safe updates, real-time telemetry dashboard models, and API-ready dictionaries | Complete baseline |
| Gateway and Telemetry Enrichment | 93-98 | Flow telemetry enrichment, process/service attribution, DNS visibility, gateway/router log ingestion, SPAN/mirror-port readiness, gateway mode validation, export-ready summaries, supported/degraded/unavailable/unsafe states, and dashboard/API-ready dictionaries | Complete baseline |
| Cross-Platform Runtime Hardening | 99-104 | Runtime detection, Windows compatibility, packet capture readiness, firewall provider readiness, filesystem/export safety, unified validation summaries, CLI/table/JSON-ready output, and dashboard/API-ready compatibility dictionaries | Complete baseline |
| Behavioral Intelligence Foundation | 105-110 | Historical flow baselines, temporal anomaly windows, service behavior fingerprints, DNS/destination behavior learning, adaptive risk weighting, unified operator summaries, operator explanations, export-ready digests, and dashboard/API-ready dictionaries | Complete baseline |
| Historical Persistence and Long-Term Intelligence | 111-116 | Historical snapshot persistence, baseline aging and decay, long-term topology evolution, historical replay windows, resource-aware retention, long-term intelligence operator summaries, export-ready digests, and dashboard/API-ready dictionaries | Complete baseline |
| Operationalization and Deployment Foundation | 117-122 | Production runtime profiles, service lifecycle readiness, deployment manifests, upgrade and migration readiness, backup and restore planning, deployment operator summaries, release-readiness checklists, and dashboard/API-ready dictionaries | Complete baseline |
| Security Foundation and Trusted Runtime | 123-128 | Secure logical node identity, worker enrollment previews, trust-chain summaries, identity regeneration and rotation previews, transport security profiles, downgrade warnings, session negotiation previews, secure configuration profiles, secret-management previews, RBAC roles, permission evaluation previews, integrity target records, tamper detection previews, update verification records, rollback preview plans, export-safe safety fields, and no raw hardware identifier, certificate, private key, listener, live auth exchange, OS keychain integration, key generation, secret exchange, user database, credential storage, privileged enrollment, file watching, private-file hashing, blocking, quarantine, deletion, restore, overwrite, installer execution, downloads, live signature trust, migration execution, or config modification behavior | Complete baseline |
| Deep Network Flow Intelligence | 129-134 | Bidirectional flow reconstruction, normalized session tracking, inbound/outbound/local-loopback direction inference, source-mode preservation, flow pairs, flow relationships, packet/socket/session/DNS/protocol/process/service/topology correlation records, cross-node relationship graphs, recurring peer interaction scoring, topology distance, advisory lateral analysis, dynamic generic application/service candidates, metadata-only behavioral signatures, confidence scoring, live Unknown/Unattributed fallbacks, fixture/simulated-only demo labels, behavioral drift records, baseline/current references, environment drift aggregation, trust-zone inference, dependency mapping, topology adjacency, recurrence state, reconstruction confidence, relationship strength, and no payload inspection, raw packet storage, PCAP generation, graph database dependency, threat verdict engine, hardcoded live identity, DPI, credential storage, raw DNS browsing-history logging, active probing, or automatic enforcement | Complete baseline |
| Autonomous Response and Policy Engine | 135-140 | Policy runtime records, in-memory and fixture-safe JSON bundle loading, validation records, disabled-policy normalization, advisory evaluation against telemetry, flow, attribution, drift, topology, and runtime context, adaptive remediation recommendations, escalation previews, quarantine/isolation provider readiness, sanitized command previews, containment preview records, risk escalation pipelines, incident candidates, safety guardrails, rollback simulations, approval gates, autonomous enforcement mode models, autonomy controls, export-safe dictionaries, containment disabled, and no firewall, quarantine, service, process, rollback, backup, restore, credential, payload inspection, subprocess, final threat verdict, or live enforcement behavior | Complete baseline |
| Visual Intelligence Layer | 141-146 | Visualization-model-only topology graphs, bounded graph exports, historical timeline windows, asset inventory intelligence, risk dashboard cards and panels, multi-node fleet visibility, visualization operator summaries, readiness checks, source-mode preservation, export-safe dictionaries, and no browser UI, remote control, live enforcement, firewall/process/service changes, remediation execution, packet payload storage, raw DNS history, private identifier export, cloud sync, or runtime database writes | Complete baseline |
| Threat Intelligence and Detection Expansion | 147-152 | Metadata-only IOC records, bounded inventories, local matching, hash-only exports, DNS domain pattern records, resolver behavior summaries, IOC match integration, DNS analytics state rollups, local signature records, deterministic signature matching, AI correlation evidence chains, advisory threat scoring, local hunt query records, composite signal support, source-mode preservation, export-safe dictionaries, and no external lookups, remote feeds, external AI calls, malicious flags, final threat verdicts, blocking, enforcement, raw DNS history, packet payload storage, or private identifier export | Complete baseline |

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
| Flow Reconstruction | `core_engine.telemetry.flows`, `core_engine.telemetry.session_tracker` | Reconstruct bidirectional metadata-only flows, split sessions by timeout, classify complete/partial/malformed flow state, associate likely services, emit flow digests, and generate topology-ready observed-flow edges. |
| Protocol Metadata Extraction | `core_engine.telemetry.protocol_metadata`, `core_engine.telemetry.fingerprints` | Summarize safe HTTP, TLS, and DNS metadata fields, remove sensitive fields, truncate long metadata, build protocol fingerprints, score confidence, report protocol anomalies, and emit dashboard/API-ready dictionaries. |
| Dynamic Topology Correlation | `core_engine.telemetry.topology_correlation`, `core_engine.telemetry.live_topology` | Correlate metadata-only flow and protocol records into bounded live topology graphs, infer node relationships and roles, compare optional baseline drift, emit replay-safe update records, and produce cluster/federation-aware dashboard/API dictionaries. |
| Real-Time Telemetry Views | `core_engine.telemetry.operator_views`, `gui.web.live_telemetry_views` | Compose interface, packet, flow, topology, protocol, resource, federation, update-control, empty-state, stale-state, and health summaries into read-only dashboard/API-ready live telemetry dictionaries. |
| Flow Telemetry Enrichment | `core_engine.telemetry.flow_enrichment`, `core_engine.telemetry.flow_observations` | Add metadata-only rolling counters, endpoint scope, direction, service hints, state transitions, confidence scores, quality flags, and dashboard/API-ready summaries to reconstructed flows. |
| Process and Service Attribution | `core_engine.telemetry.process_attribution`, `core_engine.telemetry.service_attribution` | Correlate minimized process/socket metadata to enriched flows and service names while preserving permission-safe and unsupported-platform degraded states. |
| DNS Visibility | `core_engine.telemetry.dns_visibility`, `core_engine.telemetry.dns_correlation` | Build DNS query/response metadata, domain-to-flow correlations, resolver classifications, timing/error summaries, encrypted DNS limitations, anomaly hints, and safe redaction controls. |
| Gateway Router Logs | `core_engine.gateway.router_logs`, `core_engine.gateway.log_parsers` | Parse sanitized router/firewall fixtures into metadata-only NAT, allow, deny, malformed, runtime-event, topology, export, dashboard, and API summaries. |
| Gateway Readiness | `core_engine.gateway.mirror_profiles`, `core_engine.gateway.span_readiness`, `core_engine.gateway.validation`, `core_engine.gateway.operator_views` | Build SPAN/mirror-port readiness records and aggregate telemetry, DNS, router log, topology, runtime, and operator visibility records into gateway validation summaries. |
| Cross-Platform Runtime Detection | `core_engine.platform.runtime_detection`, `core_engine.platform.capabilities` | Normalize platform family, architecture, Python version, permission state, and runtime, capture, firewall, service, path, and export capability placeholders. |
| Windows Compatibility | `core_engine.platform.windows_runtime`, `core_engine.platform.windows_paths` | Build Windows-safe path, process/socket visibility, permission, service-preview, runtime profile, fallback, and dashboard/API summaries without changing host state. |
| Cross-Platform Capture Readiness | `core_engine.platform.capture_readiness`, `core_engine.platform.capture_backends` | Summarize passive capture backend readiness, platform limitations, permission requirements, and raw-payload safety boundaries without starting capture. |
| Cross-Platform Firewall Readiness | `core_engine.platform.firewall_readiness`, `core_engine.platform.firewall_providers` | Build dry-run firewall provider previews and operator review records for Windows, macOS, Linux, and Raspberry Pi without applying rules. |
| Filesystem and Export Safety | `core_engine.platform.filesystem_safety`, `core_engine.platform.export_paths` | Classify safe paths, private files, runtime artifacts, export targets, and public documentation safety for cross-platform workflows. |
| Cross-Platform Validation | `core_engine.platform.validation_summary`, `core_engine.platform.operator_views` | Aggregate platform, capture, firewall, filesystem, export, gateway, service, and runtime health records into CLI/table/JSON and dashboard/API-ready compatibility summaries. |
| Historical Flow Baselines | `core_engine.telemetry.behavior_baselines`, `core_engine.telemetry.baseline_windows` | Build rolling metadata-only behavior baselines for ports, protocols, services, process/service fingerprints, flow tuple digests, and DNS/domain observations with bounded windows, stable/new classification, confidence scoring, dashboard/API summaries, and export-ready digests. |
| Temporal Anomaly Windows | `core_engine.telemetry.temporal_anomalies`, `core_engine.telemetry.anomaly_windows` | Build short, medium, and long anomaly windows with burst, rare service timing, volume drift, novelty labels, advisory confidence scoring, operator explanations, dashboard/API dictionaries, and export-ready digests. |
| Service Behavior Fingerprints | `core_engine.telemetry.service_fingerprints`, `core_engine.telemetry.fingerprint_profiles` | Build recurring metadata-only service profiles for process, service, protocol, port, transport, flow role, redacted DNS-summary, platform, interface, and direction combinations with unusual combination labels, dormant service return tracking, confidence scoring, dashboard/API summaries, and export-ready digests. |
| DNS and Destination Behavior Learning | `core_engine.telemetry.dns_behavior`, `core_engine.telemetry.destination_learning` | Build recurring DNS and destination profiles with redacted or hashed domains, resolver hashes, destination placeholders, novelty and drift hints, unusual resolver labels, confidence scoring, dashboard/API summaries, and export-ready digests. |
| Adaptive Risk Weighting | `core_engine.telemetry.adaptive_risk`, `core_engine.telemetry.risk_weights` | Adjust advisory scores using local baseline, anomaly, service fingerprint, and DNS/destination behavior context with confidence dampening, no-enforcement explanations, dashboard/API summaries, and export-ready digests. |
| Behavioral Intelligence Operator Summary | `core_engine.telemetry.behavior_summary`, `core_engine.telemetry.behavior_operator_views` | Roll up behavior baselines, temporal anomalies, service fingerprints, DNS/destination learning, and adaptive risk into supported/degraded/unavailable states, recommendations, explanations, dashboard/API views, and export-ready digests. |
| Historical Snapshot Persistence | `core_engine.history.snapshots`, `core_engine.history.snapshot_store` | Build metadata-only historical snapshots, bounded stores, rotation helpers, malformed input handling, dashboard/API summaries, and export-safe snapshot digests. |
| Baseline Aging and Decay | `core_engine.history.aging_policies`, `core_engine.history.baseline_decay` | Apply safe local aging policies to baselines, service fingerprints, and destination behavior with inactive, stale, dormant, maturity, explanation, dashboard/API, and export summaries. |
| Long-Term Topology Evolution | `core_engine.history.relationship_history`, `core_engine.history.topology_evolution` | Track recurring relationships, stable/transient classifications, dormant returns, topology drift, communication paths, maturity scoring, dashboard/API records, and export-safe topology history. |
| Historical Replay Windows | `core_engine.history.replay_windows`, `core_engine.history.timeline_replay` | Reconstruct bounded metadata timelines from historical snapshots and component summaries for offline review without re-running collectors. |
| Resource-Aware Historical Retention | `core_engine.history.retention_policies`, `core_engine.history.resource_retention` | Build default, edge, and Raspberry Pi retention profiles, storage/memory budget summaries, adaptive retention windows, preview-only recommendations, dashboard/API dictionaries, and export-ready summaries. |
| Long-Term Intelligence Operator Summary | `core_engine.history.intelligence_summary`, `core_engine.history.operator_views` | Combine historical snapshots, aging/decay, topology evolution, replay windows, and retention into supported/degraded/unavailable states, recommendations, privacy summaries, dashboard/API views, and export-ready dictionaries. |
| Deployment Operationalization | `core_engine.deployment` | Build production runtime profiles, service lifecycle previews, sanitized deployment manifests, upgrade and migration previews, backup/restore plans, deployment readiness summaries, release checklists, and dashboard/API-ready deployment views. |
| Bidirectional Flow Reconstruction | `core_engine.flows.session_tracking`, `core_engine.flows.flow_reconstruction` | Normalize socket observations into metadata-only sessions, infer direction, build flow pairs and relationships, classify transient and recurring behavior, preserve source mode, and emit dashboard/API/export-safe flow summaries. |
| Packet Metadata Correlation | `core_engine.flows.metadata_correlation`, `core_engine.flows.process_correlation` | Correlate packet metadata, socket observations, reconstructed sessions, DNS/destination behavior, protocol hints, process/service attribution, and topology relationships while preserving Unknown/Unattributed live fallbacks and fixture/simulated-only demo labels. |
| Cross-Node Relationship Mapping | `core_engine.topology.relationship_graphs`, `core_engine.topology.lateral_analysis` | Build normalized node relationship graphs, shared service states, recurring peer interaction scores, topology distance, relationship confidence, and advisory lateral analysis summaries without graph database or enforcement behavior. |
| Dynamic Application Attribution | `core_engine.attribution.probabilistic_apps`, `core_engine.attribution.signature_learning`, `core_engine.attribution.confidence_models` | Build generic probable application/service candidates, metadata-only behavioral signatures, bounded confidence breakdowns, conflict penalties, source-mode-aware Unknown/Unattributed live fallbacks, and fixture/simulated-only demo labels. |
| Behavioral Drift Detection | `core_engine.behavior.drift_detection`, `core_engine.behavior.environment_drift` | Compare current application, service, destination, flow, topology, and protocol observations against metadata-only baselines, aggregate environment drift, preserve source mode, and emit dashboard/API/export-safe records without threat verdicts or enforcement. |
| Network Topology Intelligence | `core_engine.topology.trust_zones`, `core_engine.topology.dependency_mapping` | Infer trust zones, service dependencies, communication chains, node dependencies, topology adjacency, relationship strength, recurrence, confidence, and source-mode-aware dashboard/API/export summaries without active probing, graph database dependency, or enforcement. |
| IOC Intelligence Framework | `core_engine.intelligence.ioc_records`, `core_engine.intelligence.ioc_inventory`, `core_engine.intelligence.ioc_matching`, `core_engine.intelligence.ioc_exports` | Normalize metadata-only IOC values for local matching, export hash-only redacted previews, maintain bounded inventories, and produce JSON/CSV-safe summaries without external lookups, malicious flags, threat verdicts, or enforcement. |
| DNS Threat Analytics | `core_engine.intelligence.domain_patterns`, `core_engine.intelligence.dns_analytics` | Build metadata-only domain pattern records, resolver behavior summaries, local IOC match rollups, and DNS analytics states with hashed domains, redacted previews, source-mode preservation, and no DNS lookups, raw DNS history, blocking, verdicts, or enforcement. |
| Threat Signature Framework | `core_engine.intelligence.signature_records`, `core_engine.intelligence.signature_matching` | Build local metadata-only signature records, validate match conditions, reject enforcement-like actions, and deterministically match IOC, DNS, flow, protocol, attribution, topology, runtime, and composite metadata without external feeds, final verdicts, blocking, or enforcement. |
| AI Correlation Layer | `core_engine.intelligence.evidence_chains`, `core_engine.intelligence.ai_correlation` | Build metadata-only evidence chain records and deterministic local correlation summaries across IOC, DNS, signature, flow, attribution, topology, drift, policy, remediation, guardrail, and risk metadata without external AI calls, final verdicts, blocking, or enforcement. |
| Threat Scoring Expansion | `core_engine.intelligence.scoring_weights`, `core_engine.intelligence.threat_scoring` | Build advisory scoring weight profiles and bounded score summaries across IOC, DNS, signature, correlation, flow, attribution, drift, topology, runtime, remediation, and guardrail metadata without malicious labels, final verdicts, blocking, external calls, or enforcement. |
| Threat Hunting Query Engine | `core_engine.intelligence.query_language`, `core_engine.intelligence.hunting_queries` | Build local metadata-only query records and deterministic hunt result summaries across IOC, DNS, signature, correlation, scoring, timeline, topology, fleet, and risk metadata without external queries, final verdicts, blocking, or enforcement. |
| Policy Runtime Engine | `core_engine.policy.runtime_engine`, `core_engine.policy.policy_loader` | Load, validate, and evaluate dry-run policy records against metadata-only telemetry, flow, attribution, drift, topology, and runtime context while rejecting unsafe enforcement modes and destructive actions. |
| Milestone V Live Runtime Bridge | `core_engine.runtime.milestone_v_bridge`, `core_engine.dispatcher`, `gui.visualization`, `core_engine.modules.scanner` | Convert bounded current worker socket snapshots into reconstructed sessions, flow rows, metadata/process correlations, relationship edges, attribution candidates, drift records, topology records, runtime counters, and TUI Traffic Flows/Topology Edges while preserving socket-only limits, no payload inspection, no PCAP generation, and no live dummy labels. Scanner diagnostics and a non-privileged macOS live `lsof` fallback handle psutil permission-blocked socket inventory without elevation. |

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

Milestone O target flow:

```text
operator-selected interface metadata
  -> dry-run passive capture planning
  -> bounded packet metadata windows
  -> bidirectional flow reconstruction
  -> safe protocol metadata and fingerprints
  -> dynamic topology correlation and drift summaries
  -> real-time telemetry dashboard/API summaries
```

Milestone P target flow:

```text
bounded packet metadata and reconstructed flows
  -> enriched flow observations
  -> process/service attribution and DNS visibility
  -> protocol and topology correlation
  -> sanitized gateway/router log summaries
  -> SPAN and mirror-port readiness summaries
  -> gateway mode validation
  -> export-ready and dashboard/API-ready operator records
```

Milestone Q target flow:

```text
runtime and platform detection records
  -> Windows, macOS, Linux, Raspberry Pi, and unknown compatibility summaries
  -> packet capture and firewall provider readiness previews
  -> filesystem and export safety checks
  -> unified cross-platform validation summary
  -> CLI/table/JSON, dashboard, and API-ready operator records
```

Milestone S target flow:

```text
behavioral intelligence and topology metadata
  -> historical snapshot persistence
  -> baseline aging and decay
  -> long-term topology evolution
  -> historical replay windows
  -> resource-aware retention controls
  -> long-term intelligence operator summaries
  -> dashboard/API views and export bundles
```

Milestone T target flow:

```text
runtime health and cross-platform readiness
  -> production runtime profiles
  -> service lifecycle readiness previews
  -> deployment manifest generation
  -> upgrade and migration readiness
  -> backup and restore planning
  -> deployment operator summaries
  -> export-safe release review records and dashboard/API views
```

No step in this plan adds cloud sync, public internet exposure, automatic enforcement, router modification, service installation, or background collection.

Milestone W target flow:

```text
policy, flow, attribution, drift, topology, health, gateway, federation, and deployment records
  -> advisory policy runtime evaluation
  -> confidence-weighted remediation recommendations
  -> quarantine/isolation provider readiness previews
  -> risk escalation and incident candidate summaries
  -> safety guardrail and response simulation records
  -> monitor, supervised, autonomous-preview, and hardened-preview mode records
  -> dashboard/API/export-safe operator review records
```

Phases 135-140 now provide the advisory policy runtime, loader baseline, confidence-weighted adaptive remediation recommendations, escalation decision previews, quarantine/isolation provider readiness previews, risk escalation incident candidates, safety guardrails, and autonomous enforcement mode models. Milestone W must not enable firewall changes, quarantine execution, service disablement, destructive rollback, packet payload inspection, credential handling, threat verdicts, or automatic enforcement.

Milestone X target flow:

```text
telemetry, flow, topology, policy, remediation, risk, and fleet records
  -> visualization-safe topology graph records
  -> bounded historical timeline summaries
  -> asset inventory intelligence
  -> risk dashboard cards and explanation panels
  -> multi-node fleet visibility models
  -> unified visualization operator summaries
  -> dashboard/API/export-safe visual intelligence records
```

Milestone X planning is tracked in `docs/PHASE_141_146_PLAN.md`. It must remain visualization-model only, source-mode preserving, bounded, export-safe, and free of browser UI, live enforcement, firewall changes, packet payload inspection, raw packet storage, raw DNS history, and private identifiers.

Milestone X integration is summarized in `docs/MILESTONE_X_INTEGRATION.md`. It connects Milestone V flow/topology intelligence and Milestone W policy/remediation previews into topology graph models, timeline windows, asset inventory summaries, risk dashboard cards, fleet visibility panels, and visualization operator/readiness records for future GUI, dashboard, and browser product work.

Milestone Y integration is summarized in `docs/MILESTONE_Y_INTEGRATION.md`, with planning tracked in `docs/PHASE_147_152_PLAN.md`. Phases 147-152 now complete the visual intelligence expansion into metadata-only threat intelligence and detection readiness with IOC models, DNS threat analytics, local signature matching, deterministic AI correlation evidence chains, advisory threat scoring expansion, and local threat hunting query records while remaining free of final threat verdicts, malicious labels, blocking, enforcement, external threat-feed lookups, external AI calls, packet payload storage, raw DNS history, credential storage, and private identifier export.

Milestone Z planning is tracked in `docs/PHASE_153_158_PLAN.md`. Phase 153 now provides metadata-only local telemetry bus envelopes, telemetry topics, bounded in-memory queue summaries, dropped-by-bound previews, retry/backoff metadata, fanout readiness, and export-safe bus summaries. Phase 154 now provides metadata-only retention tier records, storage readiness summaries, utilization and pressure states, telemetry bus queue input summaries, write/read capacity previews, and compaction previews. Phase 155 now provides metadata-only worker group records, cluster size and recommended cluster size previews, shard and partition planning previews, worker distribution summaries, capacity forecasts, fanout readiness, and scaling recommendations. Phases 156-158 are planned to scale resource optimization, edge worker modes, and relay readiness with metadata-only bounded records and without external broker dependencies, live database dependencies, runtime data writes, deletion, destructive compaction, live cloud provisioning, cluster creation, cloud APIs, telemetry routing changes, enforcement, firewall/process/service changes, credential storage, or private identifier export.

Phase 154 storage summaries consume Phase 153 telemetry bus queue depth, dropped-by-bound counts, retry metadata, and topic counts to estimate storage pressure for later scaling work. The records remain advisory and export-safe: compaction is preview-only, no runtime data is written, no data is deleted, and no database service is required.

Phase 155 scaling summaries consume Phase 153 telemetry bus queue pressure and Phase 154 storage utilization to preview cluster growth, shard counts, partition counts, worker distribution, and fanout readiness. The records remain advisory and export-safe: no infrastructure is provisioned, no clusters are created, no cloud APIs are called, runtime worker counts are unchanged, and telemetry routing is not modified.

Phase 147 now provides `core_engine.intelligence` IOC records, bounded inventories, local matching, and export summaries. IOC values are normalized for local matching but exported only as hashes and redacted previews. The framework preserves source category and source mode, supports JSON-safe and CSV-row-safe dictionaries, and avoids external lookups, malicious flags, threat verdict fields, raw payload storage, raw DNS history, credential storage, and enforcement behavior.

Phase 148 now connects DNS observations, domain pattern records, resolver behavior, Phase 147 IOC inventory or match records, and optional destination summaries into DNS analytics rollups. Domains and resolver references are exported only as hashes or sanitized summaries, and the records remain advisory with no DNS lookups, external feeds, domain blocking, malicious flags, final threat verdicts, raw DNS history storage, or enforcement behavior.

Phase 149 now adds local signature records and deterministic signature matching over IOC matches, DNS patterns, flow metadata, protocol hints, attribution summaries, topology relationships, runtime health, and composite signal contexts. Signature validation rejects enforcement-like conditions, and match records remain preview-only with no external feeds, malicious flags, final threat verdicts, blocking, or enforcement behavior.

Phase 150 now adds evidence chain records and AI correlation summaries across IOC, DNS, signature, flow, attribution, drift, topology, policy, risk, remediation, and guardrail metadata. The implementation is deterministic and local, preserves source modes, emits bounded explanation points, and performs no external AI/model calls, network requests, final verdict generation, blocking, or enforcement behavior.

Phase 151 now adds advisory scoring weight profiles and bounded threat scoring records across IOC, DNS, signature, correlation, flow, attribution, drift, topology, runtime health, remediation preview, and guardrail metadata. The implementation preserves source modes, emits score breakdowns and explanation points, and performs no external feed lookup, AI/model call, malicious labeling, final verdict generation, blocking, or enforcement behavior.

Phase 152 now adds local threat hunting query records and hunt result summaries across IOC, DNS, signature, correlation, scoring, timeline, topology, fleet, and risk metadata. The query engine supports equality, contains, confidence, severity, source-mode, and bounded-limit filters, emits sanitized matched-record summaries, and performs no external query, payload inspection, malicious labeling, final verdict generation, blocking, or enforcement behavior.

Phase 141 now provides `core_engine.visualization` topology model records, asset classification helpers, observation-to-node conversion, flow-to-edge conversion, node deduplication, edge aggregation, confidence scoring, bounded graph summaries, and JSON/Mermaid/Cytoscape-safe exports. These records are visualization-model only and do not add GUI, browser UI, live network action, packet storage, raw DNS history, enforcement hooks, or private identifier export.

Phase 142 now adds replay-safe historical timeline event and window records under `core_engine.visualization`. Timeline builders convert topology graphs, flow summaries, asset classifications, drift records, policy evaluations, remediation recommendations, incident candidates, and runtime health summaries into deduplicated, chronologically sorted, max-event-bounded windows with category counts, severity counts, source-mode preservation, and export-safe dictionaries. The timeline layer does not write databases, store raw payloads, store raw DNS history, export private identifiers, execute remediation, or modify host/network state.

Phase 143 now adds visualization-ready asset inventory intelligence records under `core_engine.visualization`. Asset role helpers infer workstation, server, router, switch, printer, NAS, phone, IoT, DNS resolver, cloud service, external service, and unknown roles from sanitized metadata hints. Inventory builders deduplicate assets, preserve source modes, summarize first-seen and last-seen windows, count related services/flows/timeline events, bound output with `max_assets`, and export role/state/confidence summaries without writing inventory databases, storing raw payloads, retaining raw DNS history, exporting private identifiers, executing remediation, or modifying host/network state.

Phase 144 now adds visualization-ready risk dashboard cards and panels under `core_engine.visualization`. Risk builders convert asset inventory, topology graphs, flow summaries, policy evaluations, remediation recommendations, incident candidates, guardrail records, runtime health, drift, and attribution records into deduplicated, high-risk-sorted, max-card-bounded panels with severity counts, category counts, recommendation counts, blocked-action counts, source-mode preservation, and export-safe dictionaries. The risk dashboard layer does not add browser UI, write runtime databases, inspect packet payloads, retain raw DNS history, export private identifiers, execute remediation, or modify host/network state.

Phase 145 now adds visualization-ready multi-node fleet visibility records under `core_engine.visualization`. Fleet builders convert runtime node summaries, federation summaries, deployment summaries, cluster health summaries, topology summaries, asset inventory, and risk dashboard summaries into deduplicated, max-node-bounded fleet panels with site summaries, group summaries, collector health, version compatibility, last check-ins, telemetry freshness, observed asset/flow counts, risk rollups, empty/degraded states, source-mode preservation, and export-safe dictionaries. The fleet layer does not add cloud sync, remote control, browser UI, runtime databases, raw payload storage, private identifier export, remediation execution, or host/network state changes.

Phase 146 now adds unified visualization operator summaries and readiness checks under `core_engine.visualization`. Operator summaries roll up topology graphs, timeline windows, asset inventory, risk dashboards, fleet visibility, and runtime health into degraded/empty component lists, recommendation summaries, source-mode summaries, readiness states, and dashboard/API/export-safe dictionaries. The readiness layer reports available, missing, degraded, and empty components without starting browser UI, making remote calls, writing runtime databases, executing remediation, or modifying host/network state.

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
- Cross-platform validation records can score runtime detection, Windows compatibility, packet capture readiness, firewall provider readiness, filesystem/export safety, service-mode readiness, gateway readiness, and runtime health before installers or production service workflows are enabled.
- Adaptive risk records can combine historical baselines, temporal anomalies, service fingerprints, and DNS/destination behavior into operator-readable advisory score explanations without enforcement.
- Behavioral intelligence summaries can roll baseline, anomaly, service fingerprint, DNS/destination, and adaptive risk records into dashboard/API, export, and operator recommendation records.

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
- Adaptive risk weighting records with base and adjusted scores, behavioral context, confidence-aware adjustments, no-enforcement explanations, dashboard/API summaries, and export-ready digests.
- Behavioral intelligence operator summary records with component rollups, supported/degraded/unavailable states, advisory recommendations, privacy/safety summaries, dashboard/API views, and export-ready digests.

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
