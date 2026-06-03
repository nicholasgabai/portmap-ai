# PortMap-AI Roadmap

This roadmap summarizes the current direction after the Phase 127 baseline. `PORTMAP_AI_HANDOFF.md` remains the canonical implementation record, `docs/PHASE_HISTORY.md` records completed phase groups, `docs/MILESTONE_INTEGRATION.md` is the active integration guide, `docs/MILESTONE_R_INTEGRATION.md` summarizes Phase 105-110 behavioral intelligence integration, `docs/MILESTONE_S_INTEGRATION.md` summarizes Phase 111-116 historical persistence integration, `docs/MILESTONE_T_INTEGRATION.md` summarizes Phase 117-122 operationalization and deployment integration, `docs/COMPLETION_ROADMAP.md` defines the remaining end-to-end completion path, and `docs/PORTMAP_AI_FINAL_ROADMAP.md` captures the longer production-launch roadmap from Milestone U onward.

## Completed Milestones

| Range | Milestone | Status |
| --- | --- | --- |
| 0-18 | Local stack, CLI, packaging, configuration, platform abstraction, safety, deployment, and release-candidate foundation | Complete baseline |
| 19-40 | Scanner expansion, packet metadata, protocol intelligence, AI advisory layers, enterprise primitives, visualization, cluster planning, and local enterprise cloud scaffolding | Complete baseline |
| 41-43 | Local visibility tooling, sanitized example datasets, visibility snapshots, and baseline delta reporting | Complete baseline |
| 44-46 | Local intelligence platform: event model, storage, and scheduler primitives | Complete baseline |
| 47-48 | Coordinated node platform: node identity and local read-only API primitives | Complete baseline |
| 49-50 | Operator dashboard foundation: static dashboard rendering, topology graphs, and timelines | Complete baseline |
| 51-53 | Policy and correlation engine: review queue, distributed aggregation, and behavior correlation | Complete baseline |
| 54-58 | Advanced diagnostics and deployment readiness: schema validation, stream metadata, plugin governance, relay orchestration, and service templates | Complete baseline |
| 59-64 | Runtime pipeline and persistent topology integration: topology state, snapshot drift, runtime workflows, review persistence, dashboard providers, and operational export bundles | Complete baseline |
| 65-70 | Unified runtime operations: runtime sessions, profiles, recovery, CLI, health monitoring, and service-mode readiness previews | Complete baseline |
| 71-76 | Distributed runtime intelligence: node state sync, federated topology, cluster health, distributed reviews, coordinated exports, and operator visibility prep | Complete baseline |
| 77-82 | Trusted runtime transport and live federation: trusted transport models, signed summary exchange, live cluster synchronization, distributed event propagation, federation diagnostics, and dashboard/API readiness | Complete baseline |
| 83-86 | Active federation runtime: runtime manager records, trusted peer lifecycle, runtime exchange scheduler, and active federation validation | Complete baseline |
| 87-92 | Live network telemetry: passive interface discovery, bounded packet metadata windows, flow reconstruction, protocol metadata extraction, dynamic topology correlation, and real-time telemetry dashboard/API summaries | Complete baseline |
| 93-98 | Gateway and telemetry enrichment: enriched flow observations, process/service attribution, DNS visibility, router log ingestion, SPAN readiness, and gateway mode validation | Complete baseline |
| 99-104 | Cross-platform runtime hardening: runtime detection, Windows compatibility, packet capture readiness, firewall provider readiness, filesystem/export safety, and unified validation summaries | Complete baseline |
| 105-110 | Behavioral intelligence foundation: historical flow baselines, temporal anomaly windows, service behavior fingerprints, DNS/destination behavior learning, adaptive risk weighting, and unified operator summaries | Complete baseline |
| 111-116 | Historical persistence and long-term intelligence: historical snapshots, baseline aging and decay, topology evolution, replay windows, resource-aware retention, and long-term intelligence operator summaries | Complete baseline |
| 117-122 | Operationalization and deployment foundation: production runtime profiles, service lifecycle readiness, deployment manifests, upgrade and migration readiness, backup/restore planning, and deployment operator summaries | Complete baseline |
| 123 | Security foundation and trusted runtime: secure logical node identity, worker enrollment previews, trust-chain summaries, identity regeneration/rotation previews, and export-safe safety fields | Complete baseline |
| 124 | Encrypted orchestration transport: transport security profiles, mTLS readiness, downgrade warnings, and session negotiation previews without certificates, keys, listeners, live auth exchange, or mTLS handshakes | Complete baseline |
| 125 | Secure config and secrets management: secure configuration profiles, secret-management previews, plaintext persistence rejection, rotation readiness, external provider readiness, and export-safe dictionaries | Complete baseline |
| 126 | RBAC and operator permissions: admin, security-operator, analyst, auditor, read-only, and service-account role records plus permission evaluation previews without user accounts, credentials, live auth enforcement, or API behavior changes | Complete baseline |
| 127 | Tamper detection: runtime integrity targets, config and manifest tamper previews, identity/trust-chain drift warnings, transport downgrade warnings, package digest mismatch records, and export-safe safety fields without file watching, blocking, quarantine, deletion, rollback, or config modification | Complete baseline |

## Current Implementation State

Phases 0-127 are implemented locally in the working tree and documented as complete baselines. A complete baseline means the foundational implementation is operational and tested, while future work may expand integration depth, production hardening, installer packaging, and operator workflows.

Current stable posture:

- Local-first operation remains the default.
- Workflows remain opt-in and operator-controlled.
- Advisory behavior remains read-only by default.
- Runtime, topology, review, dashboard-provider, and export modules now have explicit local wiring paths.
- Runtime sessions now provide local session summaries for future CLI, API, dashboard, and service-preview workflows.
- Unified runtime profiles now provide default, edge-device, and operator-merged configuration records.
- Runtime recovery helpers now summarize checkpoints, incomplete workflows, pending reviews, failed steps, and export readiness.
- The integrated runtime CLI now exposes status, run, recover, reviews, and export commands.
- Runtime health monitoring now summarizes storage, scheduler, event queue, review, dashboard, export, and session readiness.
- Service-mode readiness now provides dry-run preflight checks, command previews, and manual operator checklist records without installing or starting services.
- Distributed node state sync now normalizes trusted master and worker runtime summaries into deterministic cluster state records.
- Federated topology aggregation now merges trusted node topology snapshots with source attribution and explicit conflict records.
- Cluster runtime health now rolls up trusted node health summaries, resource warnings, availability classifications, local health events, and dashboard-ready panels.
- Distributed review queue aggregation now preserves node ownership, reports duplicate reviews and repeated categories, summarizes finding status, and prepares export-ready review records.
- Coordinated export bundle planning now combines trusted-node evidence manifests with cross-node digest summaries, missing-node records, redaction validation, and local archive plans.
- Remote operator visibility prep now provides read-only trusted-node panels for cluster runtime, federated topology, reviews, exports, and service readiness without remote control.
- Trusted node transport models now define local trust profiles, approved peers, transport sessions, handshake summaries, expiration windows, trust scopes, and replay-window metadata without opening network listeners.
- Signed runtime summary exchange now provides canonical JSON, deterministic digests, signature metadata, verification records, trusted peer validation hooks, and replay-window validation hooks.
- Live cluster state synchronization now classifies signed updates, tracks per-node last-seen state, reports conflicts and drift, and emits merged cluster state summaries.
- Distributed event propagation now wraps local events in trusted envelopes, preserves source attribution, applies replay checks, and rolls up accepted, rejected, stale, duplicate, malformed, and untrusted records.
- Federation diagnostics now summarize trusted peer, transport, signing, synchronization, event propagation, replay-window, distributed runtime, readiness, recommendation, and local health event records.
- Federation dashboard/API readiness now exposes read-only panels and API-compatible dictionaries for trusted peers, transports, signed exchanges, sync windows, events, diagnostics, readiness scores, and counters.
- Federation runtime manager records now summarize trusted peer runtime enrollment, active/inactive/paused/error states, planned signed exchange, synchronization, and event propagation loops, per-peer counters, timestamps, and dashboard/API-ready runtime state without starting listeners or daemons.
- Trusted peer lifecycle records now manage enroll, approve, pause, resume, revoke, expire, and trust scope update states with transport session linkage, stale/expired/revoked summaries, and dashboard/API-ready registry dictionaries.
- Runtime exchange scheduler records now convert federation loop plans into per-peer signed-summary exchange, cluster-state sync, and event propagation job records with interval/backoff metadata, enable/disable state, failure counters, and dashboard/API-ready summaries without executing jobs.
- Active federation validation now scores trusted peers, signed exchanges, synchronization windows, event propagation, replay-window counters, exchange scheduler state, and runtime manager readiness with operator recommendations and dashboard/API dictionaries.
- Passive interface discovery now normalizes local interface metadata, address-family summaries, loopback/broadcast/multicast capability fields, dry-run capture session plans, resource budgets, and dashboard/API-ready dictionaries without capturing packets.
- Live packet ingestion now normalizes operator-provided packet metadata into bounded dry-run windows with source/interface attribution, IPv4/IPv6 and TCP/UDP/ICMP summaries, packet size and rate summaries, replay-safe counters, malformed/unsupported classification, and no raw payload storage.
- Flow reconstruction now groups packet metadata into bidirectional flow/session records, applies timeout handling, classifies complete, partial, and malformed flows, associates likely services, emits deterministic flow digests, and produces topology-ready observed-flow edges.
- Protocol metadata extraction now summarizes HTTP, TLS, and DNS metadata, builds protocol and service fingerprints, scores confidence, handles encrypted-session metadata without decryption, truncates safe fields, removes sensitive fields, and emits protocol anomaly summaries.
- Dynamic topology correlation now maps live flow and protocol summaries into bounded topology graphs, infers node relationships and roles, correlates optional baseline drift, emits replay-safe update records, and produces cluster/federation-aware dashboard/API dictionaries.
- Real-time telemetry dashboard integration now exposes read-only live telemetry panels, bounded update controls, empty and stale rendering models, health rollups, and local API dictionaries without rendering raw payloads or replacing the TUI.
- Sanitized real-device validation after Milestone O confirmed stable extended local runtime behavior across orchestrator, master, worker, TUI, runtime status, runtime export, remote administration, node heartbeats, scoring, advisory remediation, and live dashboard updates while preserving dry-run safety and no automatic enforcement.
- Flow telemetry enrichment now adds metadata-only enriched flow observations, rolling packet and byte statistics, endpoint scope and direction inference, service-port hints, state transitions, confidence scoring, quality flags, and dashboard/API-ready summaries.
- Process and service attribution now correlates enriched flow observations with minimized process metadata and listening socket ownership, reports unsupported or permission-denied states safely, and emits confidence-scored dashboard/API dictionaries without command-line or username exposure.
- DNS visibility mode now records metadata-only DNS queries and responses, correlates domains to enriched flows, classifies resolvers, summarizes timing and NXDOMAIN/error states, reports encrypted DNS limitations, and emits dashboard/API-ready dictionaries.
- Gateway and router log ingestion now parses sanitized syslog-style fixtures into metadata-only allow, deny, NAT, malformed, runtime-event, topology-edge, export-ready, and dashboard/API summaries without starting listeners or modifying router settings.
- SPAN and mirror-port readiness now builds dry-run profiles, interface capability checks, resource and traffic warnings, packet-loss risk summaries, operator checklists, telemetry scaling guidance, and dashboard/API dictionaries without changing interface, router, or switch settings.
- Gateway mode validation now aggregates telemetry enrichment, DNS visibility, router logs, SPAN readiness, topology correlation, runtime health, and operator visibility into supported, degraded, unavailable, and unsafe dry-run readiness states.
- Cross-platform runtime detection now normalizes macOS, Linux, Raspberry Pi/Linux ARM, Windows, and unknown platform records with architecture, Python, permission, capability, and dashboard/API-ready compatibility summaries.
- Windows runtime compatibility now provides Windows-safe path normalization, log/export/cache summaries, process/socket visibility fallbacks, service-mode previews, runtime profile defaults, degraded states, and dashboard/API dictionaries without service control, firewall changes, registry writes, or elevation.
- Cross-platform packet capture readiness now reports macOS BPF/libpcap, Linux libpcap/AF_PACKET/scapy, Raspberry Pi, and Windows Npcap/WinPcap backend states with passive safety warnings and raw-payload prohibition fields without starting capture.
- Cross-platform firewall provider readiness now provides Windows Defender Firewall, macOS pf, Linux nftables/ufw/iptables, and Raspberry Pi dry-run provider previews with operator review flags and no rule changes.
- Cross-platform filesystem and export safety now validates safe log, export, and cache path summaries, artifact exclusions, private-file warnings, runtime artifact classes, and public-doc safety checks.
- Cross-platform validation summaries now roll up macOS, Linux, Raspberry Pi/Linux ARM, and Windows compatibility, packet capture readiness, firewall readiness, filesystem/export safety, aggregate states, operator recommendations, and CLI/table/JSON/dashboard/API output.
- Historical flow baselines now track rolling metadata-only entries for ports, protocols, services, process/service fingerprints, flow tuple digests, and DNS/domain observations across bounded short, medium, and long windows with stable/new/recurring/decaying classifications, advisory confidence scoring, dashboard/API summaries, and export-ready digests.
- Temporal anomaly windows now summarize short, medium, and long behavior changes against local baselines with burst detection, rare service timing, volume drift hints, port/protocol/service novelty labels, advisory confidence scoring, operator explanations, dashboard/API dictionaries, and export-ready digests.
- Service behavior fingerprints now track recurring metadata-only process, service, protocol, port, transport, flow role, redacted DNS-summary, runtime platform, interface class, and direction combinations with expected profile summaries, unusual combination labels, dormant service return tracking, confidence scoring, dashboard/API dictionaries, and export-ready digests.
- DNS and destination behavior learning now tracks recurring redacted or hashed domain summaries, resolver hashes, destination IP classification placeholders, destination frequency, recurrence timing, novelty, confidence, unusual resolver behavior, dormant destination returns, drift hints, dashboard/API dictionaries, and export-ready digests without external reputation calls.
- Adaptive risk weighting now adjusts advisory scores using local historical baselines, temporal anomalies, service fingerprints, and DNS/destination behavior with confidence-aware dampening, no-enforcement explanations, dashboard/API dictionaries, and export-ready digests.
- Behavioral intelligence operator summaries now combine baselines, temporal anomalies, service fingerprints, DNS/destination learning, and adaptive risk into supported, degraded, and unavailable states with advisory recommendations, explanations, dashboard/API views, and export-ready digests.
- Historical snapshot persistence now stores rolling metadata-only behavioral intelligence snapshots with bounded rotation helpers, export-safe summaries, structured malformed input handling, dashboard/API-safe dictionaries, and temporary-path-only write tests.
- Baseline aging and decay now applies safe local aging policies to metadata-only baselines, service fingerprints, and destination behavior with inactive, stale, dormant, and maturity summaries plus export/dashboard/API-ready decay records.
- Long-term topology evolution now tracks recurring node relationships, stable versus transient paths, dormant relationship returns, topology drift summaries, communication path rollups, and dashboard/API/export-safe topology history.
- Historical replay windows now reconstruct bounded metadata timelines from snapshots, anomaly summaries, topology evolution, baseline decay, service fingerprints, DNS/destination behavior, and adaptive risk for offline operator review.
- Resource-aware historical retention now builds storage and memory budget summaries, Raspberry Pi and edge-device retention profiles, adaptive retention windows, preview-only recommendations, and dashboard/API/export-safe retention summaries without deleting files.
- Long-term intelligence operator summaries now combine historical snapshots, baseline aging/decay, topology evolution, replay windows, and resource-aware retention into unified supported, degraded, and unavailable states with dashboard/API/export-safe operator views.
- Production runtime profiles now model development, staging, production, edge, and lab deployment postures with safety mode, telemetry level, orchestration mode, remediation mode, history retention, resource budgets, capability flags, and compatibility validation.
- Service lifecycle readiness now previews systemd, launchd, Windows Service Control Manager, foreground, and Raspberry Pi edge provider states without installing, registering, starting, stopping, or modifying services.
- Deployment manifest generation now creates sanitized standalone, orchestrator, worker, edge, lab, and production-preview deployment records with node profiles, resource envelopes, readiness, export path placeholders, backup recommendations, and advisory notes.
- Upgrade and migration readiness now previews version compatibility, runtime profile impact, manifest impact, service lifecycle impact, telemetry impact, history retention impact, rollback availability, migration safety checks, and operator steps without executing migrations.
- Backup and restore planning now builds dry-run backup plans and restore previews for configs, manifests, runtime exports, historical intelligence, and operator evidence bundles without copying, restoring, deleting, overwriting, or compressing runtime artifacts.
- Deployment operator summaries now combine deployment profiles, service lifecycle readiness, manifests, upgrade/migration readiness, and backup/restore planning into readiness scores, release checklists, operator actions, safety warnings, and dashboard/API/export-safe views.
- Secure node identity now provides deterministic logical node UUIDs, worker enrollment previews, orchestrator/master/worker/edge trust relationship summaries, identity regeneration and rotation previews, and export-safe safety fields without exposing hardware identifiers, hostnames, usernames, serial numbers, MAC addresses, credentials, certificates, listeners, or privileged enrollment actions.
- Encrypted orchestration transport readiness now models plaintext development, TLS-ready, mTLS-ready, pinned-certificate-ready, and production-required transport profiles plus session negotiation previews, downgrade warnings, mutual-auth requirements, and export-safe safety fields without generating certificates, private keys, listeners, live auth exchange, or mTLS handshakes.
- Secure config and secrets management now models development, staging, production, edge, and ephemeral runtime secure configuration profiles plus orchestrator token, worker enrollment secret, future mTLS material, API/session token, and runtime encryption key previews without storing credentials, persisting plaintext, creating encryption keys, integrating OS keychains, or exchanging secrets.
- RBAC and operator permissions now model admin, security-operator, analyst, auditor, read-only, and service-account roles plus preview-only permission decisions for telemetry, history, exports, remediation, enrollment, identity rotation, configuration, audit logs, and role management without creating users, storing credentials, enforcing live auth, or changing API access behavior.
- Tamper detection now models integrity targets and tamper preview records for runtime configs, manifests, identities, trust chains, transport profiles, package manifests, binary artifacts, and history stores without file watchers, private-file hashing, blocking, quarantine, deletion, rollback, configuration modification, or binary modification.
- Pre-Milestone U source labeling now prevents `dummy_app` and `dummy_db` from appearing in live/default TUI runtime views unless simulation or fixture mode is explicit. Live unresolved attribution displays as `Unattributed` or `Unknown`, and TUI/dashboard/API/export summaries preserve source mode.
- Pre-Milestone U live scan snapshot deduplication now bounds each worker scan cycle as a current snapshot, collapses duplicate socket rows, prunes transient live socket states, keeps remediation scoring stable across repeated identical scans, and keeps the TUI scan-results panel focused on the latest snapshot per node.
- The Textual terminal dashboard remains the primary operator UI.
- Static web dashboard rendering exists as a reusable foundation, not a replacement UI.
- Docker remains optional and advanced.
- Private real-device validation notes stay out of public commits unless scrubbed.

## Completion Roadmap

The detailed remaining roadmap is maintained in `docs/COMPLETION_ROADMAP.md`. The extended production-launch roadmap is maintained in `docs/PORTMAP_AI_FINAL_ROADMAP.md`.

Planned remaining milestones:

- Continue Milestone U security foundation and trusted runtime work after the Phase 127 tamper detection baseline.
- Deep flow intelligence, autonomous response, enterprise dashboard, packaging, governance, AI evolution, and commercial launch readiness work as tracked in `docs/PORTMAP_AI_FINAL_ROADMAP.md`.

## Medium-Term Work

- Milestone T operationalization and deployment foundation is complete as a baseline through Phase 122.
- Harden service-management packaging for long-running agents.
- Expand dashboard usability while preserving the terminal-first product direction.
- Add operator-friendly import/export flows for telemetry and advisory packets.
- Improve enterprise workflow documentation around organizations, roles, quotas, and sync manifests.

## Long-Term Vision

PortMap-AI aims to become an AI-native network observability, exposure management, telemetry intelligence, and remediation orchestration platform supporting local, distributed, and enterprise-scale deployments.

## References

- `PORTMAP_AI_HANDOFF.md`
- `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md`
- `docs/COMPLETION_ROADMAP.md`
- `docs/PORTMAP_AI_FINAL_ROADMAP.md`
- `docs/PHASE_HISTORY.md`
- `docs/MILESTONE_INTEGRATION.md`
- `docs/MILESTONE_J_INTEGRATION.md`
- `docs/MILESTONE_K_INTEGRATION.md`
- `docs/MILESTONE_L_INTEGRATION.md`
- `docs/MILESTONE_M_INTEGRATION.md`
- `docs/MILESTONE_N_INTEGRATION.md`
- `docs/MILESTONE_O_INTEGRATION.md`
- `docs/MILESTONE_P_INTEGRATION.md`
- `docs/MILESTONE_Q_INTEGRATION.md`
- `docs/MILESTONE_R_INTEGRATION.md`
- `docs/MILESTONE_S_INTEGRATION.md`
- `docs/MILESTONE_T_INTEGRATION.md`
- `docs/source_mode_labeling.md`
- `docs/live_scan_snapshot_deduplication.md`
- `docs/PHASE_117_122_PLAN.md`
- `docs/PHASE_123_128_PLAN.md`
- `docs/secure_node_identity.md`
- `docs/encrypted_orchestration_transport.md`
- `docs/secure_config_and_secrets.md`
- `docs/rbac_operator_permissions.md`
- `docs/tamper_detection.md`
- `docs/PHASE_111_116_PLAN.md`
- `docs/PHASE_59_64_PLAN.md`
- `docs/PHASE_65_70_PLAN.md`
- `docs/PHASE_71_76_PLAN.md`
- `docs/PHASE_77_82_PLAN.md`
- `docs/PHASE_87_92_PLAN.md`
- `docs/PHASE_93_98_PLAN.md`
- `docs/PHASE_99_104_PLAN.md`
- `docs/PHASE_105_110_PLAN.md`
- `docs/baseline_aging_decay.md`
- `docs/event_pipeline.md`
- `docs/historical_snapshot_persistence.md`
- `docs/historical_replay_windows.md`
- `docs/long_term_topology_evolution.md`
- `docs/resource_aware_historical_retention.md`
- `docs/long_term_intelligence_operator_summary.md`
- `docs/local_storage.md`
- `docs/runtime_scheduler.md`
- `docs/node_coordination.md`
- `docs/local_api.md`
- `docs/dashboard_foundation.md`
- `docs/dashboard_data_providers.md`
- `docs/persistent_topology_state.md`
- `docs/snapshot_drift_detection.md`
- `docs/operational_export_bundle.md`
- `docs/runtime_session_manager.md`
- `docs/unified_configuration_profiles.md`
- `docs/runtime_state_recovery.md`
- `docs/runtime_cli.md`
- `docs/runtime_health_monitor.md`
- `docs/service_mode_readiness.md`
- `docs/runtime_pipeline.md`
- `docs/topology_timeline_views.md`
- `docs/policy_review_engine.md`
- `docs/operator_review_queue_integration.md`
- `docs/distributed_visibility_aggregation.md`
- `docs/distributed_node_state_sync.md`
- `docs/federated_topology_aggregation.md`
- `docs/cluster_runtime_health.md`
- `docs/distributed_review_queue.md`
- `docs/coordinated_export_bundles.md`
- `docs/remote_operator_visibility_prep.md`
- `docs/trusted_node_transport.md`
- `docs/signed_runtime_summary_exchange.md`
- `docs/live_cluster_state_synchronization.md`
- `docs/distributed_event_propagation.md`
- `docs/federation_diagnostics.md`
- `docs/federation_dashboard_api_readiness.md`
- `docs/federation_runtime_manager.md`
- `docs/trusted_peer_lifecycle.md`
- `docs/runtime_exchange_scheduler.md`
- `docs/active_federation_validation.md`
- `docs/passive_interface_discovery.md`
- `docs/live_packet_ingestion.md`
- `docs/flow_reconstruction.md`
- `docs/protocol_metadata_extraction.md`
- `docs/dynamic_topology_correlation.md`
- `docs/realtime_telemetry_dashboard.md`
- `docs/behavior_correlation.md`
- `docs/schema_validation_engine.md`
- `docs/metadata_stream_parser.md`
- `docs/plugin_registry.md`
- `docs/diagnostic_relay_simulator.md`
- `docs/service_installer_templates.md`
- `docs/archive/`
