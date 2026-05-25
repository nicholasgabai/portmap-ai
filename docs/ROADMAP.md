# PortMap-AI Roadmap

This roadmap summarizes the current direction after the Phase 92 baseline. `PORTMAP_AI_HANDOFF.md` remains the canonical implementation record, `docs/PHASE_HISTORY.md` records completed phase groups, `docs/MILESTONE_INTEGRATION.md` is the active integration guide, `docs/MILESTONE_O_INTEGRATION.md` summarizes Phase 87-92 live telemetry integration, and `docs/COMPLETION_ROADMAP.md` defines the remaining end-to-end completion path.

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

## Current Implementation State

Phases 0-92 are implemented locally in the working tree and documented as complete baselines. A complete baseline means the foundational implementation is operational and tested, while future work may expand integration depth, production hardening, and operator workflows.

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
- The Textual terminal dashboard remains the primary operator UI.
- Static web dashboard rendering exists as a reusable foundation, not a replacement UI.
- Docker remains optional and advanced.
- Private real-device validation notes stay out of public commits unless scrubbed.

## Completion Roadmap

The detailed remaining roadmap is maintained in `docs/COMPLETION_ROADMAP.md`.

Planned remaining milestones:

- Milestone P - Gateway and Telemetry Enrichment.
- Milestone Q - Production Security and Access Control.
- Milestone R - Installer, Service, and Release Packaging.
- Milestone S - AI Security Intelligence Layer.
- Milestone T - Commercial SaaS and Fleet Management.

## Medium-Term Work

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
- `docs/PHASE_HISTORY.md`
- `docs/MILESTONE_INTEGRATION.md`
- `docs/MILESTONE_J_INTEGRATION.md`
- `docs/MILESTONE_K_INTEGRATION.md`
- `docs/MILESTONE_L_INTEGRATION.md`
- `docs/MILESTONE_M_INTEGRATION.md`
- `docs/MILESTONE_N_INTEGRATION.md`
- `docs/MILESTONE_O_INTEGRATION.md`
- `docs/PHASE_59_64_PLAN.md`
- `docs/PHASE_65_70_PLAN.md`
- `docs/PHASE_71_76_PLAN.md`
- `docs/PHASE_77_82_PLAN.md`
- `docs/PHASE_87_92_PLAN.md`
- `docs/PHASE_93_98_PLAN.md`
- `docs/event_pipeline.md`
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
