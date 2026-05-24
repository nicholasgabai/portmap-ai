# PortMap-AI Documentation Index

PortMap-AI is currently a functional local distributed network observability stack with an orchestrator API, master node, worker node, Textual terminal dashboard, remediation audit trail, local visibility tooling, diagnostic primitives, and local stack launcher.

## Start Here

- `PORTMAP_AI_HANDOFF.md` - current system state, verified baseline, and operating notes.
- `docs/ROADMAP.md` - concise current roadmap and next milestone direction.
- `docs/PHASE_HISTORY.md` - concise index of completed phase groups.
- `docs/MILESTONE_INTEGRATION.md` - active integration guide for completed Phase 44-76 platform modules.
- `docs/MILESTONE_J_INTEGRATION.md` - detailed integration summary for Phase 59-64 runtime pipeline and persistent topology work.
- `docs/MILESTONE_K_INTEGRATION.md` - detailed integration summary for Phase 65-70 unified runtime operations work.
- `docs/MILESTONE_L_INTEGRATION.md` - detailed integration summary for Phase 71-76 distributed runtime intelligence work.
- `docs/PHASE_59_64_PLAN.md` - completed milestone plan for runtime pipeline and persistent topology integration.
- `docs/PHASE_65_70_PLAN.md` - completed milestone plan for unified runtime operations.
- `docs/PHASE_71_76_PLAN.md` - completed milestone plan for distributed runtime intelligence.
- `docs/PHASE_77_82_PLAN.md` - next milestone plan for trusted runtime transport and live federation.
- `docs/DEPLOYMENT.md` - deployment paths and validation expectations.
- `docs/SECURITY_MODEL.md` - centralized safety, trust, telemetry, and remediation boundaries.
- `docs/CLI_REFERENCE.md` - command-family reference for the installed `portmap` CLI.
- `CHANGELOG.md` - release-candidate change history and verification notes.
- `docs/real_device_validation.md` - private/scrub-required Linux, Raspberry Pi, macOS, and Windows validation checklist.
- `docs/archive/` - historical milestone planning documents retained for reference.

## Setup And Operations

- `docs/quick_start.md` - setup, stack launch, dashboard, tests, and log export.
- `docs/architecture.md` - current local-first architecture and component boundaries.
- `docs/deployment_options.md` - default local install path, always-on service path, and optional Docker path.
- `docs/packaging.md` - install, setup, diagnostics, and build artifact guidance.
- `docs/release_candidate.md` - version 0.1.0 release-candidate checklist and known limitations.
- `docs/raspberry_pi_deployment.md` - Linux/ARM service setup and low-resource guidance.
- `docs/docker_deployment.md` - Docker Compose deployment for orchestrator, master, and worker.
- `docs/configuration.md` - configuration layering, environment placeholders, and runtime settings.
- `test_instructions.md` - focused local verification checklist.

## Local Platform Foundation

- `docs/event_pipeline.md` - local-only normalized event model, in-memory queue, and event bus.
- `docs/local_storage.md` - local SQLite storage for events, snapshots, assets, services, topology relationships, and findings.
- `docs/runtime_scheduler.md` - lightweight scheduler primitives for health checks, event flushing, snapshot refreshes, and policy review refreshes.
- `docs/node_coordination.md` - local node identity, capability records, heartbeat metadata, lifecycle states, and summaries.
- `docs/local_api.md` - local read-only API primitives for health, events, assets, snapshots, nodes, and topology.
- `docs/dashboard_foundation.md` - lightweight local web dashboard rendering foundation for API-backed status panels.
- `docs/persistent_topology_state.md` - persistent topology snapshot records, history summaries, and local import/export helpers.
- `docs/runtime_session_manager.md` - local runtime session records and summaries for CLI, API, dashboard, and service-preview workflows.
- `docs/unified_configuration_profiles.md` - default, edge-device, and operator-merged local runtime profile records.
- `docs/runtime_state_recovery.md` - local checkpoint records and advisory recovery summaries for interrupted runtime workflows.
- `docs/runtime_cli.md` - `portmap runtime` status, run, recover, reviews, and export commands.
- `docs/runtime_health_monitor.md` - local runtime health checks for storage, scheduler, event queue, reviews, dashboard providers, exports, and sessions.
- `docs/service_mode_readiness.md` - dry-run service-mode preflight checks, command previews, and manual operator checklist.
- `docs/distributed_node_state_sync.md` - trusted-node runtime state normalization, stale/missing detection, and cluster state summaries.
- `docs/federated_topology_aggregation.md` - trusted-node topology snapshot merging with source attribution and conflict summaries.
- `docs/cluster_runtime_health.md` - trusted-node health rollups, resource warnings, local events, and dashboard-ready cluster health panels.
- `docs/distributed_review_queue.md` - trusted-node review aggregation, duplicate detection, finding status rollups, and export-ready review summaries.
- `docs/coordinated_export_bundles.md` - multi-node evidence manifests, cross-node digests, missing-node records, and local archive plans.
- `docs/remote_operator_visibility_prep.md` - read-only trusted-node visibility models and API-ready distributed dashboard panels.
- `docs/trusted_node_transport.md` - trusted-node transport records, local trust profiles, approved peers, handshake summaries, and replay-window metadata.
- `docs/signed_runtime_summary_exchange.md` - canonical digest, signature metadata, and replay-window validation records for trusted runtime summary envelopes.
- `docs/live_cluster_state_synchronization.md` - synchronization windows, signed update classification, replay validation, and merged live cluster summaries.
- `docs/distributed_event_propagation.md` - trusted event propagation envelopes, event replay windows, batch rollups, and dashboard/API-ready propagation summaries.
- `docs/runtime_pipeline.md` - explicit dry-run workflow wiring for visibility, events, topology snapshots, drift, policy review, correlation, and optional local storage writes.
- `docs/dashboard_data_providers.md` - storage-backed, runtime-backed, topology, review, and diagnostic data providers for local dashboard models.
- `docs/operational_export_bundle.md` - local operational export bundles for snapshots, topology, findings, reviews, runtime, and diagnostics.
- `docs/topology_timeline_views.md` - normalized topology graph and historical timeline view models.
- `docs/policy_review_engine.md` - advisory policy evaluation and local operator review queue workflows.
- `docs/operator_review_queue_integration.md` - persistent local review drafts, state history, finding status tracking, and review import/export helpers.

## Visibility And Correlation

- `docs/local_visibility_operator_tooling.md` - local visibility summaries, historical snapshots, baseline deltas, categorized findings, and operator review drafts.
- `docs/examples/` - sanitized JSON examples for testing visibility workflows without local infrastructure data.
- `docs/snapshot_drift_detection.md` - baseline/current topology snapshot diffing and advisory drift records.
- `docs/network_asset_inventory.md` - authorized asset inventory, ARP evidence, reachability checks, and topology context.
- `docs/network_control_layer.md` - advisory gateway and exposed-service posture assessment.
- `docs/distributed_visibility_aggregation.md` - local coordinator aggregation for node visibility summaries with source attribution.
- `docs/behavior_correlation.md` - local baseline comparison for advisory drift, topology, service, and finding deltas.
- `docs/threat_correlation.md` - local event correlation, incident scoring, and supporting evidence.
- `docs/traffic_flow_reconstruction.md` - passive flow grouping, directional counters, and topology summaries.

## Diagnostics And Service Readiness

- `docs/schema_validation_engine.md` - bounded local schema validation and fixture mutation for mock-service diagnostics.
- `docs/metadata_stream_parser.md` - metadata-only local byte-stream parser for fixtures and explicit local files.
- `docs/plugin_registry.md` - governed local plugin manifest registry with dry-run-first controlled execution records.
- `docs/diagnostic_relay_simulator.md` - bounded local relay orchestration simulator for diagnostic session metadata and platform records.
- `docs/service_installer_templates.md` - dry-run Linux and Windows service lifecycle template generation for operator review.

## Network And Protocol Capabilities

- `docs/service_enumeration.md` - service/version detection, banner probes, fingerprints, and CLI usage.
- `docs/os_fingerprinting.md` - probabilistic OS-family inference from passive and service evidence.
- `docs/packet_capture.md` - safe packet metadata capture, PCAP output, filters, and permission handling.
- `docs/protocol_dissectors.md` - passive protocol parsing for captured packet metadata.
- `docs/deep_packet_inspection.md` - passive DPI metadata, findings, redaction, and session summaries.
- `docs/tls_intelligence.md` - TLS version, cipher, certificate, and hostname posture checks.
- `docs/udp_scanning.md` - active UDP probe scanner behavior, safety defaults, and CLI usage.
- `docs/ipv6_dual_stack.md` - IPv4/IPv6 target parsing, CIDR validation, and active dual-stack TCP scan usage.
- `docs/high_speed_scan_engine.md` - async TCP scan scheduler, safe limits, and CLI usage.
- `docs/distributed_cluster_scanning.md` - distributed scan job planning, worker registry, and task scheduling.

## Advisory Intelligence And Enterprise Primitives

- `docs/ai_layer.md` - local AI provider interface and scoring fallbacks.
- `docs/ai_behavioral_learning.md` - local behavior baselines, anomaly scoring, and learning controls.
- `docs/ai_payload_classification.md` - payload labels, suspicious markers, beaconing, and exfiltration indicators.
- `docs/ai_recommendation_engine.md` - advisory recommendations and dry-run remediation drafts.
- `docs/cve_intelligence.md` - advisory CVE normalization, cache updates, and service/version matching.
- `docs/vulnerability_correlation.md` - advisory service/CVE exposure correlation and prioritization.
- `docs/enterprise_security.md` - local enterprise auth, RBAC, audit, and agent identity primitives.
- `docs/enterprise_cloud_orchestration.md` - organization/workspace management, licensing, sync manifests, and review workflows.
- `docs/saas_architecture.md` - future SaaS control-plane, tenant, enrollment, and communication design.
- `docs/alerting_siem_integrations.md` - alert and SIEM payload formatting plus explicit delivery helpers.

## Security And UI

- `docs/security_authentication.md` - bearer-token auth, secret interpolation, and state scrubbing.
- `docs/remediation_safety.md` - remediation safety gates and dry-run enforcement posture.
- `docs/firewall_plugins.md` - firewall plugin model and safety notes.
- `docs/logging_audit.md` - structured logging, audit events, filtering, and export.
- `docs/tui_dashboard.md` - Textual dashboard panels, controls, and data sources.
- `docs/visualization_gui_platform.md` - dashboard risk timeline, topology edges, and flow visualization.
- `docs/beginner_guide.md` - conceptual guide for local network/firewall terminology.
- `docs/api_reference.md` - orchestrator HTTP endpoints and command payloads.

## Current Baseline Commands

- Use the repo-local `portmap-ai-env` created by `scripts/setup_environment.sh`.
- Install development dependencies with `pip install -r requirements-dev.txt`.
- Install the package locally with `pip install -e .`.
- Run the full suite with `python -m pytest`.
- Run the local stack with `portmap stack` or `scripts/run_stack.py`.
- Run the Textual dashboard with `portmap tui`, `scripts/run_dashboard.sh`, or allow the stack launcher to launch it.

The primary dashboard remains the Textual terminal UI. The static HTML dashboard foundation is reusable groundwork for future browser-based operator views.
