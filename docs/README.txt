# PortMap-AI Documentation Index

PortMap-AI is currently a functional local distributed network observability stack with an orchestrator API, master node, worker node, Textual terminal dashboard, remediation audit trail, and local stack launcher.

Start here:
- `PORTMAP_AI_HANDOFF.md` - current system state, verified baseline, and operating notes.
- `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md` - enterprise expansion roadmap from UDP scanning through enterprise orchestration work.
- `docs/ROADMAP.md` - concise current roadmap and post-Phase 40 direction.
- `docs/PHASE_44_53_PLAN.md` - next implementation plan for local event history, storage, coordination, API, dashboard, policy review, aggregation, and correlation.
- `docs/PHASE_HISTORY.md` - concise index of completed phase groups.
- `docs/DEPLOYMENT.md` - deployment paths and validation expectations.
- `docs/SECURITY_MODEL.md` - centralized safety, trust, telemetry, and remediation boundaries.
- `docs/CLI_REFERENCE.md` - command-family reference for the installed `portmap` CLI.
- `docs/real_device_validation.md` - Linux/Raspberry Pi, macOS, and pending Windows validation checklist.
- `docs/master_roadmap.md` - phased roadmap from reproducible setup through release candidate.
- `docs/quick_start.md` - setup, stack launch, dashboard, tests, and log export.
- `docs/architecture.md` - current local-first architecture and component boundaries.
- `test_instructions.md` - focused local verification checklist.
- `docs/deployment_options.md` - default local install path, always-on service path, and optional Docker path.
- `docs/packaging.md` - install, setup, diagnostics, and build artifact guidance.
- `docs/release_candidate.md` - version 0.1.0 release-candidate checklist and known limitations.
- `docs/raspberry_pi_deployment.md` - Linux/ARM service setup and low-resource guidance.
- `docs/configuration.md` - configuration layering, environment placeholders, and runtime settings.
- `docs/alerting_siem_integrations.md` - alert and SIEM payload formatting plus explicit delivery helpers.
- `docs/ai_behavioral_learning.md` - local behavior baselines, anomaly scoring, and learning controls.
- `docs/ai_payload_classification.md` - payload labels, suspicious markers, beaconing, and exfiltration indicators.
- `docs/ai_recommendation_engine.md` - advisory recommendations and dry-run remediation drafts.
- `docs/cve_intelligence.md` - advisory CVE normalization, cache updates, and service/version matching.
- `docs/deep_packet_inspection.md` - passive DPI metadata, findings, redaction, and session summaries.
- `docs/distributed_cluster_scanning.md` - distributed scan job planning, worker registry, and task scheduling.
- `docs/docker_deployment.md` - Docker Compose deployment for orchestrator, master, and worker.
- `docs/enterprise_cloud_orchestration.md` - organization/workspace management, licensing, sync manifests, and review workflows.
- `docs/enterprise_security.md` - local enterprise auth, RBAC, audit, and agent identity primitives.
- `docs/event_pipeline.md` - local-only normalized event model, in-memory queue, and event bus.
- `docs/local_storage.md` - local SQLite storage for events, snapshots, assets, services, topology relationships, and findings.
- `docs/runtime_scheduler.md` - lightweight local scheduler primitives for health checks, event flushing, snapshot refreshes, and policy review refreshes.
- `docs/api_reference.md` - orchestrator HTTP endpoints and command payloads.
- `docs/saas_architecture.md` - future SaaS control-plane, tenant, enrollment, and communication design.
- `docs/network_control_layer.md` - advisory gateway and exposed-service posture assessment.
- `docs/network_asset_inventory.md` - authorized asset inventory, ARP evidence, reachability checks, and topology context.
- `docs/local_visibility_operator_tooling.md` - local visibility summaries, historical snapshots, baseline deltas, categorized findings, and operator review drafts.
- `docs/examples/` - sanitized JSON examples for testing visibility workflows without local infrastructure data.
- `docs/os_fingerprinting.md` - probabilistic OS-family inference from passive and service evidence.
- `docs/packet_capture.md` - safe packet metadata capture, PCAP output, filters, and permission handling.
- `docs/protocol_dissectors.md` - passive protocol parsing for captured packet metadata.
- `docs/service_enumeration.md` - service/version detection, banner probes, fingerprints, and CLI usage.
- `docs/udp_scanning.md` - active UDP probe scanner behavior, safety defaults, and CLI usage.
- `docs/ipv6_dual_stack.md` - IPv4/IPv6 target parsing, CIDR validation, and active dual-stack TCP scan usage.
- `docs/security_authentication.md` - bearer-token auth, secret interpolation, and state scrubbing.
- `docs/firewall_plugins.md` - firewall plugin model and safety notes.
- `docs/high_speed_scan_engine.md` - async TCP scan scheduler, safe limits, and CLI usage.
- `docs/threat_correlation.md` - local event correlation, incident scoring, and supporting evidence.
- `docs/tls_intelligence.md` - TLS version, cipher, certificate, and hostname posture checks.
- `docs/traffic_flow_reconstruction.md` - passive flow grouping, directional counters, and topology summaries.
- `docs/vulnerability_correlation.md` - advisory service/CVE exposure correlation and prioritization.
- `docs/beginner_guide.md` - conceptual guide for local network/firewall terminology.
- `docs/tui_dashboard.md` - Textual dashboard panels, controls, and data sources.
- `docs/visualization_gui_platform.md` - dashboard risk timeline, topology edges, and flow visualization.

Current baseline:
- Use the repo-local `portmap-ai-env` created by `scripts/setup_environment.sh`.
- Install development dependencies with `pip install -r requirements-dev.txt`.
- Install the package locally with `pip install -e .`.
- Run the full suite with `python -m pytest`.
- Run the local stack with `portmap stack` or `scripts/run_stack.py`.
- Run the Textual dashboard with `portmap tui`, `scripts/run_dashboard.sh`, or allow the stack launcher to launch it.
- Review `CHANGELOG.md` and `docs/release_candidate.md` before cutting version `0.1.0`.

The dashboard is a terminal UI, not a browser UI. Browser-based product work belongs to a later roadmap phase.
