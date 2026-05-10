# PORTMAP-AI CODEX HANDOFF
## Phase 19-40 Enterprise Expansion Roadmap

## Project Mission

PortMap-AI is evolving from an AI-assisted port scanner into a modular, cross-platform, enterprise-ready network observability and administrator-controlled remediation orchestration platform.

Phase 19-40 closes technical gaps against tools such as Nmap, RustScan, Masscan, Wireshark, Nessus, SAINT, and SolarWinds Engineer's Toolset without cloning any single tool.

PortMap-AI should become an AI-native convergence platform combining:

- advanced scanning
- packet intelligence
- vulnerability intelligence
- AI behavioral detection
- remediation
- visualization
- distributed orchestration
- SaaS readiness

## Current Assumption

Phases 0-18 are complete. Existing foundation includes orchestrator, master/worker architecture, AI scoring, remediation logic, CLI tooling, structured logs, agent service, health endpoints, modular scanner/remediation structure, early dashboard support, configurable runtime stack, and background service direction.

Do not remove or replace this foundation. Phase 19-40 must extend the current stack.

## Current Progress

- Phase 19 UDP Scanning Engine is implemented locally but not yet committed in the current working tree.
- Phase 20 IPv6 and Dual-Stack Support is implemented locally but not yet committed in the current working tree.
- Phase 21 Network Asset Inventory is implemented locally but not yet committed in the current working tree.
- Phase 22 Service Enumeration is implemented locally but not yet committed in the current working tree.
- Phase 23 OS Fingerprinting is implemented locally but not yet committed in the current working tree.
- Phase 24 High-Speed Multithreaded Scan Engine is implemented locally but not yet committed in the current working tree.
- Phase 25 Packet Capture Core is implemented locally but not yet committed in the current working tree.
- Phase 26 Protocol Dissector Framework is implemented locally but not yet committed in the current working tree.
- Phase 27 Deep Packet Inspection is implemented locally but not yet committed in the current working tree.
- Phase 28 TLS Intelligence Layer is implemented locally but not yet committed in the current working tree.
- Phase 29 Traffic Flow Reconstruction is implemented locally but not yet committed in the current working tree.
- Phase 30 AI Behavioral Learning is implemented locally but not yet committed in the current working tree.
- Phase 31 AI Payload Classification is implemented locally but not yet committed in the current working tree.
- Phase 32 Threat Correlation Engine is implemented locally but not yet committed in the current working tree.
- Phase 33 AI Recommendation Engine is implemented locally but not yet committed in the current working tree.
- Phase 34 CVE Intelligence Engine is implemented locally but not yet committed in the current working tree.
- Phase 35 Vulnerability Correlation System is implemented locally but not yet committed in the current working tree.
- Phase 36 Enterprise Security Layer is implemented locally but not yet committed in the current working tree.
- Phase 37 Alerting and SIEM Integrations is implemented locally but not yet committed in the current working tree.
- Phase 38 Visualization and GUI Platform is implemented locally but not yet committed in the current working tree.
- Phase 39 Distributed Cluster Scanning is implemented locally but not yet committed in the current working tree.
- Phase 40 Enterprise Cloud Orchestration Platform is implemented locally but not yet committed in the current working tree.
- Do not commit until the user explicitly asks.

## Critical Architecture Rule

Do not tightly couple scanning, packet capture, AI scoring, vulnerability matching, GUI, and SaaS logic.

Each major subsystem should remain modular:

```text
core_engine/
ai_agent/
cli/
gui/
docs/
logs/
tests/
data/
```

New features should be added as isolated modules with clean interfaces.

## Safety and Legal Boundary

PortMap-AI must be designed for authorized environments only.

Implement safeguards for rate limiting, scan scope validation, local/private network safe defaults, clear warnings before aggressive scans, and administrator-controlled remediation workflows.

Autonomous remediation must remain configurable:

```text
prompt_mode = ask before action
silent_mode = auto-remediate only when explicitly enabled
dry_run_mode = log actions without applying them
```

## Phase Roadmap

### Phase 19 - UDP Scanning Engine

Goal: Add Nmap-like UDP scan support.

Build:

- `core_engine/modules/udp_scanner.py`
- `tests/test_udp_scanner.py`
- `docs/udp_scanning.md`

Features: UDP probe sender, timeout handling, retry logic, ICMP unreachable interpretation, common UDP service probes for DNS 53, DHCP 67/68, NTP 123, SNMP 161, NetBIOS 137/138, and mDNS 5353.

Acceptance: scan target UDP ports, identify open/closed/filtered/unknown states, avoid indefinite hangs, and produce structured results.

### Phase 20 - IPv6 and Dual-Stack Support

Build `core_engine/modules/ip_utils.py`, `core_engine/modules/ipv6_scanner.py`, `tests/test_ip_utils.py`, and `tests/test_ipv6_scanner.py`.

Support IPv6 target parsing, IPv4/IPv6 detection, dual-stack scan mode, IPv6 CIDR support, and safe rejection of malformed targets.

### Phase 21 - Network Asset Inventory

Build `core_engine/modules/discovery.py`, `tests/test_discovery.py`, and `docs/network_asset_inventory.md`.

Support authorized subnet asset enumeration, ARP-based local device inventory, network reachability validation, TCP transport-layer availability checks, local topology awareness, CIDR range parsing, and orchestrator-ready telemetry handoff.

### Phase 22 - Service Enumeration

Build `core_engine/modules/service_detection.py`, a service fingerprint JSON database, and `tests/test_service_detection.py`.

Implementation note: this workspace's ignored `data/` directory is root-owned, so the reproducible packaged fingerprint baseline is `core_engine/service_fingerprints.json`. The loader still checks `data/service_fingerprints.json` first when that local runtime path is writable.

Support banner grabbing, protocol probes, service fingerprint matching, confidence scoring, and unknown service handling for SSH, HTTP, HTTPS, FTP, SMTP, DNS, SMB, and RDP.

### Phase 23 - OS Fingerprinting

Build `core_engine/modules/os_fingerprint.py`, an OS fingerprint JSON database, and `tests/test_os_fingerprint.py`.

Implementation note: this workspace's ignored `data/` directory is root-owned, so the reproducible packaged fingerprint baseline is `core_engine/os_fingerprints.json`. The loader still checks `data/os_fingerprints.json` first when that local runtime path is writable.

Support TTL analysis, TCP window analysis, TCP option patterns, passive fingerprinting, and confidence scoring without claiming certainty when confidence is low.

### Phase 24 - High-Speed Multithreaded Scan Engine

Build `core_engine/modules/scan_scheduler.py`, `core_engine/modules/async_scanner.py`, and `tests/test_scan_scheduler.py`.

Support async scanning, thread pools, adaptive timing, concurrency limits, scan rate config, safe defaults, and aggressive mode warnings.

### Phase 25 - Packet Capture Core

Build `core_engine/modules/packet_capture.py`, `core_engine/modules/pcap_writer.py`, `tests/test_packet_capture.py`, and `docs/packet_capture.md`.

Support interface selection, live capture, metadata extraction, PCAP save support, capture filters, and graceful permission handling.

Implemented locally: stdlib-only metadata extraction and PCAP writing are available through `portmap capture`. Linux AF_PACKET capture is attempted only where supported; unsupported platforms and missing permissions return structured non-crashing results.

### Phase 26 - Protocol Dissector Framework

Build `core_engine/protocols/` modules for HTTP, DNS, ICMP, TLS, SSH, SMB, DHCP, FTP, and SMTP plus `tests/test_protocols.py`.

Packet capture should classify common protocols and safely label unknown or failed dissections.

Implemented locally: `core_engine.protocols` provides passive dissectors for HTTP, DNS, ICMP/ICMPv6, TLS, SSH, SMB, DHCP, FTP, and SMTP; `portmap capture --dissect` attaches safe summaries to packet metadata without raw payload storage.

### Phase 27 - Deep Packet Inspection

Build `core_engine/modules/dpi.py` and `tests/test_dpi.py`.

Support header extraction, payload metadata extraction, suspicious pattern detection, malformed protocol detection, basic session grouping, redaction controls, and no sensitive payload storage by default.

Implemented locally: `core_engine.modules.dpi` analyzes passive observations and capture packets, supports redacted previews, suspicious/malformed indicators, session grouping, and `portmap dpi` / `portmap capture --dpi` integration without raw payload storage by default.

### Phase 28 - TLS Intelligence Layer

Build `core_engine/modules/tls_inspector.py` and `tests/test_tls_inspector.py`.

Support TLS version detection, cipher suite analysis, certificate expiration checks, weak cipher detection, self-signed warnings, and hostname mismatch detection.

Implemented locally: `core_engine.modules.tls_inspector` provides read-only TLS version, cipher, certificate, expiration, self-signed, and hostname posture analysis. `portmap tls` supports bounded live endpoint checks and offline observation analysis without authentication, exploitation, configuration changes, or remediation.

### Phase 29 - Traffic Flow Reconstruction

Build `core_engine/modules/flow_tracker.py` and `tests/test_flow_tracker.py`.

Support connection lineage, source/destination tracking, protocol flow grouping, time-based session windows, and flow summaries for GUI/topology use.

Implemented locally: `core_engine.modules.flow_tracker` reconstructs passive bidirectional flows from packet metadata, capture rows, DPI records, and nested metadata observations. `portmap flows` and explicit `portmap capture --flows` produce JSON-serializable flow and topology summaries without raw payload storage.

### Phase 30 - AI Behavioral Learning

Build `ai_agent/behavior_model.py`, `ai_agent/baseline_store.py`, and `tests/test_behavior_model.py`.

Support device behavior profiles, normal port baselines, time-of-day baselines, anomaly scoring, drift handling, and safe baseline storage.

Implemented locally: `ai_agent.baseline_store` and `ai_agent.behavior_model` provide local JSON behavior baselines, per-device profile counts, time-of-day buckets, advisory anomaly scoring, and explicit opt-in learning through `portmap behavior --learn` without raw payload storage or remediation side effects.

### Phase 31 - AI Payload Classification

Build `ai_agent/payload_classifier.py` and `tests/test_payload_classifier.py`.

Support beaconing detection, suspicious payload metadata, protocol misuse detection, possible exfiltration indicators, and confidence scoring.

Implemented locally: `ai_agent.payload_classifier` classifies safe payload observations and metadata, detects suspicious content markers, protocol misuse, beaconing candidates, and possible exfiltration indicators. `portmap payload` exposes offline JSON classification with bounded redacted previews only when explicit.

### Phase 32 - Threat Correlation Engine

Build `ai_agent/threat_correlation.py` and `tests/test_threat_correlation.py`.

Support cross-node correlation, repeated anomaly linking, lateral movement indicators, suspicious scan behavior, chained event scoring, explanations, and supporting evidence.

Implemented locally: `ai_agent.threat_correlation` normalizes events across behavior, payload, flow, scan, service, OS, TLS, and generic records, then emits advisory incidents for repeated anomalies, suspicious scan behavior, lateral movement indicators, and chained behavior/payload risk. `portmap correlate` exposes offline local correlation.

### Phase 33 - AI Recommendation Engine

Build `ai_agent/recommendation_engine.py` and `tests/test_recommendation_engine.py`.

Support suggested firewall rules, service shutdowns, segmentation guidance, risk explanations, confidence scores, and prompt-mode remediation approval.

Implemented locally: `ai_agent.recommendation_engine` consumes Phase 32 correlated incidents and emits advisory recommendations for investigation, scan-source review, segmentation review, host evidence collection, credential rotation, egress policy review, and dry-run containment drafts. Destructive drafts are always approval-required, dry-run, unconfirmed, and never executed automatically. `portmap recommend` exposes offline local recommendation generation.

### Phase 34 - CVE Intelligence Engine

Build `core_engine/vuln/cve_client.py`, `core_engine/vuln/cve_store.py`, `core_engine/vuln/cvss.py`, and `tests/test_cve_client.py`.

Support NVD integration, local CVE cache, CVSS scoring, service/version to CVE matching, and an update command.

Implemented locally: `core_engine.vuln` normalizes NVD-style and local CVE records, extracts CVSS/severity/CWE/CPE/reference evidence, persists a local advisory cache, optionally fetches NVD records only through explicit `portmap cve --update`, and matches service/version evidence to CVEs with confidence and advisory risk scores. Offline `portmap cve --service-json ... --cve-json ...` matching is available for local advisory analysis.

### Phase 35 - Vulnerability Correlation System

Build `core_engine/vuln/vuln_correlator.py` and `tests/test_vuln_correlator.py`.

Support open port + service + CVE correlation, exposed service prioritization, exploitability indicators, known exploited flags, ransomware association fields, and explainable prioritization.

Implemented locally: `core_engine.vuln.vuln_correlator` prioritizes advisory vulnerability findings from service evidence and CVE matches, classifies exposure scope, detects exploitability indicators, propagates known-exploited/ransomware context, explains prioritization, and exposes offline local analysis through `portmap vuln`.

### Phase 36 - Enterprise Security Layer

Build enterprise security modules for auth, RBAC, audit, and agent identity plus focused tests.

Support JWT auth, local users, RBAC roles (`admin`, `analyst`, `viewer`, `agent`), audit trails, secure agent identity, and mTLS-ready design.

Implemented locally: `core_engine.enterprise_auth`, `core_engine.rbac`, `core_engine.enterprise_audit`, and `core_engine.agent_identity` provide signed local tokens, PBKDF2 password records, RBAC decisions, scrubbed enterprise audit events, generated agent secrets, HMAC agent signatures, and mTLS-ready certificate fingerprint fields. `portmap rbac` exposes local role/permission inspection without replacing development auth defaults.

### Phase 37 - Alerting and SIEM Integrations

Build `core_engine/integrations/` modules for Splunk, Elastic, Sentinel, webhook, and email plus tests.

Support webhook alerts, email alerts, Slack/Teams-compatible webhook formats, Splunk HEC, Elastic output, Sentinel-ready JSON, and failure isolation.

Implemented locally: `core_engine.integrations` formats generic webhook, Slack, Teams, Splunk HEC, Elastic, Sentinel, and email alert payloads, defaults delivery to dry-run, requires explicit `--send`, and isolates delivery failures as structured results. `portmap alert` exposes local formatting and explicit delivery options without persisting secrets.

### Phase 38 - Visualization and GUI Platform

Build dashboard, topology, flows, and reusable GUI components.

Support live dashboard, scan result view, risk score view, topology maps, traffic flow visualization, educational overlays, remediation approval UI, and historical analytics.

Implemented locally: `gui.visualization` provides reusable risk timeline, topology edge, traffic flow, and dashboard summary helpers. The Textual dashboard now renders Risk Timeline, Topology Edges, and Traffic Flows panels from passive flow telemetry when available, keeps visualization read-only, stores no raw payload bytes, and preserves the terminal-first dashboard path.

### Phase 39 - Distributed Cluster Scanning

Build `core_engine/cluster/job_queue.py`, `core_engine/cluster/scheduler.py`, `core_engine/cluster/worker_registry.py`, and `tests/test_cluster_scanning.py`.

Support distributed scan jobs, worker registration, health checks, job balancing, failed-job retries, partial result aggregation, and multi-worker scans.

Implemented locally: `core_engine.cluster` provides worker health/capacity registry helpers, a distributed job/task queue, retry/result aggregation primitives, and a dry-run scheduler that partitions authorized target/port sets into planned tasks without executing scans. `portmap cluster plan` exposes dry-run planning for local validation.

### Phase 40 - Enterprise Cloud Orchestration Platform

Build `saas/` tenancy, organization, licensing, and cloud-sync helpers plus administrator-facing advisory workflow primitives.

Support organization and workspace management, tenant records, team associations, RBAC inheritance, license metadata, usage counters, quota tracking, feature gating, optional encrypted sync manifests, export/import, sync conflict handling, and administrator-controlled recommendation workflows.

Implemented locally: `saas.tenancy`, `saas.orgs`, `saas.licensing`, `saas.cloud_sync`, and `core_engine.advisory.workflow` provide local/offline enterprise cloud-orchestration primitives. `portmap workspace`, `portmap license`, `portmap cloud-sync`, and `portmap advisory` expose local workflows without hosted infrastructure, network sync, billing-provider calls, or remediation execution.

## Required Engineering Standards

Every phase must include tests, docs, CLI/API integration where applicable, structured logging, error handling, safe defaults, config support, orchestrator compatibility, no hardcoded secrets, and no destructive default behavior.

## Milestones

- Milestone A, Nmap-class scanner: Phases 19-24.
- Milestone B, Wireshark-lite intelligence: Phases 25-29.
- Milestone C, AI vulnerability platform: Phases 30-35.
- Milestone D, enterprise/SaaS platform: Phases 36-40.

## Codex Working Instructions

1. Inspect the current repo structure first.
2. Do not assume missing files exist.
3. Preserve existing public interfaces unless clearly broken.
4. Add new modules instead of overloading old ones.
5. Keep functions small and testable.
6. Add docstrings.
7. Add tests before moving to the next phase.
8. Use safe defaults.
9. Keep administrator approval on remediation workflows that can change local system or network policy.
10. Update documentation after each phase.

## Immediate Next Step

Phase 40: Enterprise Cloud Orchestration Platform is complete after full Phase 40 verification.

Implemented target:

```text
saas/
saas/tenancy.py
saas/orgs.py
saas/licensing.py
saas/cloud_sync.py
core_engine/advisory/
tests/test_enterprise_cloud_orchestration.py
docs/enterprise_cloud_orchestration.md
```

Phases 19-40 are stable locally but not committed. Phase 40 is scoped to local organization/workspace management, licensing/usage metrics, optional encrypted sync manifests, and administrator review workflows.
