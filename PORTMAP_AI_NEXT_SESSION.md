# PortMap-AI Next Session Handoff

## Current State

PortMap-AI has completed Phases 0 through 18 of the master roadmap and has completed the enterprise expansion roadmap with Phases 19 through 40.

Latest verified baseline:

- Full test suite: `154 passed, 1 skipped`
- Focused Phase 16-18 tests: `14 passed`
- Wheel build smoke: `portmap_ai-0.1.0-py3-none-any.whl` built successfully
- `portmap --help` works from the repo-local environment
- `portmap doctor --output json` runs and reports overall `ok: true`
- GitHub-readiness cleanup completed and full suite still passes: `154 passed, 1 skipped`
- Phase 19 focused tests pass for UDP scanner, CLI, and packaging.
- Full-suite verification after Phase 19 passes: `164 passed, 1 skipped`.
- Phase 20 focused tests pass for IP utilities, dual-stack scanner, CLI, and packaging.
- Full-suite verification after Phase 20 passes: `178 passed, 1 skipped`.
- Phase 21 focused tests pass for discovery, CLI, and packaging.
- Full-suite verification after Phase 21 passes: `191 passed, 1 skipped`.
- Phase 22 focused tests pass for service detection, CLI, and packaging.
- Full-suite verification after Phase 22 passes: `203 passed, 1 skipped`.
- Phase 23 focused tests pass for OS fingerprinting, CLI, and packaging.
- Full-suite verification after Phase 23 passes: `212 passed, 1 skipped`.
- Phase 24 focused tests pass for scan scheduler, async scanner, CLI, and packaging.
- Full-suite verification after Phase 24 passes: `224 passed, 1 skipped`.
- Phase 25 focused tests pass for packet capture, CLI, and packaging.
- Runtime CLI smoke for packet capture returns graceful unsupported-backend output on macOS.
- Full-suite verification after Phase 25 passes: `233 passed, 1 skipped`.
- Phase 26 focused tests pass for protocol dissectors, packet capture, CLI, and packaging.
- Runtime CLI smoke for capture dissection returns graceful unsupported-backend output on macOS.
- Full-suite verification after Phase 26 passes: `243 passed, 1 skipped`.
- Phase 27 focused tests pass for DPI, packet capture, CLI, and packaging.
- Runtime CLI smoke for `portmap dpi` redacts sensitive preview values; capture DPI returns graceful unsupported-backend output on macOS.
- Full-suite verification after Phase 27 passes: `252 passed, 1 skipped`.
- Phase 28 focused tests pass for TLS intelligence, CLI, and packaging.
- Runtime CLI smoke for `portmap tls --observation-json ...` reports deprecated TLS/cipher/certificate warnings without network access.
- Full-suite verification after Phase 28 passes: `263 passed, 1 skipped`.
- Phase 29 focused tests pass for traffic flow reconstruction, packet capture, CLI, and packaging.
- Runtime CLI smoke for `portmap flows --events-json ...` produces flow/topology JSON; capture flows returns graceful unsupported-backend output on macOS.
- Full-suite verification after Phase 29 passes: `272 passed, 1 skipped`.
- Phase 30 focused tests pass for AI behavioral learning, CLI, and packaging.
- Runtime CLI smoke for `portmap behavior --events-json ...` reports advisory anomaly output without writing a baseline.
- Full-suite verification after Phase 30 passes: `282 passed, 1 skipped`.
- Phase 31 focused tests pass for AI payload classification, CLI, and packaging.
- Runtime CLI smoke for `portmap payload --events-json ...` reports sensitive-cleartext findings without echoing raw secrets.
- Full-suite verification after Phase 31 passes: `292 passed, 1 skipped`.
- Phase 32 focused tests pass for threat correlation, CLI, and packaging.
- Runtime CLI smoke for `portmap correlate --events-json ...` produces repeated-anomaly incident output.
- Full-suite verification after Phase 32 passes: `301 passed, 1 skipped`.
- Phase 33 focused tests pass for AI recommendations, CLI, and packaging.
- Runtime CLI smoke for `portmap recommend --incidents-json ...` produces dry-run approval-required containment drafts.
- Full-suite verification after Phase 33 passes: `309 passed, 1 skipped`.
- Phase 34 focused tests pass for CVE intelligence, CLI, and packaging.
- Runtime CLI smoke for `portmap cve --service-json ... --cve-json ...` produces advisory CVE matches without network access.
- Full-suite verification after Phase 34 passes: `317 passed, 1 skipped`.
- Phase 35 focused tests pass for vulnerability correlation, CVE intelligence, CLI, and packaging.
- Runtime CLI smoke for `portmap vuln --service-json ... --cve-matches-json ...` produces critical advisory findings without network access.
- Full-suite verification after Phase 35 passes: `325 passed, 1 skipped`.
- Phase 36 focused tests pass for enterprise security, existing security/enrollment helpers, CLI, and packaging.
- Runtime CLI smoke for `portmap rbac --roles analyst --permission generate:recommendations --output json` grants the expected inherited permissions.
- Full-suite verification after Phase 36 passes: `334 passed, 1 skipped`.
- Phase 37 focused tests pass for alert/SIEM integrations, CLI, and packaging.
- Runtime CLI smoke for `portmap alert --event-json ... --format slack --output json` produces a dry-run Slack-compatible payload without sending network traffic.
- Full-suite verification after Phase 37 passes: `341 passed, 1 skipped`.
- Phase 38 focused tests pass for visualization/dashboard helpers and packaging.
- Runtime dashboard construction smoke imports `PortMapDashboard` and visualization helpers without launching an interactive TUI.
- Full-suite verification after Phase 38 passes: `345 passed, 1 skipped`.
- Phase 39 focused tests pass for distributed cluster planning, CLI, and packaging.
- Runtime CLI smoke for `portmap cluster plan --target 127.0.0.1 --ports 80,443 --worker worker-a --worker worker-b --output json` produces a dry-run planned job without scanning.
- Full-suite verification after Phase 39 passes: `354 passed, 1 skipped`.
- Phase 40 focused tests pass for enterprise cloud orchestration primitives, CLI, and packaging.
- Runtime CLI smokes for `portmap workspace`, `portmap license`, `portmap cloud-sync`, and `portmap advisory` pass locally.
- Full-suite verification after Phase 40 passes: `366 passed, 1 skipped`.
- Current next step: Phase 40 is complete. Do not commit until the user asks.

## Important Product Direction

PortMap-AI is multi-platform:

- macOS: supported development/local CLI/TUI baseline.
- Linux: supported local/server baseline.
- Linux/ARM/Raspberry Pi OS: supported through the same package, low-resource profile, and systemd templates.
- Windows: experimental/future for native service packaging.

Do not make Raspberry Pi or Docker the only path.

Deployment options are:

1. Local install/CLI - recommended default.
2. Native service mode - always-on Linux/Raspberry Pi path.
3. Docker Compose - optional advanced container path.

Docker should not be auto-installed for users.

GitHub-readiness rules:

- Do not commit runtime logs, local state, virtual environments, build output, archives, or generated JSONL files.
- Docker Compose requires an explicit `PORTMAP_ORCHESTRATOR_TOKEN`; it must not fall back to `test-token`.
- Default local master binding is `127.0.0.1`, not `0.0.0.0`.
- Shared/remote deployments need long random tokens and firewall rules.

## Completed Phases

### Phase 0 - Reproducible Setup

- Runtime and dev requirements are defined.
- Repo-local `portmap-ai-env` is the standard environment.
- Stack, tests, TUI, and docs are reproducible.

### Phase 1 - CLI Interface

- Unified `portmap` CLI exists.
- Commands include scan, stack, tui, health, nodes, metrics, logs, config validate, setup, doctor, and network.

### Phase 2 - Packaged Local Install

- `pyproject.toml` defines package metadata and console scripts.
- Editable and wheel install paths are supported.

### Phase 3 - Configuration Hardening

- Config validation exists in `core_engine.config_validation`.
- Runtime services validate configs before startup.
- `portmap config validate` is available.

### Phase 4 - Platform Abstraction

- `core_engine.platform_utils` centralizes OS/process/network helpers.

### Phase 5 - Stack Stability

- Stack launcher supervises services, handles restarts, detects port conflicts, and shuts down cleanly.
- Worker/agent re-register after orchestrator state loss.

### Phase 6 - Logging and Audit

- Structured JSONL audit events exist.
- Log export and filtering are available through `portmap logs`.

### Phase 7 - Remediation Safety

- Destructive remediation is dry-run by default.
- Active destructive action requires explicit policy and confirmation.

### Phase 8 - Scanner and Risk Engine

- Risky-port database exists.
- Scanner rows include service hints.
- Scoring produces score factors and explanations.

### Phase 9 - AI Layer

- `ai_agent.interface` defines provider/result contracts.
- Local heuristic/ML provider remains default.
- Provider failures fall back safely.

### Phase 10 - TUI Improvements

- Textual dashboard shows nodes, metrics, scan results, remediation feed, command outcomes, expected services, and log tail.

### Phase 11 - Docker Deployment

- `docker-compose.yml` exists.
- Docker-specific configs and Dockerfiles exist.
- Docker remains optional.
- Local machine did not have Docker Compose plugin, so runtime compose smoke was not possible here.

### Phase 12 - Raspberry Pi / Linux Service Deployment

- `config/profiles/raspberry_pi.json` exists.
- User-scoped systemd templates exist under `deploy/systemd/`.
- `scripts/install_systemd_user.sh` exists.
- Raspberry Pi is treated as Linux/ARM support, not a separate architecture.

### Phase 13 - Packaging

- `portmap setup` initializes runtime paths/settings.
- `portmap doctor` reports platform/package readiness.
- `docs/packaging.md` exists.

### Phase 14 - Network Control Layer

- `core_engine.network_control` exists.
- `portmap network` reports gateway/local-network/exposed-service posture.
- It is advisory-only and makes no router/firewall/NAT/port-forward changes.

### Phase 15 - Security and Authentication

- `core_engine.security` exists.
- Bearer-token auth uses constant-time comparison.
- `${secret:ENV_VAR}` config interpolation works.
- Orchestrator registration/heartbeat/command paths validate node identity.
- Command payloads must be objects.
- Secret-like metadata is scrubbed before orchestrator state persistence.
- `docs/security_authentication.md` exists.

### Phase 16 - SaaS Preparation

- `core_engine.enrollment` defines local-only tenant identity, enrollment request, enrollment package, and agent identity schemas.
- Enrollment validation covers tenant/org/node identity, role, token shape, control-plane URL shape, and expiry type.
- Agent identity stores a token fingerprint instead of the raw enrollment secret.
- `docs/saas_architecture.md` documents the future control plane, multi-tenant model, enrollment flow, communication model, and non-implemented SaaS scope.

### Phase 17 - Documentation

- `docs/architecture.md` documents the current local-first architecture.
- `docs/README.txt` links setup, usage, deployment, security, SaaS, and release-candidate guides.
- `test_instructions.md` includes Phase 16-18 verification.

### Phase 18 - Release Candidate

- `pyproject.toml` version is `0.1.0`.
- `CHANGELOG.md` exists.
- `docs/release_candidate.md` defines scope, verification checklist, package notes, known limitations, and release decision.
- Release-candidate tests verify version/docs alignment.

### GitHub Readiness Cleanup

- `SECURITY.md` exists.
- Docker Compose now requires explicit `PORTMAP_ORCHESTRATOR_TOKEN`.
- Default local master config now binds to `127.0.0.1`.
- Stack-launcher token mismatch errors use token fingerprints, not raw token values.
- Systemd install helper creates `~/.portmap-ai/portmap-ai.env` with a generated token when absent.
- Runtime logs/state were removed from the Git index and ignore rules were expanded.
- Stale planning docs, sandbox simulation files, deprecated core-engine experiments, and `scriptsrun_orchestrator.bat` were removed.
- Root-owned old runtime files may still exist locally under ignored `data/` or `core_engine/logs/`; they are removed from Git and ignored.

### Phase 19 - UDP Scanning Engine

- `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md` exists as the Phase 19-40 roadmap.
- `core_engine.modules.udp_scanner` exists.
- UDP probes cover DNS, DHCP, NTP, SNMP, NetBIOS, and mDNS.
- Results classify `open`, `closed`, `filtered`, or `unknown`.
- `portmap scan --udp-target <target> --udp-ports 53,123 --output json` is available.
- `docs/udp_scanning.md` exists.
- Focused tests pass: `tests/test_udp_scanner.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 19: `164 passed, 1 skipped`.

### Phase 20 - IPv6 and Dual-Stack Support

- `core_engine.modules.ip_utils` exists.
- `core_engine.modules.ipv6_scanner` exists.
- Target parsing supports IPv4 literals, IPv6 literals, bracketed IPv6, hostnames, and CIDR ranges.
- Active TCP scans support `portmap scan --target <target> --ports 80,443 --ip-version auto|4|6`.
- Results include `tcp_state`, `ip_version`, `target_source`, and reason fields.
- Safe target/port limits and aggressive-mode limits are implemented.
- `docs/ipv6_dual_stack.md` exists.
- Focused tests pass: `tests/test_ip_utils.py`, `tests/test_ipv6_scanner.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 20: `178 passed, 1 skipped`.

### Phase 21 - Network Asset Inventory

- `core_engine.modules.discovery` exists.
- Network asset inventory supports administrator-defined IPs, hostnames, and CIDR ranges.
- `portmap discover` falls back to detected local networks when no range is supplied.
- ARP table parsing supports common macOS, Linux, and Windows output shapes.
- Optional platform ping checks and TCP transport availability checks produce structured evidence.
- Local topology snapshots include gateway, local networks, broadcast candidates, and optional ARP inventory.
- Inventory rows include asset status, methods, evidence, MAC/interface, target source, IP version, and open/closed transport ports.
- `asset_telemetry_events()` produces orchestrator-ready telemetry payloads without coupling inventory to SaaS or remediation.
- `portmap discover --range <authorized-range> --method arp --method tcp --output json` is available.
- `docs/network_asset_inventory.md` exists.
- Focused tests pass: `tests/test_discovery.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 21: `191 passed, 1 skipped`.

### Phase 22 - Service Enumeration

- `core_engine.modules.service_detection` exists.
- Packaged fingerprint database exists at `core_engine/service_fingerprints.json`.
- The loader also checks `data/service_fingerprints.json` first when that ignored runtime path is writable.
- Safe banner/protocol probes support SSH, HTTP, HTTPS, FTP, SMTP, DNS, SMB, and RDP.
- `portmap services --target <target> --ports 22,80,443 --output json` is available.
- Service rows include target, remote endpoint, state, service, version, confidence, banner, probe, evidence, and reason.
- Enumeration does not exploit services, submit credentials, brute force authentication, or trigger remediation.
- `docs/service_enumeration.md` exists.
- Focused tests pass: `tests/test_service_detection.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 22: `203 passed, 1 skipped`.

### Phase 23 - OS Fingerprinting

- `core_engine.modules.os_fingerprint` exists.
- Packaged OS fingerprint database exists at `core_engine/os_fingerprints.json`.
- The loader also checks `data/os_fingerprints.json` first when that ignored runtime path is writable.
- OS-family support covers Windows, Linux, macOS, BSD, and network appliances.
- Passive observations can include TTL, TCP window size, TCP options, services, banners, and service results.
- Active context reuses safe Phase 22 service enumeration; no raw packet crafting is used.
- `portmap os --target <target> --ports 22,80,443 --output json` is available.
- `portmap os --observation-json '{...}' --output json` is available for passive-only inference.
- Low-confidence results are reported as `unknown` with candidate explanations.
- `docs/os_fingerprinting.md` exists.
- Focused tests pass: `tests/test_os_fingerprint.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 23: `212 passed, 1 skipped`.

### Phase 24 - High-Speed Multithreaded Scan Engine

- `core_engine.modules.scan_scheduler` exists.
- `core_engine.modules.async_scanner` exists.
- Scheduler supports target/port expansion, concurrency limits, rate limits, batch estimates, adaptive delay helpers, and aggressive-mode warnings.
- Async scanner uses safe TCP connect probes and emits rows compatible with existing active TCP scan output.
- `portmap fast-scan --target <target> --ports 80,443 --output json` is available.
- Default limits are conservative: targets, ports, concurrency, and probe rate are capped unless aggressive mode is explicit.
- High-speed scanning does not use raw packets, spoofing, SYN flooding, exploitation, credential behavior, or remediation.
- `docs/high_speed_scan_engine.md` exists.
- Focused tests pass: `tests/test_scan_scheduler.py`, `tests/test_async_scanner.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 24: `224 passed, 1 skipped`.

### Phase 25 - Packet Capture Core

- `core_engine.modules.packet_capture` exists.
- `core_engine.modules.pcap_writer` exists.
- Packet metadata extraction supports Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and ARP labels without storing payload bytes in JSON rows.
- Capture filters support protocol, host, source/destination host, port, and source/destination port matching.
- `portmap capture --duration <seconds> --max-packets <n> --filter tcp --output json` is available.
- `--pcap <path>` writes filtered packets to a classic PCAP file only when the operator requests it.
- Linux live capture uses a stdlib AF_PACKET backend when available; unsupported platforms and missing permissions return structured capability results.
- Packet capture does not craft packets, spoof traffic, exploit services, collect credentials, change network settings, or trigger remediation.
- `docs/packet_capture.md` exists.
- Focused tests pass: `tests/test_packet_capture.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 25: `233 passed, 1 skipped`.

### Phase 26 - Protocol Dissector Framework

- `core_engine.protocols` package exists.
- Protocol-specific passive dissectors cover HTTP, DNS, ICMP, ICMPv6, TLS, SSH, SMB, DHCP, FTP, and SMTP.
- Dispatcher helpers support Ethernet/IP/TCP/UDP/ICMP payload extraction, protocol classification, direct payload dissection, and packet-level dissection.
- `portmap capture --dissect` attaches safe protocol summaries to captured packet metadata.
- Default capture output remains metadata-only unless `--dissect` is explicit.
- Dissection rows include protocol, status, confidence, summary, fields, evidence, payload byte counts, and errors without raw payload storage.
- Unknown, unsupported, short, and malformed payloads are labeled safely.
- FTP and SMTP sensitive command arguments are redacted.
- Protocol dissection is passive and performs no packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/protocol_dissectors.md` exists.
- Focused tests pass: `tests/test_protocols.py`, `tests/test_packet_capture.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 26: `243 passed, 1 skipped`.

### Phase 27 - Deep Packet Inspection

- `core_engine.modules.dpi` exists.
- DPI analyzes packet bytes, payload observations, protocol dissection results, and capture metadata without raw payload storage by default.
- Payload metadata includes length, SHA-256, entropy, printable ratio, null-byte count, content category, and optional redacted previews.
- Suspicious indicators cover credential markers, script injection markers, SQL injection markers, shell command markers, high-entropy payloads, cleartext FTP/SMTP identity/auth commands, and cleartext HTTP login-like flows.
- Malformed protocol indicators cover parser errors, unknown payloads for known protocols, and truncated TLS records.
- Bidirectional session keys and basic session grouping summaries are available for future flow/correlation layers.
- `portmap dpi --observation-json ...` is available.
- `portmap capture --dpi` attaches passive DPI summaries to captured packet metadata.
- DPI is passive and performs no packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/deep_packet_inspection.md` exists.
- Focused tests pass: `tests/test_dpi.py`, `tests/test_packet_capture.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 27: `252 passed, 1 skipped`.

### Phase 28 - TLS Intelligence Layer

- `core_engine.modules.tls_inspector` exists.
- TLS intelligence analyzes TLS protocol version, cipher-suite posture, certificate metadata, expiration, self-signed status, and hostname matching.
- Live TLS handshakes are bounded by safe target/port limits and use read-only connection attempts.
- Offline observation analysis is available for deterministic tests and operator-provided evidence.
- `portmap tls --target <target> --ports 443 --server-name <name> --output json` is available.
- `portmap tls --observation-json '{...}' --output json` is available without network access.
- TLS rows include target, port, server name, TLS version status, cipher analysis, certificate analysis, warnings, and advisory risk score.
- Weak posture indicators cover deprecated TLS, RC4, DES/3DES, MD5, NULL, EXPORT, anonymous suites, small key sizes, expiring or expired certificates, self-signed certificates, and hostname mismatches.
- TLS intelligence is read-only and performs no packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/tls_intelligence.md` exists.
- Focused tests pass: `tests/test_tls_inspector.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 28: `263 passed, 1 skipped`.

### Phase 29 - Traffic Flow Reconstruction

- `core_engine.modules.flow_tracker` exists.
- Flow reconstruction consumes packet metadata, capture rows, DPI records, and nested metadata observations.
- Flow records include bidirectional keys, stable flow IDs, initiator/responder lineage, time-windowed session splitting, packet counts, payload byte counts, captured byte counts, directional counters, transports, application protocols, findings, and evidence.
- Topology summaries include per-IP nodes and initiator-to-responder edges for future GUI/topology and AI correlation layers.
- `portmap flows --events-json '[...]' --window 60 --output json` is available for offline flow reconstruction.
- `portmap capture --flows` attaches passive flow summaries to explicit capture output.
- Flow reconstruction stores no raw payload bytes and performs no packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/traffic_flow_reconstruction.md` exists.
- Focused tests pass: `tests/test_flow_tracker.py`, `tests/test_packet_capture.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 29: `272 passed, 1 skipped`.

### Phase 30 - AI Behavioral Learning

- `ai_agent.baseline_store` exists.
- `ai_agent.behavior_model` exists.
- Local behavior baselines default to `~/.portmap-ai/data/behavior_baseline.json`.
- Behavior profiles learn per-device event counts, normal destination ports, peers, application protocols, transports, and active hour buckets.
- Analysis accepts packet, flow, scan, service, DPI, and nested metadata observations.
- Findings cover new devices, new destination ports, new peers, new application protocols, unusual hours, rare values, and low-confidence baselines.
- `portmap behavior --events-json '[...]' --output json` analyzes without writing the baseline.
- `portmap behavior --events-json '[...]' --learn --output json` explicitly updates the baseline.
- Behavioral learning stores no raw payload bytes and performs no packet capture, packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/ai_behavioral_learning.md` exists.
- Focused tests pass: `tests/test_behavior_model.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 30: `282 passed, 1 skipped`.

### Phase 31 - AI Payload Classification

- `ai_agent.payload_classifier` exists.
- Payload classification accepts `payload_text`, `payload_hex`, `payload_b64`, existing payload metadata, and nested network metadata.
- Classifications include labels, confidence, advisory risk scores, protocol/network context, safe payload metadata, findings, and `raw_payload_stored: false`.
- Findings cover credential markers, script injection markers, SQL injection markers, command markers, high-entropy payloads, cleartext sensitive payloads, protocol misuse, possible tunneled payloads, possible exfiltration payloads, public-destination exfiltration volume, and beaconing candidates.
- `portmap payload --events-json '{...}' --output json` is available.
- `--include-payload-preview` includes only bounded redacted previews.
- Payload classification stores no raw payload bytes by default and performs no packet capture, packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/ai_payload_classification.md` exists.
- Focused tests pass: `tests/test_payload_classifier.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 31: `292 passed, 1 skipped`.

### Phase 32 - Threat Correlation Engine

- `ai_agent.threat_correlation` exists.
- Event normalization supports behavior, payload, flow, scan, service, OS, TLS, and generic records.
- Correlation detects repeated anomalies, suspicious scan behavior, lateral movement indicators, and chained behavior/payload risk.
- `portmap correlate --events-json '[...]' --window 300 --output json` is available.
- Incident records include stable IDs, severity, score, entity, first/last seen timestamps, peers, ports, findings, event IDs, explanations, and supporting evidence summaries.
- Threat correlation stores no raw payload bytes and performs no packet capture, packet crafting, authentication, brute force, exploitation, network configuration, or remediation.
- `docs/threat_correlation.md` exists.
- Focused tests pass: `tests/test_threat_correlation.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.
- Full suite passes after Phase 32: `301 passed, 1 skipped`.

### Phase 33 - AI Recommendation Engine

- `ai_agent.recommendation_engine` exists.
- Recommendations consume Phase 32 correlated incident rows.
- Actions include investigation, scan-source review, segmentation review, host evidence collection, credential rotation, egress policy review, and dry-run remediation drafts.
- `portmap recommend --incidents-json '{...}' --output json` is available.
- Recommendation rows include stable IDs, incident linkage, action, target, priority, confidence, reason, operator prompt, supporting evidence, approval flags, and optional remediation command drafts.
- Destructive drafts are always `approval_required: true`, `dry_run: true`, `confirmed: false`, and `destructive: true`.
- Recommendation output stores no raw payload bytes, performs no automatic changes, and executes no remediation.
- `docs/ai_recommendation_engine.md` exists.
- Focused tests pass: `tests/test_recommendation_engine.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

### Phase 34 - CVE Intelligence Engine

- `core_engine.vuln.cve_client`, `core_engine.vuln.cve_store`, and `core_engine.vuln.cvss` exist.
- CVE normalization supports NVD-style records, normalized records, CVSS metrics, severity, CWE IDs, CPE criteria, references, and known-exploited flags when provided.
- Service/version matching uses service aliases, CPE evidence, version tokens, confidence scoring, and advisory risk scoring.
- `portmap cve --service-json ... --cve-json ... --output json` is available for offline matching.
- `portmap cve --update --query ...` or `--cve-id ...` explicitly fetches from NVD and updates the local advisory cache.
- Local cache defaults to `~/.portmap-ai/data/cve_cache.json` and supports custom `--cache` paths.
- CVE output stores no raw payload bytes, performs no automatic remediation, and does not use network access unless `--update` is provided.
- `docs/cve_intelligence.md` exists.
- Focused tests pass: `tests/test_cve_client.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

### Phase 35 - Vulnerability Correlation System

- `core_engine.vuln.vuln_correlator` exists.
- Vulnerability findings combine service evidence, CVE matches, exposure scope, CVSS/risk score, known-exploited flags, ransomware association fields, and exploitability indicators.
- Exposure classification covers public interfaces, all-interface binds, LAN exposure, open/listening state, and unknown scope.
- Exploitability indicators include remote code execution, authentication bypass, privilege escalation, path traversal, SQL injection, credential exposure, denial of service, and known-exploited evidence.
- `portmap vuln --service-json ... --cve-matches-json ... --output json` is available for prioritizing existing CVE match output.
- `portmap vuln --service-json ... --cve-json ... --output json` can run raw service/CVE matching and prioritization in one local command.
- Output stores no raw payload bytes, performs no automatic remediation, and does not use network access.
- `docs/vulnerability_correlation.md` exists.
- Focused tests pass: `tests/test_vuln_correlator.py`, `tests/test_cve_client.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

### Phase 36 - Enterprise Security Layer

- `core_engine.enterprise_auth`, `core_engine.rbac`, `core_engine.enterprise_audit`, and `core_engine.agent_identity` exist.
- Enterprise tokens are stdlib-only HS256 tokens with subject, roles, issuer, audience, not-before, issued-at, and expiration validation.
- Password records use PBKDF2-SHA256; public user records expose only a hash fingerprint.
- RBAC roles are `admin`, `analyst`, `viewer`, and `agent`, with analyst/admin inheritance and explicit permission checks.
- Enterprise audit events use `event_type: enterprise_security` and scrub secret-like metadata.
- Agent identities store only secret fingerprints, can generate one-time secrets, support HMAC message signatures, timestamp-skew validation, and mTLS-ready certificate fingerprints.
- `portmap rbac --roles ... --permission ... --output json` is available for local permission inspection.
- Current local development auth defaults are not replaced.
- `docs/enterprise_security.md` exists.
- Focused tests pass: `tests/test_enterprise_security.py`, `tests/test_security.py`, `tests/test_enrollment.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

### Phase 37 - Alerting and SIEM Integrations

- `core_engine.integrations` package exists with common, webhook, Splunk, Elastic, Sentinel, and email helpers.
- Generic webhook, Slack-compatible, Teams-compatible, Splunk HEC, Elastic document/bulk, Sentinel-ready JSON, and email payloads are generated locally.
- Delivery helpers default to dry-run, require explicit `--send`, and return structured failed results on delivery errors.
- `portmap alert --event-json ... --format generic|slack|teams|splunk|elastic|sentinel|email --output json` is available for local formatting.
- Explicit delivery paths support webhook URLs, Splunk HEC tokens, Elastic API keys, and SMTP options without persisting secrets.
- Output stores no raw credentials, performs no automatic changes, and sends no network/email traffic unless `--send` is provided.
- `docs/alerting_siem_integrations.md` exists.
- Focused tests pass: `tests/test_integrations.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

### Phase 38 - Visualization and GUI Platform

- `gui.visualization` exists with reusable risk timeline, topology edge, traffic flow, and dashboard summary helpers.
- The Textual dashboard now includes Risk Timeline, Topology Edges, and Traffic Flows panels.
- Dashboard visualization reads passive flow telemetry from `~/.portmap-ai/logs/flow_events.jsonl` or flow-capable `master_events.log` entries when present.
- Risk timeline output buckets recent scan/remediation scores into low, medium, high, and critical trend rows.
- Topology and flow panels summarize initiator/responder relationships, protocols, packet counts, payload byte counts, and findings without storing raw payload bytes.
- Dashboard metrics include flow count, topology node/edge counts, and latest max score.
- Visualization is read-only and performs no capture, packet transmission, authentication, exploit, network configuration, or remediation behavior.
- `docs/visualization_gui_platform.md` exists.
- Focused tests pass: `tests/test_gui_app.py` and `tests/test_packaging.py`.

### Phase 39 - Distributed Cluster Scanning

- `core_engine.cluster` package exists with worker registry, job queue, and safe scheduler primitives.
- Worker registry normalizes orchestrator worker nodes, health, capabilities, stale status, max concurrency, active jobs, and available capacity.
- Job queue tracks cluster jobs, planned/assigned/running/completed/partial/failed states, task attempts, retry state, task results, errors, and aggregate result output.
- Scheduler reuses the Phase 24 safe scan planner for target, port, concurrency, rate, and aggressive-mode validation.
- Scheduler partitions authorized targets/ports into bounded tasks and assigns them across available worker capacity without executing probes.
- `portmap cluster plan --target ... --ports ... --worker ... --workers-json ... --output json|table` is available for dry-run cluster planning.
- Cluster planning output stores no raw payload bytes, performs no automatic changes, and does not execute packet capture, scanning, packet crafting, authentication, exploit, network configuration, or remediation behavior.
- `docs/distributed_cluster_scanning.md` exists.
- Focused tests pass: `tests/test_cluster_scanning.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

### Phase 40 - Enterprise Cloud Orchestration Platform

- `saas.tenancy` exists for tenant records, workspace configuration validation, tenant isolation helpers, and local workspace config persistence.
- `saas.orgs` exists for organization metadata, team associations, user grouping, and RBAC role inheritance.
- `saas.licensing` exists for license metadata, subscription tier labels, usage counters, quota tracking, feature gating, and local usage summaries.
- `saas.cloud_sync` exists for optional encrypted sync manifests with nonce-based payload protection, SHA-256 digest checks, HMAC integrity validation, offline-compatible export/import, and conflict handling.
- `core_engine.advisory.workflow` exists for administrator-facing recommendation objects, review states, approval transitions, and enterprise audit event generation.
- `portmap workspace`, `portmap license`, `portmap cloud-sync`, and `portmap advisory` are available for local Phase 40 workflows.
- Cloud sync is optional and performs no network requests.
- Advisory workflows require administrator-defined RBAC permissions for approval transitions and do not execute remediation.
- `docs/enterprise_cloud_orchestration.md` exists.
- Focused tests pass: `tests/test_enterprise_cloud_orchestration.py`, `tests/test_cli_main.py`, and `tests/test_packaging.py`.

## Key Files

- `PORTMAP_AI_HANDOFF.md` - full current handoff.
- `PORTMAP_AI_NEXT_SESSION.md` - compact handoff for low-context continuation.
- `CHANGELOG.md` - 0.1.0 release-candidate changelog.
- `SECURITY.md` - GitHub security policy and deployment hardening notes.
- `core_engine/vuln/cve_client.py` - Phase 34 NVD normalization, fetch helper, and service/CVE matching.
- `core_engine/vuln/cve_store.py` - Phase 34 local CVE cache persistence.
- `core_engine/vuln/cvss.py` - Phase 34 CVSS/severity/risk helpers.
- `core_engine/vuln/vuln_correlator.py` - Phase 35 vulnerability prioritization and exposure correlation.
- `core_engine/enterprise_auth.py` - Phase 36 local token and password helpers.
- `core_engine/rbac.py` - Phase 36 local roles and permission checks.
- `core_engine/enterprise_audit.py` - Phase 36 enterprise audit event helper.
- `core_engine/agent_identity.py` - Phase 36 secure agent identity and signature helpers.
- `core_engine/cluster/worker_registry.py` - Phase 39 worker health/capacity registry.
- `core_engine/cluster/job_queue.py` - Phase 39 distributed job/task queue.
- `core_engine/cluster/scheduler.py` - Phase 39 safe distributed scan planner.
- `core_engine/advisory/workflow.py` - Phase 40 administrator advisory review workflows.
- `saas/tenancy.py` - Phase 40 tenant and workspace management.
- `saas/orgs.py` - Phase 40 organization/team/user grouping helpers.
- `saas/licensing.py` - Phase 40 license and usage accounting helpers.
- `saas/cloud_sync.py` - Phase 40 optional encrypted sync manifest helpers.
- `gui/visualization.py` - Phase 38 dashboard visualization normalization helpers.
- `gui/app.py` - Textual dashboard with scan, remediation, topology, flow, and timeline panels.
- `docs/cve_intelligence.md` - Phase 34 CVE intelligence documentation.
- `docs/alerting_siem_integrations.md` - Phase 37 alert/SIEM integration documentation.
- `docs/enterprise_security.md` - Phase 36 enterprise security documentation.
- `docs/distributed_cluster_scanning.md` - Phase 39 cluster scan planning documentation.
- `docs/enterprise_cloud_orchestration.md` - Phase 40 organization/workspace, licensing, sync, and advisory workflow documentation.
- `docs/visualization_gui_platform.md` - Phase 38 visualization and GUI platform documentation.
- `docs/vulnerability_correlation.md` - Phase 35 vulnerability correlation documentation.
- `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md` - Phase 19-40 enterprise roadmap.
- `docs/udp_scanning.md` - Phase 19 UDP scanner behavior and usage.
- `docs/ipv6_dual_stack.md` - Phase 20 IPv4/IPv6 target parsing and active dual-stack scan usage.
- `docs/network_asset_inventory.md` - Phase 21 authorized asset inventory and topology context.
- `docs/service_enumeration.md` - Phase 22 service and version detection.
- `docs/os_fingerprinting.md` - Phase 23 probabilistic OS-family inference.
- `docs/high_speed_scan_engine.md` - Phase 24 async TCP scan scheduler and safe limits.
- `docs/packet_capture.md` - Phase 25 packet metadata capture and PCAP output.
- `docs/protocol_dissectors.md` - Phase 26 passive protocol parsing framework.
- `docs/deep_packet_inspection.md` - Phase 27 DPI metadata, indicators, redaction, and session grouping.
- `docs/ai_behavioral_learning.md` - Phase 30 local behavior baselines and advisory anomaly scoring.
- `docs/ai_payload_classification.md` - Phase 31 payload labels, suspicious markers, beaconing, and exfiltration indicators.
- `docs/ai_recommendation_engine.md` - Phase 33 advisory recommendations and dry-run remediation drafts.
- `docs/threat_correlation.md` - Phase 32 event correlation, incident scoring, and supporting evidence.
- `docs/tls_intelligence.md` - Phase 28 TLS protocol, cipher, certificate, and hostname posture checks.
- `docs/traffic_flow_reconstruction.md` - Phase 29 passive flow grouping, directional counters, and topology summaries.
- `docs/release_candidate.md` - final release checklist.
- `docs/architecture.md` - current architecture guide.
- `docs/saas_architecture.md` - future SaaS/control-plane guide.
- `docs/master_roadmap.md` - roadmap.
- `test_instructions.md` - verification checklist.
- `pyproject.toml` - package metadata/version/package data.
- `cli/main.py` - unified CLI.
- `core_engine/orchestrator.py` - HTTP API.
- `core_engine/orchestrator_service.py` - persisted orchestrator state.
- `core_engine/worker_node.py` - worker scan/heartbeat loop.
- `core_engine/master_node.py` - master socket server and remediation command dispatch.
- `core_engine/enrollment.py` - SaaS-prep schema helpers.
- `core_engine/security.py` - auth helpers.
- `core_engine/network_control.py` - posture assessment.
- `core_engine/runtime_setup.py` - setup/doctor helpers.

## Verification Commands

Use the repo-local environment:

```bash
cd <repo-root>
source portmap-ai-env/bin/activate
python -m pytest
python -m pytest tests/test_udp_scanner.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_ip_utils.py tests/test_ipv6_scanner.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_discovery.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_service_detection.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_os_fingerprint.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_scan_scheduler.py tests/test_async_scanner.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_protocols.py tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_dpi.py tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_tls_inspector.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_flow_tracker.py tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_behavior_model.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_payload_classifier.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_threat_correlation.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_recommendation_engine.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_cve_client.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_vuln_correlator.py tests/test_cve_client.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_enterprise_security.py tests/test_security.py tests/test_enrollment.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_integrations.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_gui_app.py tests/test_packaging.py
python -m pytest tests/test_cluster_scanning.py tests/test_cli_main.py tests/test_packaging.py
python -m pytest tests/test_enterprise_cloud_orchestration.py tests/test_cli_main.py tests/test_packaging.py
python -m pip wheel --no-deps -w /tmp/portmap-ai-wheel .
portmap --help
portmap doctor --output json
portmap tls --observation-json '{"target":"legacy.example.com","server_name":"legacy.example.com","tls_version":"TLSv1.0","cipher":{"name":"RC4-MD5","bits":64},"certificate":{"subject":{"commonName":"legacy.example.com"},"issuer":{"commonName":"Legacy CA"},"san_dns":["legacy.example.com"],"not_after":"<CERT_NOT_AFTER>"}}' --output json
portmap flows --events-json '[{"timestamp":1,"protocol":"TCP","src_ip":"<LAN_IP>","src_port":51515,"dst_ip":"<LAN_IP>","dst_port":443,"payload_bytes":128}]' --output json
portmap behavior --events-json '[{"device_id":"worker-1","metadata":{"protocol":"TCP","dst_ip":"<LAN_IP>","dst_port":443},"application_protocol":"TLS"}]' --output json
portmap payload --events-json '{"protocol":"HTTP","payload_text":"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret"}' --output json
portmap correlate --events-json '[{"timestamp":1,"device_id":"worker-1","score":0.6,"findings":[{"type":"new_peer"}]},{"timestamp":2,"device_id":"worker-1","score":0.6,"findings":[{"type":"new_destination_port"}]},{"timestamp":3,"device_id":"worker-1","score":0.6,"findings":[{"type":"unusual_hour"}]}]' --output json
portmap recommend --incidents-json '{"incidents":[{"incident_id":"inc-1","type":"chained_behavior_payload_risk","severity":"high","score":0.9,"entity":"worker-1","peers":["<LAN_IP>"],"findings":["new_peer","credential_marker"],"event_count":2}]}' --output json
portmap cve --service-json '[{"target":"127.0.0.1","port":80,"state":"open","service":"HTTP","version":"Apache/2.4.49"}]' --cve-json '[{"id":"CVE-2021-41773","summary":"Apache HTTP Server 2.4.49 path traversal vulnerability.","severity":"high","cvss_score":7.5,"cpes":["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]}]' --output json
portmap vuln --service-json '[{"target":"203.0.113.10","port":80,"state":"open","service":"HTTP","version":"Apache/2.4.49","classification":"public_interface"}]' --cve-matches-json '{"matches":[{"target":"203.0.113.10","port":80,"service":"HTTP","version":"Apache/2.4.49","cve_id":"CVE-2021-41773","severity":"high","cvss_score":7.5,"risk_score":0.88,"confidence":0.95,"known_exploited":true,"summary":"Apache HTTP Server 2.4.49 remote code execution vulnerability."}]}' --output json
portmap rbac --roles analyst --permission generate:recommendations --output json
portmap alert --event-json '{"severity":"critical","title":"Critical Apache vulnerability","summary":"Apache HTTP Server requires review.","target":"203.0.113.10"}' --format slack --output json
python -c "from gui.app import PortMapDashboard; from gui.visualization import render_risk_timeline; print(type(PortMapDashboard()).__name__); print(render_risk_timeline([]))"
portmap cluster plan --target 127.0.0.1 --ports 80,443 --worker worker-a --worker worker-b --output json
portmap workspace --tenant-json '{"tenant_id":"tenant.local","name":"Local Tenant"}' --org-json '{"organizations":[{"org_id":"org.ops","tenant_id":"tenant.local","name":"Ops"}]}' --team-json '{"teams":[{"team_id":"team.netops","tenant_id":"tenant.local","org_id":"org.ops","name":"NetOps","roles":["analyst"],"members":["alice"]}]}' --user alice
portmap license --license-json '{"license_id":"lic-1","tenant_id":"tenant.local","tier":"team","features":["cloud_sync"],"quotas":{"workspaces":2}}' --usage-json '{"tenant_id":"tenant.local","counters":{"workspaces":1}}' --feature cloud_sync --quota workspaces
portmap cloud-sync --tenant-id tenant.local --workspace-id workspace.local --key local-sync-key --payload-json '{"setting":"value"}'
portmap advisory --recommendation-json '{"recommendations":[{"recommendation_id":"rec-1","title":"Review workspace","summary":"Review workspace settings.","category":"configuration_review","target":"workspace.local","actions":["review settings"]}]}'
```

Optional real-runtime checks before tagging:

```bash
portmap stack --no-dashboard --verbose
portmap tui
portmap network --output json
docker compose config
```

`docker compose` requires Docker Engine with the Compose plugin. Docker is not required for the default product path.

## Next Step

Phase 40 enterprise cloud orchestration is complete. Do not commit until the user asks.
