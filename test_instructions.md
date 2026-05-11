# PortMap-AI Test Instructions

## 1. Environment Setup
```bash
cd <repo-root>
scripts/setup_environment.sh
source portmap-ai-env/bin/activate
pip install -e .
```

Use the repo-local `portmap-ai-env`. Older sibling environments from previous experiments should not be treated as the reproducible baseline.

Core documentation references:
- `docs/README.txt`
- `docs/architecture.md`
- `docs/ROADMAP.md`
- `docs/PHASE_HISTORY.md`
- `docs/DEPLOYMENT.md`
- `docs/SECURITY_MODEL.md`
- `docs/CLI_REFERENCE.md`
- `docs/real_device_validation.md`

## 2. Launch Full Stack (orchestrator, master, worker, dashboard)
```bash
scripts/run_stack.py --verbose
```
Observe orchestrator/master/worker logs for successful connections; the dashboard should open automatically.

Docker is not required for the normal local stack. The default user path is local install plus `portmap stack`; Docker Compose is an optional advanced deployment path.

## 3. Dashboard Functional Checks
- Click **Scan Now** and **Toggle Autolearn** buttons; confirm log lines appear in worker/master consoles.
- Use **Detect Orchestrator**; verify dashboard logs detection line.
- Press **Export Logs**; confirm archive path printed.
- Hit `?` to view help overlay; `Esc` to close.

## 4. CLI Tests (new terminal, same venv)
```bash
python -m pytest
```

## 4a. Unified CLI Checks
```bash
python -m cli.main --help
portmap --help
python -m cli.main scan --output json
portmap scan --output json
python -m cli.main stack --no-dashboard --verbose
```

With the stack running in another terminal:
```bash
python -m cli.main health
python -m cli.main nodes
python -m cli.main metrics
portmap health
portmap nodes
portmap metrics
```

## 4b. Config Validation Checks
```bash
portmap config validate core_engine/default_configs/orchestrator.json
portmap config validate core_engine/default_configs/master1.json core_engine/default_configs/worker_orchestrated.json
portmap config validate core_engine/default_configs/worker_orchestrated.json --role worker
```

Invalid configs should return exit code `1` with readable errors:

```bash
portmap config validate tests/node_configs/master_config_multi_nodes.json
```

## 4c. Audit Log Checks
```bash
portmap logs --filter-event-type command_event --tail 10
portmap logs --filter-event-type remediation_decision --tail 10
portmap logs --output-dir ./artifacts
```

## 4d. Remediation Safety Checks
```bash
python -m pytest tests/test_remediation_safety.py tests/test_master_remediation.py tests/test_agent_service.py
```

## 4e. Scanner and Risk Engine Checks
```bash
python -m pytest tests/test_scanner.py tests/test_scoring.py
portmap scan --output json
```

## 4f. AI Layer Checks
```bash
python -m pytest tests/test_ai_interface.py tests/test_scoring.py
```

## 4g. TUI Dashboard Checks
```bash
python -m pytest tests/test_gui_app.py
portmap tui
```

## 4h. Docker Deployment Checks
```bash
python -m pytest tests/test_docker_deployment.py tests/test_packaging.py
docker compose config
docker compose up --build
```
Requires Docker Engine with the Compose plugin available as `docker compose`.
Skip the compose commands on machines without Docker Compose; the Python tests still validate the repository-side Docker contract.

## 4i. Deployment Option Documentation Checks
```bash
python -m pytest tests/test_packaging.py
```
Read `docs/deployment_options.md` and confirm it presents:
- Local Install as the recommended default.
- Raspberry Pi / always-on service as the continuous monitoring path.
- Docker Compose as optional advanced mode.

## 4j. Raspberry Pi / Linux Service Checks
```bash
python -m pytest tests/test_raspberry_pi_deployment.py tests/test_packaging.py
portmap config validate core_engine/default_configs/worker_orchestrated.json --profile raspberry_pi --role worker
```
Read `docs/raspberry_pi_deployment.md` and confirm the guidance remains Linux/ARM compatible without making Raspberry Pi the only supported platform.

## 4k. Network Control Layer Checks
```bash
python -m pytest tests/test_network_control.py tests/test_cli_main.py
portmap network
portmap network --output json
```
Confirm output is advisory-only and does not claim to modify router, firewall, NAT, or port-forward settings.

## 4l. Security and Authentication Checks
```bash
python -m pytest tests/test_security.py tests/test_config_loader.py tests/test_config_validation.py tests/test_orchestrator_state.py
PORTMAP_ORCHESTRATOR_TOKEN=secret-from-env portmap config validate core_engine/default_configs/orchestrator.json
```
Read `docs/security_authentication.md` and confirm shared/remote deployments are directed to use non-default bearer tokens via environment-backed secrets.

## 4m. SaaS Preparation and Release Candidate Checks
```bash
python -m pytest tests/test_enrollment.py tests/test_release_candidate.py tests/test_packaging.py
```
Read `docs/architecture.md`, `docs/saas_architecture.md`, `docs/release_candidate.md`, and `CHANGELOG.md`.
Confirm 0.1.0 remains local-first, SaaS is documented but not required, Docker is optional, and release checks include tests, wheel build, setup, and doctor.

## 4n. UDP Scanner Checks
```bash
python -m pytest tests/test_udp_scanner.py tests/test_cli_main.py tests/test_packaging.py
portmap scan --udp-target 127.0.0.1 --udp-ports 53,123,161 --output json
```
Read `docs/udp_scanning.md` and confirm UDP scanning remains scoped, rate-limited, JSON-serializable, and free of remediation side effects.

## 4o. IPv6 / Dual-Stack Scanner Checks
```bash
python -m pytest tests/test_ip_utils.py tests/test_ipv6_scanner.py tests/test_cli_main.py tests/test_packaging.py
portmap scan --target ::1 --ports 80,443 --ip-version 6 --output json
```
Read `docs/ipv6_dual_stack.md` and confirm active TCP target scans require explicit targets, validate malformed inputs, support IPv4/IPv6, and keep safe limits by default.

## 4p. Network Asset Inventory Checks
```bash
python -m pytest tests/test_discovery.py tests/test_cli_main.py tests/test_packaging.py
portmap discover --range 127.0.0.1 --method tcp --tcp-ports 80,443 --output json
```
Read `docs/network_asset_inventory.md` and confirm inventory is scoped to authorized ranges or detected local networks, uses ARP/reachability/transport evidence, emits telemetry-ready records, and makes no network configuration or remediation changes.

## 4q. Service Enumeration Checks
```bash
python -m pytest tests/test_service_detection.py tests/test_cli_main.py tests/test_packaging.py
portmap services --target 127.0.0.1 --ports 22,80,443 --output json
```
Read `docs/service_enumeration.md` and confirm service detection uses safe banner/protocol probes, fingerprint matching, confidence scores, unknown-service handling, and no credential, exploit, or remediation behavior.

## 4r. OS Fingerprinting Checks
```bash
python -m pytest tests/test_os_fingerprint.py tests/test_cli_main.py tests/test_packaging.py
portmap os --target 127.0.0.1 --ports 22,80,443 --output json
portmap os --observation-json '{"target":"host1","ttl":64,"tcp_window":29200,"services":["SSH"],"banners":["OpenSSH Ubuntu"]}' --output json
```
Read `docs/os_fingerprinting.md` and confirm OS inference is probabilistic, reports low-confidence results as unknown, accepts passive evidence, reuses safe service enumeration for active context, and performs no exploit or credential behavior.

## 4s. High-Speed Scan Engine Checks
```bash
python -m pytest tests/test_scan_scheduler.py tests/test_async_scanner.py tests/test_cli_main.py tests/test_packaging.py
portmap fast-scan --target 127.0.0.1 --ports 80,443 --timeout 0.05 --output json
```
Read `docs/high_speed_scan_engine.md` and confirm async scanning uses safe TCP connect probes, concurrency/rate limits, adaptive delays, aggressive-mode warnings, and no raw packet, spoofing, exploit, or remediation behavior.

## 4t. Packet Capture Core Checks
```bash
python -m pytest tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
portmap capture --duration 0.1 --max-packets 1 --filter tcp --output json
```
Read `docs/packet_capture.md` and confirm packet capture handles unsupported platforms or missing permissions gracefully, extracts metadata without storing payloads in JSON rows, supports simple filters, writes PCAP only when requested, and performs no packet crafting, exploit, credential, or remediation behavior.

## 4u. Protocol Dissector Framework Checks
```bash
python -m pytest tests/test_protocols.py tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
portmap capture --duration 0.1 --max-packets 1 --filter tcp --dissect --output json
```
Read `docs/protocol_dissectors.md` and confirm protocol parsing is passive, labels unknown or failed dissections safely, redacts sensitive command arguments, and performs no packet crafting, authentication, exploit, network configuration, or remediation behavior.

## 4v. Deep Packet Inspection Checks
```bash
python -m pytest tests/test_dpi.py tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
portmap dpi --observation-json '{"protocol":"HTTP","payload_text":"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret"}' --include-payload-preview --output json
portmap capture --duration 0.1 --max-packets 1 --filter tcp --dpi --output json
```
Read `docs/deep_packet_inspection.md` and confirm DPI stores metadata instead of raw payloads by default, redacts optional previews, labels suspicious or malformed indicators as operator-review evidence, groups sessions passively, and performs no packet crafting, authentication, exploit, network configuration, or remediation behavior.

## 4w. TLS Intelligence Checks
```bash
python -m pytest tests/test_tls_inspector.py tests/test_cli_main.py tests/test_packaging.py
portmap tls --observation-json '{"target":"legacy.example.com","server_name":"legacy.example.com","tls_version":"TLSv1.0","cipher":{"name":"RC4-MD5","bits":64},"certificate":{"subject":{"commonName":"legacy.example.com"},"issuer":{"commonName":"Legacy CA"},"san_dns":["legacy.example.com"],"not_after":"<CERT_NOT_AFTER>"}}' --output json
```
Read `docs/tls_intelligence.md` and confirm TLS inspection is read-only, reports protocol/cipher/certificate/hostname posture, supports offline observations for deterministic tests, and performs no authentication, exploit, network configuration, or remediation behavior.

## 4x. Traffic Flow Reconstruction Checks
```bash
python -m pytest tests/test_flow_tracker.py tests/test_packet_capture.py tests/test_cli_main.py tests/test_packaging.py
portmap flows --events-json '[{"timestamp":1,"protocol":"TCP","src_ip":"<LAN_IP>","src_port":51515,"dst_ip":"<LAN_IP>","dst_port":443,"payload_bytes":128}]' --output json
portmap capture --duration 0.1 --max-packets 1 --filter tcp --flows --output json
```
Read `docs/traffic_flow_reconstruction.md` and confirm flow reconstruction groups passive metadata into bidirectional flows, tracks directional counters and topology summaries, stores no raw payloads, and performs no packet crafting, authentication, exploit, network configuration, or remediation behavior.

## 4y. AI Behavioral Learning Checks
```bash
python -m pytest tests/test_behavior_model.py tests/test_cli_main.py tests/test_packaging.py
portmap behavior --events-json '[{"device_id":"worker-1","metadata":{"protocol":"TCP","dst_ip":"<LAN_IP>","dst_port":443},"application_protocol":"TLS"}]' --output json
```
Read `docs/ai_behavioral_learning.md` and confirm behavior learning is local, advisory, opt-in for baseline updates via `--learn`, stores no raw payloads, and performs no authentication, exploit, network configuration, or remediation behavior.

## 4z. AI Payload Classification Checks
```bash
python -m pytest tests/test_payload_classifier.py tests/test_cli_main.py tests/test_packaging.py
portmap payload --events-json '{"protocol":"HTTP","payload_text":"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret"}' --output json
```
Read `docs/ai_payload_classification.md` and confirm payload classification is local and advisory, redacts optional previews, stores no raw payloads by default, reports suspicious/beaconing/exfiltration indicators, and performs no authentication, exploit, network configuration, or remediation behavior.

## 4aa. Threat Correlation Checks
```bash
python -m pytest tests/test_threat_correlation.py tests/test_cli_main.py tests/test_packaging.py
portmap correlate --events-json '[{"timestamp":1,"device_id":"worker-1","score":0.6,"findings":[{"type":"new_peer"}]},{"timestamp":2,"device_id":"worker-1","score":0.6,"findings":[{"type":"new_destination_port"}]},{"timestamp":3,"device_id":"worker-1","score":0.6,"findings":[{"type":"unusual_hour"}]}]' --output json
```
Read `docs/threat_correlation.md` and confirm correlation is local and advisory, links repeated anomalies/scanning/lateral movement/chained evidence, stores no raw payloads, and performs no authentication, exploit, network configuration, or remediation behavior.

## 4ab. AI Recommendation Engine Checks
```bash
python -m pytest tests/test_recommendation_engine.py tests/test_cli_main.py tests/test_packaging.py
portmap recommend --incidents-json '{"incidents":[{"incident_id":"inc-1","type":"chained_behavior_payload_risk","severity":"high","score":0.9,"entity":"worker-1","peers":["<LAN_IP>"],"findings":["new_peer","credential_marker"],"event_count":2}]}' --output json
```
Read `docs/ai_recommendation_engine.md` and confirm recommendations are advisory, destructive drafts are approval-required and dry-run, no remediation is executed, no raw payloads are stored, and existing safety gates remain the enforcement boundary.

## 4ac. CVE Intelligence Checks
```bash
python -m pytest tests/test_cve_client.py tests/test_cli_main.py tests/test_packaging.py
portmap cve --service-json '[{"target":"127.0.0.1","port":80,"state":"open","service":"HTTP","version":"Apache/2.4.49"}]' --cve-json '[{"id":"CVE-2021-41773","summary":"Apache HTTP Server 2.4.49 path traversal vulnerability.","severity":"high","cvss_score":7.5,"cpes":["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]}]' --output json
```
Read `docs/cve_intelligence.md` and confirm CVE matching is advisory, offline by default, only uses network access with explicit `--update`, stores a local cache only when requested, and performs no scanning, authentication, exploit, network configuration, or remediation behavior.

## 4ad. Vulnerability Correlation Checks
```bash
python -m pytest tests/test_vuln_correlator.py tests/test_cve_client.py tests/test_cli_main.py tests/test_packaging.py
portmap vuln --service-json '[{"target":"203.0.113.10","port":80,"state":"open","service":"HTTP","version":"Apache/2.4.49","classification":"public_interface"}]' --cve-matches-json '{"matches":[{"target":"203.0.113.10","port":80,"service":"HTTP","version":"Apache/2.4.49","cve_id":"CVE-2021-41773","severity":"high","cvss_score":7.5,"risk_score":0.88,"confidence":0.95,"known_exploited":true,"summary":"Apache HTTP Server 2.4.49 remote code execution vulnerability."}]}' --output json
```
Read `docs/vulnerability_correlation.md` and confirm vulnerability correlation is advisory, prioritizes service/CVE exposure evidence, reports known-exploited and ransomware association fields when present, explains prioritization, and performs no scanning, authentication, exploit, network configuration, or remediation behavior.

## 4ae. Enterprise Security Checks
```bash
python -m pytest tests/test_enterprise_security.py tests/test_security.py tests/test_enrollment.py tests/test_cli_main.py tests/test_packaging.py
portmap rbac --roles analyst --permission generate:recommendations --output json
```
Read `docs/enterprise_security.md` and confirm enterprise security helpers are local primitives, tokens are signed and bounded by expiry/audience/roles, password hashes and generated agent secrets are not exposed in public records, RBAC permissions are explicit, audit metadata is scrubbed, and current local development auth defaults are not replaced.

## 4af. Alerting and SIEM Integration Checks
```bash
python -m pytest tests/test_integrations.py tests/test_cli_main.py tests/test_packaging.py
portmap alert --event-json '{"severity":"critical","title":"Critical Apache vulnerability","summary":"Apache HTTP Server requires review.","target":"203.0.113.10"}' --format slack --output json
```
Read `docs/alerting_siem_integrations.md` and confirm alert formatting is local and dry-run by default, network/email delivery only happens with explicit `--send`, delivery failures return structured failed results instead of interrupting callers, secrets are not persisted, and integrations perform no scanning, authentication to monitored services, exploit, network configuration, or remediation behavior.

## 4ag. Visualization and GUI Platform Checks
```bash
python -m pytest tests/test_gui_app.py tests/test_packaging.py
portmap tui
```
Read `docs/visualization_gui_platform.md` and confirm visualization is terminal-first, read-only, summarizes risk timeline/topology/flow data, stores no raw payload bytes, and performs no capture, packet transmission, exploit, network configuration, or remediation behavior.

## 4ah. Distributed Cluster Scanning Checks
```bash
python -m pytest tests/test_cluster_scanning.py tests/test_cli_main.py tests/test_packaging.py
portmap cluster plan --target 127.0.0.1 --ports 80,443 --worker worker-a --worker worker-b --output json
```
Read `docs/distributed_cluster_scanning.md` and confirm cluster planning is dry-run by default, validates safe target/port limits, assigns bounded tasks to available workers, stores no raw payload bytes, and performs no packet capture, scanning execution, authentication, exploit, network configuration, or remediation behavior.

## 4ai. Enterprise Cloud Orchestration Checks
```bash
python -m pytest tests/test_enterprise_cloud_orchestration.py tests/test_cli_main.py tests/test_packaging.py
portmap workspace --tenant-json '{"tenant_id":"tenant.local","name":"Local Tenant"}' --org-json '{"organizations":[{"org_id":"org.ops","tenant_id":"tenant.local","name":"Ops"}]}' --team-json '{"teams":[{"team_id":"team.netops","tenant_id":"tenant.local","org_id":"org.ops","name":"NetOps","roles":["analyst"],"members":["alice"]}]}' --user alice
portmap license --license-json '{"license_id":"lic-1","tenant_id":"tenant.local","tier":"team","features":["cloud_sync"],"quotas":{"workspaces":2}}' --usage-json '{"tenant_id":"tenant.local","counters":{"workspaces":1}}' --feature cloud_sync --quota workspaces
portmap cloud-sync --tenant-id tenant.local --workspace-id workspace.local --key local-sync-key --payload-json '{"setting":"value"}'
portmap advisory --recommendation-json '{"recommendations":[{"recommendation_id":"rec-1","title":"Review workspace","summary":"Review workspace settings.","category":"configuration_review","target":"workspace.local","actions":["review settings"]}]}'
```
Read `docs/enterprise_cloud_orchestration.md` and confirm the phase is limited to organization/workspace management, licensing and usage metrics, optional encrypted sync manifests, and administrator review workflows. Confirm cloud sync is optional/offline-first and advisory workflows do not execute remediation.

## 5. Integration Test
```bash
scripts/run_integration_tests.sh
```
(Skips automatically if ports unavailable.)

## 6. Packaging Smoke Test
```bash
scripts/package_local.sh
ls dist/
python -m pip wheel --no-deps -w /tmp/portmap-ai-wheel .
python -m pip install --force-reinstall --no-deps /tmp/portmap-ai-wheel/portmap_ai-0.1.0-py3-none-any.whl
cd /tmp
portmap --help
portmap setup --output json
portmap doctor --output json
portmap stack --no-dashboard --verbose
```

## 7. Optional: Docker Build
```bash
docker build -f docker/orchestrator.Dockerfile -t portmap-orch:dev .
docker build -f docker/worker.Dockerfile -t portmap-worker:dev .
```

## 8. Shutdown
- For `run_stack.py`, press `Ctrl+C` once to stop all services.
- Deactivate environment: `deactivate`
