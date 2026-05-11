# 🧠 PortMap-AI — Project Handoff Summary
### AI-Driven Network Observability & Port Mapping Platform

---

## 🔍 Overview
**PortMap-AI** is an intelligent, modular **network observability and visualization platform** that performs **AI-enhanced port visibility, telemetry analysis, exposure scoring, and administrator-controlled remediation orchestration** across multi-node environments.
It supports **master/worker topology**, distributed scanning, and eventually cloud-based AI decision layers.

**Core Goals:**
- Map network ports and detect anomalies in real time.
- Apply adaptive AI logic to classify telemetry and support administrator-reviewed response workflows.
- Support local, multi-node, and SaaS-tier deployments.
- Provide CLI and operator UI modes. The current UI is a Textual terminal dashboard, not a browser UI.

---

## 🌐 Long-Term Vision
PortMap-AI aims to become an AI-native network observability, exposure management, telemetry intelligence, and remediation orchestration platform supporting local, distributed, and enterprise-scale deployments.

---

## ✅ Complete Baseline Definition
“Complete Baseline” indicates the foundational implementation of a phase is operational and tested, while future enhancements may still expand functionality.

---

## 🛡️ Global Safety Guarantees
- PortMap-AI supports authorized observability, telemetry analysis, packet inspection, protocol-aware diagnostics, service discovery, topology mapping, TLS analysis, flow reconstruction, and administrator-controlled remediation workflows.
- Some platform capabilities may generate standards-compliant diagnostic network traffic for observability and validation purposes.
- PortMap-AI is not designed for unauthorized access, credential theft, brute forcing, malware deployment, persistence, destructive exploitation, denial-of-service activity, or autonomous offensive operations.

---

## ✅ Current Verified State (Phase 0 Baseline)

PortMap-AI is now a functional local distributed system, not just a prototype.

Implemented and verified:
- Orchestrator HTTP API in `core_engine/orchestrator.py`.
- Master node socket listener and remediation-aware ACK flow.
- Worker node scanner loop, orchestrator registration, heartbeat, and command processing.
- Textual terminal dashboard in `gui/app.py`.
- Unified CLI entry point in `cli/main.py` (`python -m cli.main ...`).
- One-command local stack launcher in `scripts/run_stack.py`.
- TLS utilities, firewall plugin scaffolding, command audit logging, structured logging, log export, CI, Dockerfiles, packaging scripts, and expanded docs.

Validation performed:
- Full test suite passes in the repo-local environment: `154 passed, 1 skipped`.
- Local stack smoke test succeeds on default development ports:
  - Orchestrator: `127.0.0.1:9100`
  - Master: `127.0.0.1:9000` by default for local release safety
  - Worker: registers as `worker-001`, sends heartbeats/scans, and receives remediation ACKs.
  - API endpoints `/healthz`, `/nodes`, and `/metrics` respond correctly.

Phase 0 dependency work:
- `requirements.txt` now declares runtime dependencies.
- `requirements-dev.txt` now layers test/development dependencies on top of runtime requirements.
- `scikit-learn` is pinned to `1.7.1` to match the existing serialized IsolationForest model artifact.
- The standard development environment is repo-local: `./portmap-ai-env`.
- Older sibling environments from previous experiments should not be treated as the reproducible baseline.

Deployment posture:
- Docker is optional, not a PortMap-AI requirement.
- The recommended user path is local install plus `portmap stack` / `portmap tui`.
- The always-on monitoring path should be native service management (`systemd` on Linux/Raspberry Pi, `launchd` on macOS, Windows Service later).
- Docker Compose is an advanced containerized deployment mode for operators who already want Docker.
- Docker Compose requires an explicit `PORTMAP_ORCHESTRATOR_TOKEN`; it intentionally does not fall back to the local development token because it publishes host ports.
- Phase 13 packaging should make the local install path feel like a product without requiring users to understand Docker, repo paths, or Python internals.
- Raspberry Pi is a supported Linux/ARM deployment target, not a product boundary. Bundling must remain multi-platform and avoid Pi-only assumptions.
- Runtime logs, local state, build outputs, virtual environments, and generated archives are ignored and removed from the Git index before GitHub publication.

---

## 🧩 Architecture Summary

```
portmap-ai/
│
├── ai_agent/                   # AI logic and decision layer
│   ├── interface.py            # AI provider contract and result validation
│   ├── scoring.py              # get_score(): computes AI threat scores
│   ├── remediation.py          # Decides remediation actions (prompt/silent)
│   ├── ml_model/               # (Planned) ML training and model weights
│   └── __init__.py
│
├── core_engine/                # Network operations and multi-node control
│   ├── master_node.py          # Coordinates worker nodes and aggregates results
│   ├── worker_node.py          # Performs local scans, sends to master
│   ├── orchestrator.py         # Cloud orchestration HTTP service entrypoint
│   ├── orchestrator_service.py # Shared orchestrator state & persistence helpers
│   ├── config_loader.py        # Shared loader for node & ~/.portmap-ai settings
│   ├── platform_utils.py       # Cross-platform host/process/network helpers
│   ├── logging_utils.py        # Central logging helpers w/ rotation + console
│   ├── agent_service.py        # Background agent for continuous worker mode + orchestrator heartbeat/remediation
│   ├── modules/
│   │   ├── scanner.py          # basic_scan(): performs network scans
│   │   ├── dispatcher.py       # Handles node communication, message routing
│   │   ├── risk_assessor.py    # Calculates composite risk scores (AI+rules)
│   │   ├── protocol_labeler.py # Identifies protocol type by port/traffic
│   │   └── __init__.py
│   └── __init__.py
│
├── cli/                        # Command-line interface layer
│   ├── main.py                 # Unified CLI entry point
│   ├── logs.py                 # Log export CLI
│   └── dashboard.py            # Dashboard launcher
│
├── data/                       # Stores persistent runtime data
│   ├── nodes_status.json       # Example: stores last-known worker node state
│   └── samples/                # Example captured traffic / ports
│
├── docs/                       # Technical documentation, specs, and readmes
│   ├── architecture.md
│   ├── mvp_plan.md
│   ├── api_reference.md
│   ├── quick_start.md          # Fast-path setup for orchestrator/master/worker/dashboard
│   └── roadmap.md
│
├── scripts/                    # Cross-platform launch helpers & env setup
│   ├── run_orchestrator.sh
│   ├── run_master.sh
│   ├── run_worker.sh
│   ├── run_dashboard.sh
│   └── ...                     # Windows .bat equivalents + setup scripts
│
├── logs/                       # Runtime logs (scan results, remediation actions)
│   ├── master.log
│   ├── worker.log
│   └── events/
│
├── portmap_agent.py            # CLI wrapper around background agent service
├── settings.json               # Central configuration (IP, ports, modes, etc.)
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Developer/testing dependencies (pytest, textual, …)
└── pyproject.toml              # Installable package metadata and console scripts
```

---

## ⚙️ System Flow Summary

### Master/Worker Communication
- **Master Node (`core_engine/master_node.py`)**
  - Listens for incoming worker payloads (`socket`-based JSON packets).
  - Validates node ID, aggregates scan + anomaly reports.
  - Updates logs and forwards data to AI layer for scoring.

- **Worker Node (`core_engine/worker_node.py`)**
  - Executes periodic scans (`modules/scanner.basic_scan()`).
  - Calls `ai_agent.scoring.get_score()` on findings.
  - Sends JSON payload to master containing:
    ```json
    {
      "node_id": "worker_01",
      "timestamp": 1724700000,
      "ports": [22, 443, 8080],
      "anomalies": [],
      "score": 0.92
    }
    ```

### AI Scoring Pipeline
1. Raw connection data → `ai_agent/scoring.get_score()`
2. The active AI provider analyzes the connection through `ai_agent.interface.AIProvider`.
3. The default `LocalAIProvider` uses the local ML scorer only when enabled and loaded; otherwise it uses deterministic heuristic scoring.
4. Provider outputs are validated before being written to the payload.
5. Provider failures fall back to heuristic scoring and record fallback metadata.
6. Returns a float score in `[0, 1]` plus score factors, explanation, and provider name.

- ✅ Structured log handlers for master & worker nodes (`logging_utils.py`).
- ✅ Remediation toggle pipeline wired via `ai_agent/remediation.py`.
- ✅ Background agent service (`core_engine/agent_service.py` + `portmap_agent.py`).
- ✅ Master now returns remediation-aware ACKs; worker logs decisions for operator review.
- ✅ Cloud orchestrator HTTP layer introduced (`core_engine/orchestrator.py`) with token auth + state persistence.
- ✅ Log rotation + archival CLI (`core_engine/log_exporter.py`, `cli/logs.py`) delivering full audit bundles.
- ✅ Remediation enforcement: master queues `apply_remediation` commands, workers execute via `firewall_hooks`.
- ✅ Phase 5 operator dashboard (`gui/app.py`) for live node status & log tail (Textual TUI).
- ✅ Cross-platform launch scripts (`/scripts`) + quick start doc for turnkey setup.

### Planned Next Steps
- Expand to **cloud orchestration layer** for master node control (SaaS tier).
- Harden remediation path with enforceable firewall hooks & audit trail.
- Add config hot-reload + CLI UX polish around new agent workflow.

---

## 📦 Current Development Phase

**Phase 0 — Reproducible Setup (Complete)**
✅ Master/worker/orchestrator stack is locally functional.
✅ Runtime and development dependency manifests are now present.
✅ Setup docs standardize on the repo-local `portmap-ai-env`.
✅ Fresh repo-local setup, tests, stack smoke, and TUI launch path are documented.

**Phase 1 — Unified CLI Interface (Complete)**
✅ Added `python -m cli.main scan`, `stack`, `tui`, `health`, `nodes`, `metrics`, and `logs`.
✅ Added CLI tests for scan output, stack command construction, API checks, log export, and TUI launch wiring.
✅ CLI wraps existing modules and launchers rather than replacing them.
✅ Phase 2 packaging exposes the unified CLI as the installed `portmap` console command.

**Phase 2 — Packaged Local Install (Complete Baseline)**
✅ Added `pyproject.toml` for editable local installs.
✅ Added console scripts: `portmap`, `portmap-agent`, `portmap-dashboard`, `portmap-export-logs`, `portmap-master`, `portmap-orchestrator`, and `portmap-worker`.
✅ Moved stack launcher into importable `core_engine.stack_launcher`; `scripts/run_stack.py` is now a compatibility wrapper.
✅ Packaged default local stack configs under `core_engine/default_configs`.
✅ Verified editable install and non-editable wheel install.
✅ Verified `portmap --help`, `portmap scan --output json`, service command help output, and `portmap stack --no-dashboard --verbose` from outside the source tree.
✅ Added packaging metadata tests.

**Phase 3 — Configuration Hardening (Complete)**
✅ Added `core_engine.config_validation` with structured validation results, errors, warnings, and JSON/text formatting.
✅ Added `portmap config validate <path...>` with text and JSON output modes plus optional `--role` enforcement.
✅ Validator checks node roles, ports, hosts, scan intervals, remediation settings, log settings, TLS fields, firewall settings, expected services, env-substituted numeric values, and legacy-key warnings.
✅ Orchestrator, master, and worker validate configs before startup after defaults/profiles/settings are merged.
✅ Worker `--watch-config` validates reloads and skips invalid updates while keeping current runtime settings.
✅ `portmap stack` validates orchestrator/master/worker configs before launching subprocesses.

**Phase 4 — Platform Abstraction Layer (Complete Baseline)**
✅ Added `core_engine.platform_utils` for OS/CPU detection, network interface enumeration, process-name lookup, local address resolution, listener PID lookup, and port-listening probes.
✅ Moved scanner connection enumeration/process lookup behind the platform abstraction.
✅ Moved stack-launcher port conflict probing, Python module launch, and subprocess shutdown behind the platform abstraction while preserving existing compatibility helpers.
✅ Worker registration and background-agent registration now use the shared local address helper.
✅ Linux firewall plugin now uses shared executable lookup and command execution helpers.
✅ Legacy scan/remediator CLI paths now use shared connection/process/terminal/PID helpers.
✅ Added `docs/platform_abstraction.md` and package-data inclusion.

**Phase 5 — Stack Stability (Complete Baseline)**
✅ `portmap stack` now supervises orchestrator, master, and worker with bounded restart attempts (`--restart-limit`, `--no-restart`).
✅ Dashboard exits no longer force the core stack down.
✅ Stack shutdown uses shared platform process helpers for consistent terminate/kill behavior.
✅ Worker node and background agent re-register with the orchestrator after unknown-node heartbeat responses, covering orchestrator restarts or state loss.
✅ Orchestrator state marks stale nodes offline after `node_stale_after` seconds without heartbeat; set `0` to disable stale detection.
✅ Added focused tests for restart policy, re-registration, stale-node detection, and stale-timeout config validation.
✅ Added `docs/stack_stability.md` and package-data inclusion.

**Phase 6 — Logging and Audit (Complete Baseline)**
✅ Added `core_engine.audit_events` for normalized structured JSONL audit records.
✅ Command outcomes now include common fields (`timestamp`, `event_type`, `node_id`, `action`, `status`) and are mirrored into `audit_events.jsonl`.
✅ Remediation decisions now include common fields plus `risk_score`, enforcement mode, score factors, and source details, and are mirrored into `audit_events.jsonl`.
✅ Master telemetry JSON lines now include `event_type`, `timestamp`, `node_id`, `risk_score`, sampled ports, anomalies, and score factors.
✅ Added audit filtering through `portmap logs --filter-node`, `--filter-event-type`, and `--tail`; archive export remains unchanged.
✅ Added `docs/logging_audit.md` and package-data inclusion.

**Phase 7 — Remediation Safety (Complete Baseline)**
✅ Added `core_engine.remediation_safety` with destructive-action detection, active-enforcement policy, confirmation checks, and dry-run enforcement.
✅ Destructive commands (`block`, `drop`, `kill`, `kill_process`, `terminate`) are forced to dry-run unless active enforcement is explicitly enabled and the command is confirmed.
✅ Active destructive execution now requires firewall `dry_run: false`, `remediation_safety.active_enforcement_enabled: true`, and command-level `confirmed: true`; optional confirmation tokens are supported.
✅ Master remediation commands and background-agent command execution both pass through the safety gate.
✅ Remediation safety policy is validated by config validation.
✅ Added `docs/remediation_safety.md` and package-data inclusion.

**Phase 8 — Scanner and Risk Engine (Complete Baseline)**
✅ Added `core_engine.risky_ports` as a centralized known risky-port and service-hint database.
✅ Scanner rows now include `service_name` when the local port maps to a known/common service.
✅ Heuristic scoring now uses risky-port severity, all-interface listeners, high ephemeral listeners, unusual socket states, public remote endpoints, suspicious process markers, payload presence, and expected-service allowlists.
✅ Every heuristic score now includes both `score_factors` and human-readable `risk_explanation`.
✅ ML scoring path now preserves a basic `risk_explanation` as well.
✅ Added `docs/scanner_risk_engine.md` and package-data inclusion.

**Phase 9 — AI Layer (Complete Baseline)**
✅ Added `ai_agent.interface` with `AIProvider`, `AIAnalysisResult`, connection payload validation, and provider result validation.
✅ Wrapped existing heuristic and optional local ML scoring in `LocalAIProvider`, preserving the current stable default behavior.
✅ Added `StubAIProvider` for safe local placeholder analysis in tests, UI work, or future integration scaffolding.
✅ Added provider injection/reset helpers for future local or API-backed AI integrations.
✅ `get_score()` now records `ai_provider` and validates provider output before mutating scan payloads.
✅ Provider failures fall back to heuristic scoring with `ai_provider_failed` and fallback metadata instead of interrupting scans.
✅ Added `docs/ai_layer.md` and package-data inclusion.

**Phase 10 — TUI Improvements (Complete Baseline)**
✅ Dashboard displays node overview, local remediation totals, firewall mode, orchestrator health, and `/metrics` counters.
✅ Added a dedicated Scan Results panel showing sampled ports, score, provider, status, and scoring signals.
✅ Remediation Feed, Command Outcomes, Expected Services, and Master Log Tail remain visible in the primary operator workflow.
✅ Dashboard controls queue scan/autolearn commands for the selected node, export logs, detect orchestrator, adjust tail size, and manage expected-service allowlists.
✅ Fixed selected-node command resolution to follow the highlighted row when available.
✅ Added `docs/tui_dashboard.md` and package-data inclusion.

**Phase 11 — Docker Deployment (Complete Baseline)**
✅ Added `docker-compose.yml` for orchestrator, master, and worker services.
✅ Added Docker-specific configs under `docker/config/` with service DNS names and environment placeholders.
✅ Added `docker/master.Dockerfile` and updated orchestrator/worker Dockerfiles to install the runtime package instead of dev requirements.
✅ Added persistent `portmap-runtime` volume mounted at `/root/.portmap-ai` for logs, state, settings, and exports.
✅ Added orchestrator health check and compose service dependencies.
✅ Added `.dockerignore` to keep local venvs, logs, state, build outputs, and JSONL files out of images.
✅ Added `docs/docker_deployment.md` and package-data inclusion.
✅ Clarified Docker as an optional advanced deployment path, not the default user requirement.
⚠️ Local compose syntax/runtime check was blocked because this Docker install lacks the `docker compose` plugin and no legacy `docker-compose` binary is installed.

**Phase 12 — Raspberry Pi / Linux Service Deployment (Complete Baseline)**
✅ Added `config/profiles/raspberry_pi.json` as a low-resource Linux/ARM profile with env-overridable host, port, timeout, scan interval, and log rotation settings.
✅ Added user-scoped systemd templates for an all-in-one local stack and a worker-only node under `deploy/systemd/`.
✅ Added `scripts/install_systemd_user.sh` to install user services without requiring system-wide sudo operations.
✅ Added `docs/raspberry_pi_deployment.md` covering Raspberry Pi OS, Debian/Ubuntu small hosts, service mode, resource guidance, worker-only mode, and LAN-scanning safety.
✅ Packaging metadata now includes the Raspberry Pi profile, systemd templates, and deployment documentation.
✅ Added tests for profile loading/validation, systemd templates, and user-scoped install script behavior.
✅ Guidance explicitly keeps Raspberry Pi as one Linux/ARM target while preserving macOS, general Linux, Docker, and future Windows support.

**Phase 13 — Packaging (Complete Baseline)**
✅ Added `core_engine.runtime_setup` for local runtime initialization, platform support reporting, runtime paths, and packaging diagnostics.
✅ Added `portmap setup` to initialize `~/.portmap-ai`, data/log/export directories, and default settings without installing Docker or privileged components.
✅ Added `portmap doctor` to report Python version, OS/architecture support level, runtime paths, packaged config availability, command availability, and native service guidance.
✅ Added `docs/packaging.md` covering supported baseline, local install flow, setup/doctor commands, build artifacts, and non-developer UX goals.
✅ Updated `scripts/package_local.sh` so source bundles instruct users to install runtime dependencies, run `portmap setup`, and run `portmap doctor`.
✅ Packaging metadata now includes packaging docs and the systemd install helper.
✅ Added tests for runtime setup, platform support messaging, setup/doctor CLI commands, and package-data inclusion.

**Phase 14 — Network Control Layer (Complete Baseline)**
✅ Added `core_engine.network_control` for read-only gateway detection, local network enumeration, exposed-service classification, and posture recommendations.
✅ Added `portmap network` with text and JSON output.
✅ Gateway detection uses read-only platform-native commands when available (`ip route`, `route -n get default`, `route print`).
✅ Exposed services are derived from local scanner output and classified as loopback-only, LAN interface, all interfaces, public interface, or unknown.
✅ Recommendations are advisory-only and explicitly avoid router, firewall, NAT, or port-forward changes.
✅ Added `docs/network_control_layer.md` and package-data inclusion.
✅ Added tests for gateway parsing, local network extraction, exposed-service classification, advisory-only posture output, and CLI wiring.

**Phase 15 — Security and Authentication (Complete Baseline)**
✅ Added `core_engine.security` with bearer-token extraction, constant-time token verification, token fingerprints, secret redaction, metadata scrubbing, and node identity validation.
✅ Orchestrator auth now uses constant-time bearer-token checks instead of direct string comparison.
✅ Orchestrator registration, heartbeat, and command endpoints reject malformed node IDs, invalid roles, and non-object command payloads before state mutation.
✅ Config loading now supports `${secret:ENV_VAR}` for environment-backed secret values.
✅ Orchestrator state scrubs token/secret/password/key/credential metadata before persistence.
✅ Config validation checks auth token field types and warns when default development tokens remain configured.
✅ Added `docs/security_authentication.md` and package-data inclusion.
✅ Added tests for auth helpers, secret interpolation, state scrubbing, auth validation, and packaging metadata.

**Phase 16 — SaaS Preparation (Complete Baseline)**
✅ Added `core_engine.enrollment` schema helpers for tenant identity, enrollment requests, enrollment packages, and persisted agent identities.
✅ Enrollment package validation checks tenant/org/node identity, agent role, enrollment token shape, control-plane URL shape, and expiry type.
✅ Agent identity creation stores an enrollment token fingerprint instead of preserving the raw enrollment secret.
✅ Added redaction helper for enrollment packages.
✅ Added `docs/saas_architecture.md` documenting local-agent/control-plane separation, multi-tenant model, enrollment flow, outbound communication model, security boundaries, and intentionally unimplemented SaaS pieces.
✅ Added focused enrollment tests.

**Phase 17 — Documentation (Complete Baseline)**
✅ Added `docs/architecture.md` as the current local-first architecture guide.
✅ Updated `docs/README.txt` so new users can find setup, architecture, deployment, security, SaaS, and release-candidate docs.
✅ Updated `test_instructions.md` with Phase 16-18 checks.
✅ Packaging metadata now includes the architecture, SaaS, release-candidate, and changelog artifacts.

**Phase 18 — Release Candidate (Complete Baseline)**
✅ Confirmed project version remains `0.1.0` in `pyproject.toml`.
✅ Added `CHANGELOG.md` for the 0.1.0 release candidate.
✅ Added `docs/release_candidate.md` covering release scope, verification checklist, packaging notes, known limitations, and release decision.
✅ Added release-candidate tests for version/docs alignment and operator verification commands.
✅ Focused Phase 16-18 verification passes.
✅ Final full-suite verification passes: `154 passed, 1 skipped`.
✅ Wheel build smoke test passes for `portmap_ai-0.1.0-py3-none-any.whl`.
🧩 Next: perform any real-device runtime smoke checks desired for Linux/Raspberry Pi/Docker Compose, then tag 0.1.0.

**GitHub Readiness Cleanup (Complete Baseline)**
✅ Added `SECURITY.md` with safe deployment defaults, remote-deployment requirements, reporting guidance, and known security gaps.
✅ Hardened Docker Compose so published services require an explicit `PORTMAP_ORCHESTRATOR_TOKEN`; no Docker `test-token` fallback remains.
✅ Changed the default packaged local master config to bind `127.0.0.1` instead of `0.0.0.0`.
✅ Redacted stack-launcher token mismatch errors with token fingerprints instead of raw tokens.
✅ Systemd user-service install now creates a private `~/.portmap-ai/portmap-ai.env` with a generated token when absent; service templates read that environment file.
✅ Removed runtime logs/state from the Git index and expanded ignore rules for logs, JSONL files, build outputs, archives, local data, caches, and virtual environments.
✅ Removed stale planning docs, sandbox simulation files, deprecated core-engine experiments, and the stray root-level `scriptsrun_orchestrator.bat`.
✅ Re-audited for personal paths and obvious token exposure patterns; remaining `test-token` references are local-development defaults/tests/docs with warnings.
✅ Focused hardening tests pass; full suite passes after cleanup: `154 passed, 1 skipped`.

**Phase 19 — UDP Scanning Engine (Started / Complete Baseline)**
✅ Added `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md` as the Phase 19-40 enterprise expansion roadmap.
✅ Added isolated `core_engine.modules.udp_scanner` with common UDP probes, timeout handling, retry logic, safe port limits, and JSON-serializable result rows.
✅ UDP results classify states as `open`, `closed`, `filtered`, or `unknown`.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `portmap scan --udp-target ... --udp-ports ...` CLI support while preserving existing local socket scanning.
✅ Added `docs/udp_scanning.md` and package-data inclusion.
✅ Added focused UDP scanner and CLI tests.
✅ Full-suite verification after Phase 19 passes: `164 passed, 1 skipped`.

**Phase 20 — IPv6 and Dual-Stack Support (Started / Complete Baseline)**
✅ Added `core_engine.modules.ip_utils` for IPv4/IPv6 literal parsing, bracketed IPv6 handling, CIDR expansion, hostname resolution, IP-version filtering, and safe target limits.
✅ Added `core_engine.modules.ipv6_scanner` for conservative active TCP `connect_ex` probes across IPv4 and IPv6 targets.
✅ Active TCP scan rows follow the existing JSON-serializable scanner output style and include `tcp_state`, `ip_version`, `target_source`, and reason fields.
✅ Added `portmap scan --target ... --ports ... --ip-version ...` CLI support while preserving default local socket inventory behavior.
✅ Added malformed-target rejection, CIDR expansion limits, TCP port validation, safe defaults, and explicit aggressive-mode limits.
✅ Added `docs/ipv6_dual_stack.md` and package-data inclusion.
✅ Added focused IP utility, dual-stack scanner, CLI, and packaging tests.
✅ Full-suite verification after Phase 20 passes: `178 passed, 1 skipped`.

**Phase 21 — Network Asset Inventory (Complete Baseline)**
✅ Reframed Phase 21 from broad host discovery to authorized network asset inventory.
✅ Added `core_engine.modules.discovery` for subnet asset enumeration, ARP table parsing, platform ping reachability checks, TCP transport availability checks, local topology snapshots, broadcast candidates, and orchestrator-ready telemetry events.
✅ Added `portmap discover --range ... --method arp|ping|tcp --output json` with safe defaults, local-network fallback when no range is provided, target limits, and explicit aggressive-mode override.
✅ Asset rows are JSON serializable and include status, evidence, methods, MAC/interface details, target source, IP version, and open/closed transport ports.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/network_asset_inventory.md` and package-data inclusion.
✅ Added focused discovery and CLI tests.
✅ Focused Phase 21 verification passes: `31 passed`.
✅ Full-suite verification after Phase 21 passes: `191 passed, 1 skipped`.

**Phase 22 — Service Enumeration (Complete Baseline)**
✅ Added isolated `core_engine.modules.service_detection` for safe TCP banner grabbing, HTTP/HTTPS HEAD probes, SMTP EHLO fallback, fingerprint matching, confidence scoring, version extraction, and unknown-service handling.
✅ Added packaged fingerprint database at `core_engine/service_fingerprints.json`; the loader also checks `data/service_fingerprints.json` first when that local ignored runtime path is writable.
✅ Initial service support covers SSH, HTTP, HTTPS, FTP, SMTP, DNS, SMB, and RDP.
✅ Added `portmap services --target ... --ports ... --ip-version ... --output json` with safe target/port limits and explicit aggressive-mode override.
✅ Service rows are JSON serializable and include target, remote endpoint, state, service, version, confidence, banner, probe, evidence, and reason.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/service_enumeration.md` and package-data inclusion.
✅ Added focused service-detection and CLI tests.
✅ Focused Phase 22 verification passes: `33 passed`.
✅ Full-suite verification after Phase 22 passes: `203 passed, 1 skipped`.

**Phase 23 — OS Fingerprinting (Complete Baseline)**
✅ Added isolated `core_engine.modules.os_fingerprint` for probabilistic OS-family inference from TTL, TCP window size, TCP option markers, service evidence, and banner evidence.
✅ Added packaged OS fingerprint database at `core_engine/os_fingerprints.json`; the loader also checks `data/os_fingerprints.json` first when that local ignored runtime path is writable.
✅ Initial OS-family support covers Windows, Linux, macOS, BSD, and network appliances.
✅ Added passive observation support through `fingerprint_observation()` and active context support through safe Phase 22 service enumeration.
✅ Added `portmap os --target ...` and `portmap os --observation-json ...` with safe target/port limits and explicit aggressive-mode override.
✅ Low-confidence results are reported as `unknown` with candidate explanations rather than overstating certainty.
✅ Fingerprint rows are JSON serializable and include target, probable OS, confidence, certainty, evidence, candidates, notes, and optional service results.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/os_fingerprinting.md` and package-data inclusion.
✅ Added focused OS-fingerprinting and CLI tests.
✅ Focused Phase 23 verification passes: `32 passed`.
✅ Full-suite verification after Phase 23 passes: `212 passed, 1 skipped`.

**Phase 24 — High-Speed Multithreaded Scan Engine (Complete Baseline)**
✅ Added `core_engine.modules.scan_scheduler` for safe target/port expansion, scan planning, concurrency limits, rate limits, batch estimates, adaptive delay helpers, and aggressive-mode warnings.
✅ Added `core_engine.modules.async_scanner` for asyncio-based TCP connect scanning with JSON-serializable scanner rows compatible with existing active TCP scan output.
✅ Added `portmap fast-scan --target ... --ports ... --concurrency ... --rate ... --output json` with safe target/port/concurrency/rate defaults and explicit aggressive-mode override.
✅ Async scan rows include target, remote endpoint, IP version, status, TCP state, service hint, reason, duration, and scanner metadata.
✅ Adaptive delay handling increases pacing under elevated timeout/error pressure.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/high_speed_scan_engine.md` and package-data inclusion.
✅ Added focused scheduler, async scanner, and CLI tests.
✅ Focused Phase 24 verification passes: `38 passed`.
✅ Full-suite verification after Phase 24 passes: `224 passed, 1 skipped`.

**Phase 25 — Packet Capture Core (Complete Baseline)**
✅ Added `core_engine.modules.packet_capture` for interface selection, safe live-capture orchestration, Ethernet/IP/TCP/UDP/ICMP/ARP metadata extraction, simple capture filters, and graceful unsupported/permission results.
✅ Added `core_engine.modules.pcap_writer` as a stdlib-only classic PCAP writer for operator-requested packet export.
✅ Added `portmap capture --interface ... --duration ... --max-packets ... --filter ... --pcap ... --output json`.
✅ Capture metadata rows are JSON serializable and include interface, lengths, MACs, IPs, protocols, ports, TTL/hop-limit, TCP flags/window, UDP length, ICMP fields, payload byte counts, and parse reasons without storing payload bytes in JSON output.
✅ Linux live capture attempts use the stdlib AF_PACKET backend when available; macOS/Windows and missing privileges return structured `unsupported_capture_backend` or `permission_denied` results instead of crashing.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/packet_capture.md` and package-data inclusion.
✅ Added focused packet-capture and CLI tests.
✅ Focused Phase 25 verification passes: `37 passed`.
✅ Runtime CLI smoke on macOS returns graceful `unsupported_capture_backend`.
✅ Full-suite verification after Phase 25 passes: `233 passed, 1 skipped`.

**Phase 26 — Protocol Dissector Framework (Complete Baseline)**
✅ Added `core_engine.protocols` package with isolated passive dissectors for HTTP, DNS, ICMP/ICMPv6, TLS, SSH, SMB, DHCP, FTP, and SMTP.
✅ Added protocol dispatcher helpers for Ethernet/IP/TCP/UDP/ICMP payload extraction, port/payload-based protocol classification, direct payload dissection, and packet-level dissection.
✅ Integrated protocol summaries into packet capture through explicit `portmap capture --dissect`; default capture output remains metadata-only.
✅ Dissection rows are JSON serializable and include protocol, status, confidence, summary, fields, evidence, payload byte counts, and parser errors without storing raw payload bytes.
✅ Unknown, unsupported, short, or malformed payloads are labeled safely as `unknown` or `error` instead of interrupting capture.
✅ FTP and SMTP dissectors redact sensitive command arguments such as credentials and email envelope values.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/protocol_dissectors.md` and package-data inclusion.
✅ Added focused protocol, packet-capture, CLI, and packaging tests.
✅ Focused Phase 26 verification passes: `47 passed`.
✅ Runtime CLI smoke with `--dissect` on macOS returns graceful `unsupported_capture_backend`.
✅ Full-suite verification after Phase 26 passes: `243 passed, 1 skipped`.

**Phase 27 — Deep Packet Inspection (Complete Baseline)**
✅ Added `core_engine.modules.dpi` for passive DPI analysis of packet bytes, payload observations, protocol dissection results, and metadata-only capture rows.
✅ DPI extracts safe header summaries, payload length, SHA-256, entropy, printable ratio, null-byte count, content category, and optional redacted previews.
✅ Added suspicious indicator detection for credential markers, script injection markers, SQL injection markers, shell command markers, high-entropy payloads, cleartext FTP/SMTP identity/auth commands, and cleartext HTTP login-like flows.
✅ Added malformed protocol indicators for parser errors, unrecognized payloads for known protocols, and truncated TLS records.
✅ Added bidirectional session keys and basic session grouping summaries for future flow/correlation layers.
✅ Integrated DPI through `portmap dpi --observation-json ...` and optional `portmap capture --dpi`; default capture output remains metadata-only unless DPI is explicit.
✅ DPI output is JSON serializable and does not store raw payload bytes by default; optional previews are bounded and redacted.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/deep_packet_inspection.md` and package-data inclusion.
✅ Added focused DPI, packet-capture, CLI, and packaging tests.
✅ Focused Phase 27 verification passes: `47 passed`.
✅ Runtime CLI smoke for `portmap dpi` redacts sensitive preview values; capture `--dpi` returns graceful `unsupported_capture_backend` on macOS.
✅ Full-suite verification after Phase 27 passes: `252 passed, 1 skipped`.

**Phase 28 — TLS Intelligence Layer (Complete Baseline)**
✅ Added `core_engine.modules.tls_inspector` for read-only TLS protocol, cipher-suite, certificate, expiration, self-signed, and hostname posture analysis.
✅ Added live TLS handshake support with bounded target/port expansion and offline observation analysis for deterministic tests and operator-provided evidence.
✅ TLS rows are JSON serializable and include target, port, server name, TLS version status, cipher analysis, certificate metadata, warnings, and advisory risk score.
✅ Weak posture indicators cover deprecated TLS versions, RC4, DES/3DES, MD5, NULL, EXPORT, anonymous suites, small key sizes, soon-to-expire/expired certificates, self-signed certificates, and hostname mismatches.
✅ Added `portmap tls --target ... --ports ... --server-name ... --output json` and `portmap tls --observation-json ...`.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/tls_intelligence.md` and package-data inclusion.
✅ Added focused TLS-inspector, CLI, and packaging tests.
✅ Focused Phase 28 verification passes: `41 passed`.
✅ Runtime CLI smoke for `portmap tls --observation-json ...` reports deprecated TLS/cipher/certificate warnings without network access.
✅ Full-suite verification after Phase 28 passes: `263 passed, 1 skipped`.

**Phase 29 — Traffic Flow Reconstruction (Complete Baseline)**
✅ Added `core_engine.modules.flow_tracker` for passive bidirectional flow reconstruction from packet metadata, capture rows, DPI records, and nested metadata observations.
✅ Flow reconstruction supports source/destination lineage, initiator/responder assignment, time-windowed session splitting, directional packet/payload counters, transport summaries, application-protocol summaries, finding/evidence aggregation, and stable flow IDs.
✅ Added topology-ready node and edge summaries for future GUI/topology and AI correlation layers.
✅ Added `portmap flows --events-json ... --window ... --output json` for offline flow reconstruction from JSON metadata.
✅ Added optional `portmap capture --flows` integration; default capture output remains metadata-only unless flow summaries are explicit.
✅ Flow output is JSON serializable and stores no raw payload bytes.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/traffic_flow_reconstruction.md` and package-data inclusion.
✅ Added focused flow-tracker, packet-capture, CLI, and packaging tests.
✅ Focused Phase 29 verification passes: `51 passed`.
✅ Runtime CLI smoke for `portmap flows --events-json ...` produces flow/topology JSON; capture `--flows` returns graceful `unsupported_capture_backend` on macOS.
✅ Full-suite verification after Phase 29 passes: `272 passed, 1 skipped`.

**Phase 30 — AI Behavioral Learning (Complete Baseline)**
✅ Added `ai_agent.baseline_store` for local JSON behavior baselines under `~/.portmap-ai/data/behavior_baseline.json` by default, with explicit path override support.
✅ Added `ai_agent.behavior_model` for local behavioral analysis of packet, flow, scan, service, DPI, and nested metadata observations.
✅ Behavior profiles learn per-device event counts, normal destination ports, peers, application protocols, transports, and active hour buckets.
✅ Added advisory anomaly findings for new devices, new destination ports, new peers, new application protocols, unusual hours, rare values, and low-confidence baselines.
✅ Added `portmap behavior --events-json ... --baseline ... --learn --output json`; baseline updates occur only when `--learn` is explicit.
✅ Behavioral analysis output is JSON serializable and stores no raw payload bytes.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/ai_behavioral_learning.md` and package-data inclusion.
✅ Added focused behavior-model, baseline-store, CLI, and packaging tests.
✅ Focused Phase 30 verification passes: `44 passed`.
✅ Runtime CLI smoke for `portmap behavior --events-json ...` reports advisory anomaly output without writing a baseline.
✅ Full-suite verification after Phase 30 passes: `282 passed, 1 skipped`.

**Phase 31 — AI Payload Classification (Complete Baseline)**
✅ Added `ai_agent.payload_classifier` for local payload classification from direct observations, DPI payload metadata, and nested network metadata.
✅ Payload classification supports `payload_text`, `payload_hex`, `payload_b64`, and existing safe payload metadata inputs.
✅ Added labels, confidence scores, advisory risk scores, and findings for credential markers, script injection markers, SQL injection markers, command markers, high-entropy payloads, cleartext sensitive payloads, protocol misuse, possible tunneled payloads, possible exfiltration payloads, public-destination exfiltration volume, and beaconing candidates.
✅ Added aggregate event analysis for regular small-payload beaconing patterns and public-destination payload volume.
✅ Added `portmap payload --events-json ... --include-payload-preview --output json`; optional previews are bounded and redacted.
✅ Payload classification output is JSON serializable and stores no raw payload bytes by default.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/ai_payload_classification.md` and package-data inclusion.
✅ Added focused payload-classifier, CLI, and packaging tests.
✅ Focused Phase 31 verification passes: `47 passed`.
✅ Runtime CLI smoke for `portmap payload --events-json ...` reports sensitive-cleartext findings without echoing raw secrets.
✅ Full-suite verification after Phase 31 passes: `292 passed, 1 skipped`.

**Phase 32 — Threat Correlation Engine (Complete Baseline)**
✅ Added `ai_agent.threat_correlation` for local advisory event normalization and incident correlation across behavior, payload, flow, scan, service, OS, TLS, and generic records.
✅ Correlation detects repeated anomalies, suspicious scan behavior, lateral movement indicators, and chained behavior/payload risk within configurable time windows.
✅ Incident rows are JSON serializable and include stable incident IDs, entity, severity, score, first/last seen timestamps, peers, ports, linked findings, event IDs, explanation, and supporting evidence summaries.
✅ Added `portmap correlate --events-json ... --window ... --output json` for offline local correlation.
✅ Threat correlation output stores no raw payload bytes and remains advisory-only.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/threat_correlation.md` and package-data inclusion.
✅ Added focused threat-correlation, CLI, and packaging tests.
✅ Focused Phase 32 verification passes: `48 passed`.
✅ Runtime CLI smoke for `portmap correlate --events-json ...` produces repeated-anomaly incident output.
✅ Full-suite verification after Phase 32 passes: `301 passed, 1 skipped`.

**Phase 33 — AI Recommendation Engine (Complete Baseline)**
✅ Added `ai_agent.recommendation_engine` for local advisory recommendations from Phase 32 correlated incidents.
✅ Recommendations include investigation, scan-source review, segmentation review, host evidence collection, credential rotation, egress policy review, and dry-run remediation drafts for high-scoring incidents.
✅ Recommendation rows are JSON serializable and include stable recommendation IDs, incident linkage, action, target, priority, confidence, reason, operator prompt, supporting evidence, approval flags, and optional remediation command drafts.
✅ Destructive recommendations are always marked `approval_required: true`, `dry_run: true`, `confirmed: false`, and `destructive: true`.
✅ Added `portmap recommend --incidents-json ... --review-threshold ... --approval-threshold ... --output json`.
✅ Recommendation output stores no raw payload bytes and performs no automatic changes.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/ai_recommendation_engine.md` and package-data inclusion.
✅ Added focused recommendation-engine, CLI, and packaging tests.
✅ Focused Phase 33 verification passes: `49 passed`.
✅ Runtime CLI smoke for `portmap recommend --incidents-json ...` produces dry-run approval-required containment drafts.
✅ Full-suite verification after Phase 33 passes: `309 passed, 1 skipped`.

**Phase 34 — CVE Intelligence Engine (Complete Baseline)**
✅ Added `core_engine.vuln` package with `cve_client`, `cve_store`, and `cvss` helpers for advisory vulnerability intelligence.
✅ CVE normalization supports NVD-style records, existing normalized records, descriptions, CVSS metrics, severity, CWE IDs, CPE criteria, references, and known-exploited flags when provided.
✅ Added local service/version-to-CVE matching with service aliases, CPE evidence, version token matching, confidence scoring, and advisory risk scoring.
✅ Added local CVE cache persistence under `~/.portmap-ai/data/cve_cache.json` with merge/dedupe behavior and custom cache-path support.
✅ Added explicit NVD update support through `portmap cve --update --query ...` or `--cve-id ...`; network access is not used unless `--update` is requested.
✅ Added `portmap cve --service-json ... --cve-json ... --min-confidence ... --output json|table` for offline matching.
✅ CVE output is JSON serializable, stores no raw payload bytes, and performs no automatic changes beyond explicit local cache writes during `--update`.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/cve_intelligence.md` and package-data inclusion.
✅ Added focused CVE-client, CLI, and packaging tests.
✅ Focused Phase 34 verification passes: `51 passed`.
✅ Runtime CLI smoke for `portmap cve --service-json ... --cve-json ...` produces advisory CVE matches without network access.
✅ Full-suite verification after Phase 34 passes: `317 passed, 1 skipped`.

**Phase 35 — Vulnerability Correlation System (Complete Baseline)**
✅ Added `core_engine.vuln.vuln_correlator` for advisory service/CVE exposure correlation and prioritization.
✅ Vulnerability findings combine service evidence, CVE matches, exposure scope, CVSS/risk score, known-exploited flags, ransomware association fields, and exploitability indicators.
✅ Exposure classification covers open/listening services, public interfaces, all-interface binds, LAN exposure, and unknown scope.
✅ Exploitability indicators include remote code execution, authentication bypass, privilege escalation, path traversal, SQL injection, credential exposure, denial of service, and known-exploited evidence.
✅ Finding rows are JSON serializable and include stable vulnerability IDs, priority labels/scores, explanations, recommended operator-review actions, and evidence summaries.
✅ Added `portmap vuln --service-json ... --cve-matches-json ... --cve-json ... --min-confidence ... --output json|table`.
✅ Vulnerability correlation output stores no raw payload bytes and performs no automatic changes.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/vulnerability_correlation.md` and package-data inclusion.
✅ Added focused vulnerability-correlator, CVE-client, CLI, and packaging tests.
✅ Focused Phase 35 verification passes: `59 passed`.
✅ Runtime CLI smoke for `portmap vuln --service-json ... --cve-matches-json ...` produces critical advisory findings without network access.
✅ Full-suite verification after Phase 35 passes: `325 passed, 1 skipped`.

**Phase 36 — Enterprise Security Layer (Complete Baseline)**
✅ Added `core_engine.enterprise_auth` for stdlib-only HS256 token issuing/verification, audience/expiry/role checks, PBKDF2-SHA256 password records, and public user-record redaction.
✅ Added `core_engine.rbac` with local roles (`admin`, `analyst`, `viewer`, `agent`), inheritance, effective permissions, and authorization decisions.
✅ Added `core_engine.enterprise_audit` for normalized enterprise security audit events with shared secret scrubbing.
✅ Added `core_engine.agent_identity` for secure agent identity records, generated one-time agent secrets, secret fingerprints, HMAC message signatures, timestamp-skew validation, and mTLS-ready certificate fingerprint fields.
✅ Added `portmap rbac --roles ... --permission ... --output json|table` for local role/permission inspection.
✅ Enterprise security output stores no raw bearer tokens or generated agent secrets and does not replace current local development auth defaults.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/enterprise_security.md` and package-data inclusion.
✅ Added focused enterprise-security, security, enrollment, CLI, and packaging tests.
✅ Focused Phase 36 verification passes: `66 passed`.
✅ Runtime CLI smoke for `portmap rbac --roles analyst --permission generate:recommendations --output json` grants the expected inherited permissions.
✅ Full-suite verification after Phase 36 passes: `334 passed, 1 skipped`.

**Phase 37 — Alerting and SIEM Integrations (Complete Baseline)**
✅ Added `core_engine.integrations` package with common alert normalization, webhook, Splunk HEC, Elastic, Sentinel, and email helpers.
✅ Generic webhook, Slack-compatible, Teams-compatible, Splunk HEC, Elastic document/bulk, Sentinel-ready JSON, and email alert payloads are generated locally.
✅ Delivery helpers default to dry-run, require explicit `--send` for network/SMTP delivery, and return structured delivery results instead of raising on failures.
✅ Webhook/SIEM/email failure isolation catches delivery errors and reports failed destination/status/detail without interrupting callers.
✅ Added `portmap alert --event-json ... --format generic|slack|teams|splunk|elastic|sentinel|email --output json|table`.
✅ Explicit send paths support webhook URLs, Splunk HEC token headers, Elastic API key headers, and SMTP email options without persisting secrets.
✅ Alerting/SIEM output stores no raw credentials and performs no automatic changes.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/alerting_siem_integrations.md` and package-data inclusion.
✅ Added focused integration, CLI, and packaging tests.
✅ Focused Phase 37 verification passes: `56 passed`.
✅ Runtime CLI smoke for `portmap alert --event-json ... --format slack --output json` produces a dry-run Slack-compatible payload without sending network traffic.
✅ Full-suite verification after Phase 37 passes: `341 passed, 1 skipped`.

**Phase 38 — Visualization and GUI Platform (Complete Baseline)**
✅ Added `gui.visualization` for reusable risk timeline, topology edge, traffic flow, and dashboard summary helpers.
✅ Expanded the Textual dashboard with Risk Timeline, Topology Edges, and Traffic Flows panels while preserving the existing terminal UI product direction.
✅ Dashboard visualization consumes passive flow telemetry from `~/.portmap-ai/logs/flow_events.jsonl` or flow-capable `master_events.log` entries when available.
✅ Risk timeline summaries bucket recent scan/remediation scores into low, medium, high, and critical trend rows.
✅ Topology and flow panels display initiator/responder relationships, protocols, packet counts, payload byte counts, and findings without storing raw payload bytes.
✅ Dashboard metrics now include flow count, topology node/edge counts, and latest max score alongside node/orchestrator/remediation status.
✅ Visualization remains read-only.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/visualization_gui_platform.md` and package-data inclusion.
✅ Added focused visualization/dashboard and packaging tests.
✅ Focused Phase 38 verification passes: `25 passed`.
✅ Runtime dashboard construction smoke imports `PortMapDashboard` and visualization helpers without launching an interactive TUI.
✅ Full-suite verification after Phase 38 passes: `345 passed, 1 skipped`.

**Phase 39 — Distributed Cluster Scanning (Complete Baseline)**
✅ Added `core_engine.cluster` package with worker registry, distributed job queue, and safe scan scheduler primitives.
✅ Worker registry normalizes orchestrator worker nodes, health status, scan capabilities, stale workers, max concurrency, active jobs, and available capacity.
✅ Job queue tracks cluster jobs, planned/assigned/running/completed/partial/failed states, task attempts, retry state, task results, errors, and aggregate result output.
✅ Distributed scheduler reuses the Phase 24 safe scan planner for target, port, concurrency, rate, and aggressive-mode validation.
✅ Scheduler partitions authorized target/port sets into bounded tasks and assigns them across available worker capacity without executing probes.
✅ Added `portmap cluster plan --target ... --ports ... --worker ... --workers-json ... --output json|table` for dry-run cluster planning.
✅ Cluster planning output is JSON serializable and includes job, workers, assignments, summary, warnings, `raw_payload_stored: false`, and `automatic_changes: false`.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/distributed_cluster_scanning.md` and package-data inclusion.
✅ Added focused cluster, CLI, and packaging tests.
✅ Focused Phase 39 verification passes: `60 passed`.
✅ Runtime CLI smoke for `portmap cluster plan --target 127.0.0.1 --ports 80,443 --worker worker-a --worker worker-b --output json` produces a dry-run planned job without scanning.
✅ Full-suite verification after Phase 39 passes: `354 passed, 1 skipped`.

**Phase 40 — Enterprise Cloud Orchestration Platform (Complete Baseline)**
✅ Added `saas.tenancy` for tenant records, workspace configuration validation, tenant isolation helpers, and local workspace config persistence.
✅ Added `saas.orgs` for organization metadata, team associations, user grouping, and RBAC role inheritance through the existing local RBAC layer.
✅ Added `saas.licensing` for license metadata, subscription tier labels, usage counters, quota tracking, feature gating, and local usage summaries.
✅ Added `saas.cloud_sync` for optional encrypted sync manifests with nonce-based payload protection, SHA-256 digest checks, HMAC integrity validation, offline-compatible export/import, and conflict handling.
✅ Added `core_engine.advisory.workflow` for administrator-facing recommendation objects, review states, approval transitions, and enterprise audit event generation.
✅ Added CLI commands `portmap workspace`, `portmap license`, `portmap cloud-sync`, and `portmap advisory` for local Phase 40 workflows.
✅ Organization, team, license, sync, and advisory outputs are JSON serializable, auditable, and local/offline friendly.
✅ Advisory workflows require administrator-defined RBAC permissions for approval transitions and do not execute remediation.
✅ Cloud sync remains optional and performs no network requests.
✅ This phase follows the global PortMap-AI safety guarantees.
✅ Added `docs/enterprise_cloud_orchestration.md` and package-data inclusion.
✅ Added focused enterprise-cloud, CLI, and packaging tests.
✅ Focused Phase 40 verification passes: `65 passed`.
✅ Runtime CLI smokes for workspace, license, cloud-sync, and advisory commands pass locally.
✅ Full-suite verification after Phase 40 passes: `366 passed, 1 skipped`.

**Phase 41 — Local Visibility and Operator Tooling (Complete Baseline)**
✅ Added `core_engine.visibility` for offline local visibility reports from existing asset, service, and flow evidence.
✅ Visibility reports include summaries, categorized asset/service/flow findings, policy details, dry-run response workflow drafts, and explicit `automatic_changes: false`, `administrator_controlled: true`, and `raw_payload_stored: false` fields.
✅ Added `portmap visibility --assets-json ... --services-json ... --flows-json ... --policy-json ... --output json|table`.
✅ Expanded service fingerprint coverage for MySQL/MariaDB-compatible banners, PostgreSQL, Redis, MongoDB, Elasticsearch, MSSQL, Oracle, VNC, WinRM, POP3, and IMAP.
✅ Visibility workflows remain opt-in and consume already-collected evidence; they do not run scans, execute remediation, transmit data, or store raw payload bytes.
✅ This phase follows the global PortMap-AI safety guarantees and uses placeholders in public docs.
✅ Added `docs/local_visibility_operator_tooling.md` and package-data inclusion.
✅ Added focused visibility, service-detection, CLI, and packaging tests.

---

## 🧠 Technical Highlights

| Component | Function | Current Status |
|------------|-----------|----------------|
| `ai_agent/scoring.py` | Computes anomaly risk score from scan results | ✅ Working |
| `core_engine/worker_node.py` | Sends scan + AI results to master | ✅ Config-driven + structured logging |
| `core_engine/master_node.py` | Aggregates worker reports | ✅ Logging + remediation dispatch |
| `modules/scanner.py` | Performs network port scan | ✅ Basic placeholder functional |
| `core_engine/config_loader.py` | Shared node/global config loader | ✅ New |
| `ai_agent/remediation.py` | Remediation decision engine | ✅ Prompt/Silent modes |
| `logs/` | Event and anomaly tracking | ✅ Writing to ~/.portmap-ai/logs |
| `core_engine/orchestrator.py` | SaaS orchestration API | ✅ Responds to register/heartbeat/commands |
| `core_engine/log_exporter.py` | Audit archive utility | ✅ Packages rotated logs + state |
| `core_engine/agent_service.py` | Daemon agent loop | ✅ Pulls orchestrator commands, executes remediation |
| `core_engine/enrollment.py` | Future SaaS enrollment schemas | ✅ Local-only validation/redaction helpers |
| `core_engine/visibility.py` | Offline local visibility summaries, categorized findings, and review drafts | ✅ Working |

---

## 🔐 Security Roadmap

| Stage | Focus Area | Description |
|--------|-------------|--------------|
| Phase 0 | Reproducible Setup | Dependencies, tests, stack, and docs are reproducible |
| Phase 1 | Unified CLI | Local operations available through `portmap` |
| Phase 2 | Packaged Install | Editable and wheel installs expose console scripts |
| Phase 3 | Configuration Hardening | Config validation fails clearly before runtime startup |
| Phase 4 | Platform Abstraction | Host/process/network inspection centralized for cross-platform support |
| Phase 5 | Stack Stability | Restart, disconnect, shutdown, and port-conflict resilience |
| Phase 6-41 | Safety, Deployment, Release, UDP, IPv6, Inventory, Services, OS, Async Scan, Capture, Dissection, DPI, TLS, Flows, Behavior, Payload AI, Correlation, Recommendations, CVE, Vulnerability Correlation, Enterprise Security, Alerting/SIEM, Visualization/GUI, Cluster Scanning, Enterprise Cloud Orchestration, Local Visibility | Logging, remediation safety, TUI, Docker, Raspberry Pi, packaging, auth, SaaS prep, docs, RC, UDP scanner, dual-stack scanner, network asset inventory, service enumeration, OS fingerprinting, high-speed async scanning, packet capture core, protocol dissectors, deep packet inspection, TLS intelligence, traffic flow reconstruction, AI behavioral learning, AI payload classification, threat correlation, AI recommendations, CVE intelligence, vulnerability correlation, enterprise security primitives, alerting and SIEM integrations, visualization and GUI platform, distributed cluster scan planning, organization/workspace management, licensing/usage metrics, optional cloud sync manifests, administrator advisory workflows, and local visibility summaries |

---

## 🧰 Environment & Execution

**Deployment Options (important product guidance):**

PortMap-AI has three intended run modes:

1. **Local Install (recommended default)**
   Use Python packaging and the `portmap` CLI. This is the primary path for most users because it avoids Docker setup, image builds, named volumes, and container networking.

   Current developer command:
   ```bash
   pip install -e .
   portmap setup
   portmap doctor
   portmap stack --verbose
   portmap tui
   ```

   Future packaged-user target:
   ```bash
   pipx install portmap-ai
   portmap setup
   portmap doctor
   portmap stack
   portmap tui
   ```

2. **Raspberry Pi / Always-On Agent**
   Use native service management for 24/7 monitoring. Phase 12 provides `systemd` templates for Raspberry Pi OS and general systemd-based Linux hosts, with logs and settings under `~/.portmap-ai`. Raspberry Pi is one supported ARM/Linux target, not the only deployment target.

3. **Docker Compose (optional advanced mode)**
   Use `docker compose up --build` only when the operator specifically wants containers. Do not auto-install Docker for users; Docker installation is a system-level choice with platform-specific permissions and security implications.

Detailed deployment guidance lives in `docs/deployment_options.md` and `docs/raspberry_pi_deployment.md`.

**Local Run Example (scripts):**
```bash
# Terminal 1 (Orchestrator HTTP API)
scripts/run_orchestrator.sh

# Terminal 2 (Master)
scripts/run_master.sh

# Terminal 3 (Worker)
scripts/run_worker.sh --continuous --log-level INFO

# Audit bundle export (any terminal)
python cli/logs.py --output-dir ./artifacts

# Operator dashboard (Textual TUI)
PORTMAP_ORCHESTRATOR_URL=http://127.0.0.1:9100 \
scripts/run_dashboard.sh
```

**One-Command Stack Launcher (optional):**
```bash
scripts/run_stack.py  # starts orchestrator, master, and worker together
```
This launches orchestrator, master, worker (adding `--continuous --log-level INFO`), and auto-opens the dashboard after a short delay. Use `--no-dashboard` to skip the TUI, `--dashboard-delay` to tweak the wait, `--verbose` to stream process output, and `--*_config`/`--worker-args` to override defaults.

**Comprehensive Quick Start:**
1. **Clone & Enter Repo** – `git clone <repo-url>` then `cd portmap-ai`.
2. **Bootstrap Python Env** –
   - macOS/Linux: `scripts/setup_environment.sh && source portmap-ai-env/bin/activate`
   - Windows (PowerShell): `scripts\setup_environment.bat` then `portmap-ai-env\Scripts\activate.ps1`
3. **Run Core Services (each in own terminal, venv active):**
   - Orchestrator → `scripts/run_orchestrator.sh`
   - Master → `scripts/run_master.sh`
   - Worker → `scripts/run_worker.sh --continuous --log-level INFO`
4. **Launch Dashboard:** set `PORTMAP_ORCHESTRATOR_URL`/`PORTMAP_ORCHESTRATOR_TOKEN` if needed, then `scripts/run_dashboard.sh`.
5. **Inject Manual Commands:** use dashboard buttons or call `curl -X POST .../commands` (see docs for example payload).
6. **Export Logs/Audit Trail:** `python cli/logs.py --output-dir ./artifacts`.
7. **Run Tests (optional):** `python -m pytest` (GUI tests auto-skip if `textual` absent).
8. **Customize Configs:** copy JSON from `tests/node_configs/`, adjust IPs/tokens/ports, pass as first argument to run scripts.
9. **Operationalize:** wrap scripts in systemd/Windows services for auto-start and point dashboard env vars to remote orchestrator endpoints for SaaS deployments.

**Developer Setup:**
```bash
python3 -m venv portmap-ai-env
source portmap-ai-env/bin/activate
pip install -r requirements-dev.txt
```

`requirements.txt` contains runtime dependencies used by the current scanner, scoring, dashboard, firewall, and API modules. `requirements-dev.txt` includes runtime requirements plus test tooling.

---

## 🧾 Developer Notes

- Worker/master communication tested on same system (loopback).
- All imports patched with `sys.path` fix for development portability.
- File hierarchy is confirmed and synced to root `portmap-ai/`.
- Background agent now available via `portmap_agent.py` for continuous runs.
- Remediation actions flow from master → orchestrator → worker; firewall enforcement now uses pluggable drivers (`noop`, `linux_iptables` dry-run by default).
- Global defaults live under `~/.portmap-ai/data/settings.json`; CLI config overrides continue to work per-node.
- Local pytest suite (`python -m pytest`) covers config merging, remediation dispatcher behaviour, orchestrator state lifecycles, logging/audit utilities, scoring, scanner behavior, run-stack helpers, GUI helpers, and real-time agent command handling.
- Orchestrator persistence stored at `~/.portmap-ai/data/orchestrator_state.json`; secret-like node metadata is scrubbed before persistence. Token auth defaults to development values for local testing and should be replaced with `${secret:PORTMAP_ORCHESTRATOR_TOKEN}` for shared or remote deployments.
- Orchestrator heartbeat returns command batches (`scan_now`, `set_interval`, `set_autolearn`, `reload_config`, `apply_remediation`) processed by the background agent.
- Remediation decisions also appended to `~/.portmap-ai/logs/remediation_events.jsonl`, powering the dashboard history view.
- Dashboard expects `PORTMAP_ORCHESTRATOR_URL`/`PORTMAP_ORCHESTRATOR_TOKEN` env vars; falls back to `http://127.0.0.1:9100` if unset.
- Dashboard pre-loads defaults (URL `http://127.0.0.1:9100`, token `test-token`) from settings/env and offers a **Detect Orchestrator** button to rescan common endpoints.
- Docker Compose and systemd deployments should use generated or operator-provided tokens, not the local development token.
- Quick-start automation available in `docs/quick_start.md`; `/scripts` directory wraps module launches for macOS/Linux/Windows and auto-sets `PYTHONPATH`.
- Structured configuration profiles, validation, and env placeholders documented in `docs/configuration.md`; worker supports optional validated config hot-reload.
- Integration smoke tests and `/metrics` endpoint: run `scripts/run_integration_tests.sh` and query `/metrics` for register/heartbeat counters.
- Documentation additions: `docs/beginner_guide.md` (firewall primer), `docs/api_reference.md` (HTTP endpoints & config keys), `docs/CLI_REFERENCE.md`, `docs/DEPLOYMENT.md`, `docs/PHASE_HISTORY.md`, `docs/ROADMAP.md`, `docs/SECURITY_MODEL.md`, `docs/real_device_validation.md`, `docs/alerting_siem_integrations.md`, `docs/distributed_cluster_scanning.md`, `docs/enterprise_cloud_orchestration.md`, `docs/platform_abstraction.md` (cross-platform runtime boundary), `docs/stack_stability.md`, `docs/logging_audit.md`, `docs/remediation_safety.md`, `docs/scanner_risk_engine.md`, `docs/ai_layer.md`, `docs/ai_behavioral_learning.md`, `docs/ai_payload_classification.md`, `docs/ai_recommendation_engine.md`, `docs/cve_intelligence.md`, `docs/enterprise_security.md`, `docs/vulnerability_correlation.md`, `docs/threat_correlation.md`, `docs/tui_dashboard.md`, `docs/visualization_gui_platform.md`, `docs/deployment_options.md`, `docs/deep_packet_inspection.md`, `docs/docker_deployment.md`, `docs/raspberry_pi_deployment.md`, `docs/packaging.md`, `docs/network_control_layer.md`, `docs/network_asset_inventory.md`, `docs/service_enumeration.md`, `docs/os_fingerprinting.md`, `docs/high_speed_scan_engine.md`, `docs/packet_capture.md`, `docs/protocol_dissectors.md`, `docs/tls_intelligence.md`, `docs/traffic_flow_reconstruction.md`, `docs/security_authentication.md`, `docs/architecture.md`, `docs/saas_architecture.md`, `docs/release_candidate.md`, `docs/udp_scanning.md`, and `docs/ipv6_dual_stack.md`.

---

## 🧱 Current Build Anchor (Codex sync reference)

**Focus file:** `core_engine/worker_node.py`
**Key active imports:**
```python
from ai_agent.scoring import get_score
from core_engine.modules.scanner import basic_scan
```
**Behavior:** Sends JSON scan payloads to master node, validates startup/reload config, re-registers after orchestrator state loss, uses shared platform helpers for local address resolution, and scores connections through the replaceable AI provider interface.
**Next:** Phase 41 local visibility and operator tooling is complete. Do not commit until the user asks.

---

### ✅ Handoff Purpose
This summary provides **Codex** or any development assistant with a structural and contextual snapshot of PortMap-AI as of the **Phase 41 local-visibility-and-operator-tooling baseline**.
