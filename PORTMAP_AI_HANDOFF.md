# 🧠 PortMap-AI — Project Handoff Summary
### AI-Driven Network Security & Port Mapping SaaS

---

## 🔍 Overview
**PortMap-AI** is an intelligent, modular **network security and visualization SaaS** that performs **AI-enhanced port scanning, risk scoring, and autonomous remediation** across multi-node environments.
It supports **master/worker topology**, distributed scanning, and eventually cloud-based AI decision layers.

**Core Goals:**
- Map network ports and detect anomalies in real time.
- Apply adaptive AI logic to classify and remediate suspicious activity.
- Support local, multi-node, and SaaS-tier deployments.
- Provide CLI and operator UI modes. The current UI is a Textual terminal dashboard, not a browser UI.

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
| Phase 6-18 | Safety, Deployment, Release | Logging, remediation safety, TUI, Docker, Raspberry Pi, packaging, auth, SaaS prep, docs, RC |

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
- Documentation additions: `docs/beginner_guide.md` (firewall primer), `docs/api_reference.md` (HTTP endpoints & config keys), `docs/platform_abstraction.md` (cross-platform runtime boundary), `docs/stack_stability.md`, `docs/logging_audit.md`, `docs/remediation_safety.md`, `docs/scanner_risk_engine.md`, `docs/ai_layer.md`, `docs/tui_dashboard.md`, `docs/deployment_options.md`, `docs/docker_deployment.md`, `docs/raspberry_pi_deployment.md`, `docs/packaging.md`, `docs/network_control_layer.md`, `docs/security_authentication.md`, `docs/architecture.md`, `docs/saas_architecture.md`, and `docs/release_candidate.md`.

---

## 🧱 Current Build Anchor (Codex sync reference)

**Focus file:** `core_engine/worker_node.py`
**Key active imports:**
```python
from ai_agent.scoring import get_score
from core_engine.modules.scanner import basic_scan
```
**Behavior:** Sends JSON scan payloads to master node, validates startup/reload config, re-registers after orchestrator state loss, uses shared platform helpers for local address resolution, and scores connections through the replaceable AI provider interface.
**Next:** Review `git status`, commit the release-candidate changes, perform optional real-device runtime smoke checks for Linux/Raspberry Pi/Docker Compose, then tag 0.1.0.

---

### ✅ Handoff Purpose
This summary provides **Codex** or any development assistant with a structural and contextual snapshot of PortMap-AI as of the **Phase 18 release-candidate baseline plus GitHub-readiness cleanup** — ready for review, commit, optional real-device smoke checks, and 0.1.0 tagging.
