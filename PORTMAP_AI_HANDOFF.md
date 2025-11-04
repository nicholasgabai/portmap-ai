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
- Provide CLI and GUI modes (GUI planned for later phase).  

---

## 🧩 Architecture Summary  

```
portmap-ai/
│
├── ai_agent/                   # AI logic and decision layer
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
│   ├── main_cli.py             # Entry point for CLI execution
│   ├── commands.py             # CLI command definitions
│   └── utils.py
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
├── sandbox_sim/                # For testing simulation of multiple nodes
│   ├── test_master.py
│   ├── test_worker.py
│   └── local_configs/
│
├── portmap_agent.py            # CLI wrapper around background agent service
├── settings.json               # Central configuration (IP, ports, modes, etc.)
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Developer/testing dependencies (pytest, textual, …)
├── README.md                   # Project overview and usage guide
└── setup.py                    # Installable package setup
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
2. Uses rules + (future) ML heuristics to produce confidence values.
3. Returns float score in `[0, 1]` representing risk level.

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

## 📦 Current Development Phase (as of handoff)

**Phase 1 — Multi-Node Infrastructure Build (Active)**  
✅ Master/worker sockets stable with config-driven setup  
✅ Structured logging & remediation toggle pipeline in place  
✅ Background agent thread + CLI wrapper online  
✅ Phase 2 logging/audit trail completed (rotation + export bundles)  
✅ Phase 3 real-time agent wired into orchestrator heartbeat/command flow  
🧩 Testing local multi-node communication using multiple terminals  
🔭 Goals now shift toward orchestration + remediation hardening  

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

---

## 🔐 Security Roadmap  

| Stage | Focus Area | Description |
|--------|-------------|--------------|
| Phase 1 | Core Infrastructure | Establish master/worker comms |
| Phase 2 | Logging & Audit Trail | Persistent event logging |
| Phase 3 | Real-Time Agent | Background monitoring toggle |
| Phase 4 | Remediation Logic | Prompt/Silent AI responses |
| Phase 5 | GUI Layer | Local/remote control dashboard |
| Phase 6 | SaaS Cloud Sync | Multi-client management, licensing, analytics |

---

## 🧰 Environment & Execution  

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
PORTMAP_ORCHESTRATOR_TOKEN=test-token \
scripts/run_dashboard.sh
```

**One-Command Stack Launcher (optional):**  
```bash
scripts/run_stack.py  # starts orchestrator, master, and worker together
```
Pass `--orchestrator-config`, `--master-config`, or `--worker-config` to override defaults. Extra worker options can follow `--worker-args`.

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
pip install -r requirements-dev.txt  # installs pytest for local checks
```

**Python Requirements:**  
```txt
socket
json
time
logging
threading
```

(Advanced dependencies will be added as ML/GUI components develop.)

---

## 🧾 Developer Notes  

- Worker/master communication tested on same system (loopback).  
- All imports patched with `sys.path` fix for development portability.  
- File hierarchy is confirmed and synced to root `portmap-ai/`.  
- Background agent now available via `portmap_agent.py` for continuous runs.  
- Remediation actions flow from master → orchestrator → worker; `firewall_hooks.execute_firewall_action` remains a stub for platform-specific enforcement.  
- Global defaults live under `~/.portmap-ai/data/settings.json`; CLI config overrides continue to work per-node.  
- Local pytest suite (`requirements-dev.txt`) covers config merging, remediation dispatcher behaviour, orchestrator state lifecycles, logging/audit utilities, and real-time agent command handling.  
- Orchestrator persistence stored at `~/.portmap-ai/data/orchestrator_state.json`; token auth defaults to `portmap-dev-token` (override in config).  
- Orchestrator heartbeat returns command batches (`scan_now`, `set_interval`, `set_autolearn`, `reload_config`, `apply_remediation`) processed by the background agent.  
- Remediation decisions also appended to `~/.portmap-ai/logs/remediation_events.jsonl`, powering the dashboard history view.  
- Dashboard expects `PORTMAP_ORCHESTRATOR_URL`/`PORTMAP_ORCHESTRATOR_TOKEN` env vars; falls back to `http://127.0.0.1:9100` if unset.  
- Dashboard pre-loads defaults (URL `http://127.0.0.1:9100`, token `test-token`) from settings/env and offers a **Detect Orchestrator** button to rescan common endpoints.  
- Quick-start automation available in `docs/quick_start.md`; `/scripts` directory wraps module launches for macOS/Linux/Windows and auto-sets `PYTHONPATH`.  

---

## 🧱 Current Build Anchor (Codex sync reference)

**Focus file:** `core_engine/worker_node.py`  
**Key active imports:**
```python
from ai_agent.scoring import get_score
from core_engine.modules.scanner import basic_scan
```
**Behavior:** Sends JSON scan payloads to master node.  
**Next:** Extend remediation hooks with real firewall integrations and begin GUI/operator surface planning.

---

### ✅ Handoff Purpose
This summary provides **Codex** or any development assistant with a full structural and contextual snapshot of PortMap-AI as of **Phase 4 (Remediation Logic)** — ready for continuation into **GUI layer**, **SaaS orchestration**, and production-grade enforcement work.  
