# PortMap-AI Quick Start Guide

This guide walks you from cloning the repository to running the orchestrator, master, worker, and Textual dashboard on macOS/Linux or Windows.

## 1. Clone the repository

```bash
git clone https://github.com/<your-org>/portmap-ai.git
cd portmap-ai
```

## 2. Create the virtual environment

### macOS / Linux
```bash
scripts/setup_environment.sh
source portmap-ai-env/bin/activate
```

### Windows (PowerShell)
```powershell
scripts\setup_environment.bat
portmap-ai-env\Scripts\activate.ps1
```

> The setup script installs all developer dependencies (including `textual` for the dashboard and `pytest` for tests). If you prefer runtime-only deps, install from `requirements.txt` (once created) and optionally add `textual`.

## 3. Launch the services

### Option A: single command (recommended for local testing)
```bash
scripts/run_stack.py
```
This spawns orchestrator, master, and worker concurrently. Use `Ctrl+C` to stop them, or pass `--*_config` flags to point at alternate JSON configs. Extra worker parameters can follow `--worker-args`.

### Option B: manual control (one terminal each)

**Terminal 1 — Orchestrator**
```bash
scripts/run_orchestrator.sh  # or .bat on Windows
```

**Terminal 2 — Master**
```bash
scripts/run_master.sh
```

**Terminal 3 — Worker**
```bash
scripts/run_worker.sh --continuous --log-level INFO
```

Either approach establishes the master/worker heartbeat and keeps the orchestrator receiving node telemetry.

## 4. View the dashboard

In a fourth terminal:

```bash
export PORTMAP_ORCHESTRATOR_URL="http://127.0.0.1:9100"
export PORTMAP_ORCHESTRATOR_TOKEN="test-token"  # matches orchestrator config
scripts/run_dashboard.sh
```

On Windows (PowerShell):
```powershell
$env:PORTMAP_ORCHESTRATOR_URL = 'http://127.0.0.1:9100'
$env:PORTMAP_ORCHESTRATOR_TOKEN = 'test-token'
scripts\run_dashboard.bat
```

The Textual TUI shows node status, remediation history, and buttons to trigger commands (`scan_now`, `toggle autolearn`).

## 5. Run tests (optional)

```bash
python -m pytest
```

> Certain agent/orchestrator integration tests expect the orchestrator to be reachable; run them after the orchestrator is up or skip with `-k` filters.

## 6. Export logs / audit trail

```bash
python cli/logs.py --output-dir ./artifacts
```

This creates a dated zip including rotated logs and state files in the `artifacts/` folder.

## 7. Next steps

- To change configs, copy templates from `tests/node_configs/` and pass them to the run scripts, e.g. `scripts/run_worker.sh my_worker.json`.
- To package for deployment, wrap the run scripts in system services (systemd, Windows Services, launchd) and ensure `PYTHONPATH`/env variables are set.
- For cloud-hosted orchestrators, point `PORTMAP_ORCHESTRATOR_URL` to your SaaS endpoint and set tokens per tenant.

Enjoy securing your network with PortMap-AI!
