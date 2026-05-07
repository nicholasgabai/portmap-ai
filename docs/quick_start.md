# PortMap-AI Quick Start Guide

This guide walks you from cloning the repository to running the orchestrator, master, worker, and Textual dashboard on macOS/Linux or Windows.

PortMap-AI does not require Docker. The recommended path for most users is the local install/CLI path in this guide. Docker Compose is an optional advanced deployment mode for users who already want containers; see `docs/deployment_options.md` for the full deployment split.

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
pip install -e .
```

### Windows (PowerShell)
```powershell
scripts\setup_environment.bat
portmap-ai-env\Scripts\activate.ps1
pip install -e .
```

> The setup script installs runtime dependencies from `requirements.txt` plus developer/test dependencies from `requirements-dev.txt`.
> `pip install -e .` installs the package in editable mode and exposes console commands such as `portmap`, `portmap-orchestrator`, `portmap-master`, `portmap-worker`, and `portmap-dashboard`.

The standard development environment is the repo-local `portmap-ai-env` directory created by the setup script. If an older sibling environment exists at `../portmap-ai-env`, do not rely on it for reproducibility; rebuild the repo-local environment with the setup script.

Initialize local runtime paths and check package readiness:

```bash
portmap setup
portmap doctor
```

## 3. Launch the services

### Option A: single command (recommended for local testing)
```bash
scripts/run_stack.py
```
This spawns orchestrator, master, and worker concurrently (worker runs with `--continuous --log-level INFO`) and launches the dashboard automatically after a short delay. Use `Ctrl+C` to stop them, pass `--no-dashboard` to skip the TUI, tweak the delay with `--dashboard-delay`, use `--verbose` to stream process output, and pass `--*_config`/`--worker-args` to override defaults.

The stack launcher validates configs and checks port conflicts before startup. Core services are supervised with bounded restarts by default; use `--restart-limit N` to change the limit or `--no-restart` to disable restart supervision.

The unified CLI wraps the same launcher:

```bash
python -m cli.main stack --verbose
python -m cli.main stack --no-dashboard
portmap stack --verbose
```

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
scripts/run_worker.sh --continuous --log-level INFO --watch-config
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

The Textual TUI shows node status, orchestrator health/metrics, scan results with risk signals, remediation history, command outcomes, expected-service allowlists, and buttons to trigger commands (`scan_now`, `toggle autolearn`).

Equivalent unified CLI command:

```bash
python -m cli.main tui
portmap tui
```

Quick API checks while the orchestrator is running:

```bash
python -m cli.main health
python -m cli.main nodes
python -m cli.main metrics
portmap health
portmap nodes
portmap metrics
```

Assess local gateway and exposed-service posture without making changes:

```bash
portmap network
portmap network --output json
```

Validate configs before launching:

```bash
portmap config validate core_engine/default_configs/orchestrator.json
portmap config validate core_engine/default_configs/master1.json core_engine/default_configs/worker_orchestrated.json
portmap config validate core_engine/default_configs/worker_orchestrated.json --role worker
```

The service entrypoints and `portmap stack` run the same validation after defaults, profiles, environment substitutions, and shared settings are merged. Invalid configs fail before listeners start.

## 5. Run tests (optional)

```bash
python -m pytest
```

> Certain agent/orchestrator integration tests expect the orchestrator to be reachable; run them after the orchestrator is up or skip with `-k` filters.

For deeper coverage (spawns subprocesses), run the integration suite:

```bash
scripts/run_integration_tests.sh
```

## 6. Export logs / audit trail

```bash
python cli/logs.py
```

This creates a dated zip including rotated logs and state files in `~/Downloads/portmap-ai-exports` by default. The dashboard's **Export Logs** button uses the same destination and shows it in the status/help text.

To override the destination for one export:

```bash
python cli/logs.py --output-dir ./artifacts
python -m cli.main logs --output-dir ./artifacts
portmap logs --output-dir ./artifacts
```

To inspect structured audit JSONL events without creating an archive:

```bash
portmap logs --filter-node worker-001 --tail 20
portmap logs --filter-event-type remediation_decision
```

To change the default for dashboard and CLI exports, set `export_dir` in `~/.portmap-ai/data/settings.json`:

```json
{
  "export_dir": "~/Downloads/portmap-ai-exports"
}
```

## 7. Next steps

- Use the dashboard **Expected Services** panel to allowlist normal local services (for example a dev MySQL server on port 3306). The allowlist is saved under `expected_services` in `~/.portmap-ai/data/settings.json` and lowers noise without enabling firewall changes.
- Review `score_factors` and `risk_explanation` in scan/remediation output to understand why a connection scored high.
- To understand deployment choices, read `docs/deployment_options.md`. Local install is the default user path; Docker Compose is optional.
- For Raspberry Pi or other always-on Linux hosts, read `docs/raspberry_pi_deployment.md`. It uses native `systemd` services and keeps the core app multi-platform.
- To run the distributed stack in containers, use `docker compose up --build`; see `docs/docker_deployment.md`.
- To change configs, copy templates from `tests/node_configs/` and pass them to the run scripts, e.g. `scripts/run_worker.sh my_worker.json`.
- Enable real firewall enforcement only after dry-run testing. Active destructive actions require both `"firewall": {"plugin": "linux_iptables", "options": {"dry_run": false}}` and `"remediation_safety": {"active_enforcement_enabled": true, "require_confirmation": true}`. Unconfirmed destructive commands are forced back to dry-run.
- To package for deployment, wrap the run scripts in system services (systemd, Windows Services, launchd) and ensure `PYTHONPATH`/env variables are set.
- To verify a non-editable local wheel, run `python -m pip wheel --no-deps -w /tmp/portmap-ai-wheel .` and install the generated wheel in a clean environment.
- For cloud-hosted orchestrators, point `PORTMAP_ORCHESTRATOR_URL` to your SaaS endpoint and set tokens per tenant.

Enjoy securing your network with PortMap-AI!
