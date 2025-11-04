# PortMap-AI Launch Scripts

Cross-platform helpers that wrap the core `python -m ...` entrypoints. All scripts assume you run them from the repository root (or any directory as long as the repo is intact).

## Environment Setup

```bash
scripts/setup_environment.sh        # macOS / Linux
scripts\setup_environment.bat       # Windows
```
This creates `portmap-ai-env/`, installs dependencies, and prints the activation command.

## Runtime Helpers

| Component    | macOS/Linux                       | Windows                         |
|--------------|-----------------------------------|---------------------------------|
| Orchestrator | `scripts/run_orchestrator.sh`     | `scripts\run_orchestrator.bat` |
| Master       | `scripts/run_master.sh`           | `scripts\run_master.bat`       |
| Worker       | `scripts/run_worker.sh`           | `scripts\run_worker.bat`       |
| Dashboard    | `scripts/run_dashboard.sh`        | `scripts\run_dashboard.bat`    |

Each script accepts an optional first argument pointing to a custom JSON config. If omitted, it falls back to the sample configs under `tests/node_configs/`.

Example (macOS/Linux):
```bash
scripts/run_orchestrator.sh
scripts/run_master.sh
scripts/run_worker.sh
PORTMAP_ORCHESTRATOR_TOKEN=test-token scripts/run_dashboard.sh
```

Example (Windows PowerShell):
```powershell
scripts\run_orchestrator.bat
scripts\run_master.bat
scripts\run_worker.bat
$env:PORTMAP_ORCHESTRATOR_TOKEN = 'test-token'
scripts\run_dashboard.bat
```

The scripts automatically set `PYTHONPATH` so the modules resolve correctly.
