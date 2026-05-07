# Packaging

Phase 13 makes the local install path the primary product path. Docker remains optional, and Raspberry Pi remains one Linux/ARM deployment target rather than a separate product.

## Supported Baseline

Current packaging baseline:

- macOS: supported for local development, CLI, stack, and TUI.
- Linux: supported for local CLI, stack, TUI, and systemd service mode.
- Linux/ARM/Raspberry Pi OS: supported through the same Python package, low-resource profile, and systemd templates.
- Windows: experimental. Batch scripts exist, but native service packaging is future work.

PortMap-AI should not claim full support for every OS until each platform has install, run, service, and uninstall validation.

## Recommended Install

Current local install:

```bash
python3 -m venv portmap-ai-env
source portmap-ai-env/bin/activate
pip install -e .
portmap setup
portmap doctor
portmap stack --verbose
```

Future user-facing install target:

```bash
pipx install portmap-ai
portmap setup
portmap start
portmap tui
```

## Runtime Initialization

`portmap setup` creates the local runtime layout:

- `~/.portmap-ai`
- `~/.portmap-ai/data`
- `~/.portmap-ai/logs`
- default settings file
- export directory

It does not install Docker, system services, firewall rules, or privileged components.

## Diagnostics

`portmap doctor` reports:

- Python version.
- Current OS/architecture support level.
- Runtime paths.
- Default packaged config availability.
- Installed console script availability.
- Native service manager guidance.

Use JSON output for automation:

```bash
portmap doctor --output json
```

## Build Artifacts

Build a wheel:

```bash
python -m pip wheel --no-deps -w dist .
```

Build the local source bundle:

```bash
scripts/package_local.sh
```

The package includes:

- Python packages under `ai_agent`, `cli`, `core_engine`, and `gui`.
- Console scripts declared in `pyproject.toml`.
- Default node configs.
- Deployment docs.
- Profile configs.
- systemd templates.

## Non-Developer UX Goal

The user should not need to know the repository layout. Phase 13 should keep moving toward:

- one setup command;
- one start command;
- one status/doctor command;
- clear config/log/export paths;
- optional Docker;
- optional native service installation;
- no Pi-only or Docker-only assumptions.
