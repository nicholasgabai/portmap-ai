# PortMap-AI Architecture

PortMap-AI is a local-first network security stack. It can run as a single local tool, as a local distributed orchestrator/master/worker stack, or as an always-on Linux service. Docker is optional.

## Runtime Components

### CLI

`cli.main` exposes the installed `portmap` command. It wraps the existing scanner, stack launcher, TUI, API status checks, configuration validation, log export, runtime setup, diagnostics, and network posture commands.

### Orchestrator

`core_engine.orchestrator` provides the HTTP API used by local agents and the dashboard. It handles registration, heartbeat, command queues, health, node inventory, metrics, and persisted state. Authentication is bearer-token based and implemented through `core_engine.security`.

### Master Node

`core_engine.master_node` receives worker scan payloads over sockets, writes structured telemetry, evaluates remediation decisions, and queues remediation commands through the orchestrator when policy allows.

### Worker Node

`core_engine.worker_node` runs scans, scores findings, sends results to the master, registers with the orchestrator, sends heartbeats, and executes supported orchestrator commands.

### Scanner and Risk Engine

`core_engine.modules.scanner` uses the platform abstraction layer to inspect connections. `ai_agent.scoring` combines deterministic heuristics, known risky ports, service hints, optional local ML scoring, and provider validation from `ai_agent.interface`.

### TUI

`gui.app` provides the Textual operator dashboard. It displays node health, metrics, scan samples, remediation events, command outcomes, expected services, and log tails.

## Data and Logs

Runtime state defaults to `~/.portmap-ai`:

- `data/settings.json` for local settings;
- `data/orchestrator_state.json` for orchestrator state;
- `logs/*.jsonl` for structured audit and telemetry records;
- `exports/` for log archive output.

Package defaults and examples remain in the repository and installed package data.

## Platform Boundary

`core_engine.platform_utils` centralizes OS, process, port, subprocess, and network-interface helpers. Core modules should use this layer instead of hardcoding platform-specific behavior. macOS and Linux are current targets, Raspberry Pi OS is supported as Linux/ARM, and Windows remains a future compatibility target.

## Security Boundary

PortMap-AI uses these local security controls:

- bearer-token checks for orchestrator APIs;
- config validation before runtime startup;
- environment-backed secret interpolation;
- secret scrubbing before state persistence;
- remediation safety gates with dry-run defaults;
- structured audit events for commands and remediation decisions.

## Deployment Modes

Recommended order:

1. Local install: `pip install -e .`, `portmap setup`, `portmap stack`, `portmap tui`.
2. Always-on Linux/Raspberry Pi service: user-scoped `systemd` templates.
3. Docker Compose: optional advanced deployment for operators who already want containers.
4. Future SaaS: documented in `docs/saas_architecture.md`.
