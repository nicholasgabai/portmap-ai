# PortMap-AI Architecture

PortMap-AI is a local-first network observability platform that can run as a single CLI tool, a local orchestrator/master/worker stack, an always-on Linux service, or an optional Docker Compose deployment. The main handoff document remains the source of truth for phase-by-phase implementation status.

## Core Boundaries

- `cli/` exposes the installed `portmap` command and wraps scanner, stack, dashboard, validation, export, and analysis workflows.
- `core_engine/` contains orchestration, worker/master services, runtime setup, platform helpers, telemetry modules, cluster planning, integrations, advisory workflow helpers, and vulnerability intelligence.
- `ai_agent/` contains scoring, behavior baselines, payload classification, correlation, and recommendation helpers.
- `gui/` contains the Textual terminal dashboard and reusable visualization helpers.
- `saas/` contains local/offline organization, workspace, licensing, and sync-manifest primitives.
- `docs/` contains operator and developer documentation.

## Runtime Flow

The orchestrator exposes the local HTTP control API. Worker nodes register, send heartbeats, receive queued commands, run local scans when configured, and send payloads to the master. The master records telemetry, applies scoring and decision logic, and queues administrator-controlled remediation workflow commands through the orchestrator when enabled by policy.

## Data Model

Runtime data defaults to `~/.portmap-ai`:

- `data/settings.json` for local settings.
- `data/orchestrator_state.json` for orchestrator state.
- `logs/*.jsonl` for audit, command, remediation, scan, and flow telemetry.
- `exports/` for generated log bundles.

Packaged defaults and examples remain in the repository and installed package data.

## Platform Boundary

`core_engine.platform_utils` centralizes OS, process, socket, subprocess, and network-interface helpers. Platform-sensitive modules should use this layer rather than hardcoding OS behavior. Linux/macOS are the current local validation targets, Raspberry Pi OS is treated as Linux/ARM, and Windows runtime support remains pending external validation.

## Safety Boundary

PortMap-AI follows the global safety guarantees in `PORTMAP_AI_HANDOFF.md`. It supports authorized observability and diagnostics, keeps remediation administrator-controlled, and avoids autonomous offensive operations.

## Related Docs

- `docs/DEPLOYMENT.md`
- `docs/SECURITY_MODEL.md`
- `docs/CLI_REFERENCE.md`
- `docs/PHASE_HISTORY.md`
- `docs/real_device_validation.md`
