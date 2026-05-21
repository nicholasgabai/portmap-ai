# Phase 65-70 Unified Runtime Operations Plan

Milestone K defines the next implementation milestone for making PortMap-AI operate as a cohesive long-running local platform. The focus is runtime session management, unified configuration profiles, state recovery, integrated runtime CLI commands, local health monitoring, and service-mode readiness.

This is a planning document only. It does not implement runtime behavior, start services, install components, change host configuration, contact external systems, or transmit data outside the local operator environment.

## Milestone K: Unified Runtime Operations

Goal:
Make PortMap-AI operate as a cohesive long-running local platform while preserving the current local-first, operator-controlled, advisory-by-default posture.

Milestone K should connect the existing runtime pipeline, scheduler, local storage, event model, topology state, policy review records, dashboard providers, and export bundle helpers into operationally clear local workflows.

All work should remain:

- local-first
- operator-controlled
- advisory by default
- policy-aware
- lightweight for edge devices
- Raspberry Pi/Linux compatible
- testable with sanitized fixtures
- compatible with existing CLI behavior

## Current Starting Point

Implemented foundation available before Phase 65:

- Local event model, queue, and event bus.
- SQLite-backed local storage repositories.
- Runtime scheduler primitives.
- Local node identity and coordination primitives.
- Local read-only API primitives.
- Dashboard rendering and provider foundations.
- Persistent topology state and snapshot drift detection.
- Runtime pipeline workflow primitives.
- Persistent operator review records and history.
- Operational export bundle helpers.
- Diagnostic schema validation, stream metadata parsing, plugin governance, relay orchestration, and service lifecycle template records.

Milestone K should improve operational cohesion without bypassing safety boundaries or replacing the existing Textual terminal dashboard.

## Phase 65 - Runtime Session Manager

Status: Complete Baseline

Goal:
Add a local runtime session manager that tracks explicit operator-started PortMap-AI runtime sessions across scheduler, pipeline, storage, dashboard provider, health, and export subsystems.

Build:

- `core_engine/runtime/session.py`
- `core_engine/runtime/session_state.py`
- `tests/test_runtime_session_manager.py`
- `docs/runtime_session_manager.md`

Features:

- Runtime session identifiers.
- Session start and stop timestamps.
- Session mode labels such as dry-run, local-write, and service-preview.
- Enabled component summaries.
- Runtime pipeline summary references.
- Event queue and storage status references.
- Review queue and export summary references.
- Last error and warning summaries.
- Local-only session records with explicit safety fields.
- Deterministic session summaries for CLI, API, and dashboard use.

Acceptance:

- A runtime session can be created, summarized, stopped, and serialized.
- Dry-run remains the default session posture.
- Session records do not start services or execute actions.
- Failed subsystem summaries are isolated and reported.
- Tests use temporary records and sanitized fixtures only.

## Phase 66 - Unified Configuration Profiles

Status: Complete Baseline

Goal:
Add unified runtime configuration profile helpers that compose existing configuration validation, runtime defaults, scheduler settings, storage settings, API settings, dashboard provider settings, and export settings.

Build:

- `core_engine/runtime/profiles.py`
- `core_engine/runtime/profile_loader.py`
- `tests/test_runtime_profiles.py`
- `docs/unified_configuration_profiles.md`

Features:

- Local runtime profile records.
- Profile merge helpers for default, edge-device, and operator-provided settings.
- Validation through existing configuration validation primitives.
- Scheduler interval defaults.
- Storage and API binding defaults.
- Dashboard provider defaults.
- Export bundle defaults.
- Raspberry Pi-conscious resource settings.
- Operator-readable profile summaries.

Acceptance:

- Profiles can be loaded, merged, validated, and summarized.
- Existing CLI and configuration behavior remains compatible.
- Default local API binding remains loopback-only.
- Invalid profiles fail with structured validation output.
- Public docs and tests use sanitized placeholders only.

## Phase 67 - Runtime State Recovery

Status: Complete Baseline

Goal:
Add local runtime state recovery helpers that can inspect previous session records, storage state, review records, and export summaries so an operator can resume or review interrupted local workflows.

Build:

- `core_engine/runtime/recovery.py`
- `core_engine/runtime/checkpoints.py`
- `tests/test_runtime_recovery.py`
- `docs/runtime_state_recovery.md`

Features:

- Local checkpoint records.
- Last-known runtime session summaries.
- Incomplete workflow detection.
- Pending review summary detection.
- Failed step summary detection.
- Export-ready record detection.
- Recovery recommendation records.
- Explicit operator review requirements.
- No automatic restart or workflow execution.

Acceptance:

- Recovery helpers can build summaries from sanitized previous records.
- Missing or malformed checkpoints are handled safely.
- Recovery recommendations are advisory only.
- No services are started and no configuration is changed.
- Tests use temporary storage locations only.

## Phase 68 - Integrated Runtime CLI

Status: Complete Baseline

Goal:
Add CLI commands that expose the unified runtime operations path without changing existing command behavior.

Build:

- `cli/runtime.py`
- Updates to `cli/main.py`
- `tests/test_runtime_cli.py`
- `docs/runtime_cli.md`

Features:

- `portmap runtime status`
- `portmap runtime run`
- `portmap runtime recover`
- `portmap runtime reviews`
- `portmap runtime export`
- Dry-run default behavior.
- Explicit local-write mode for operator-approved local storage writes.
- JSON and table output.
- Structured error summaries.
- Compatibility with existing `portmap stack`, `portmap tui`, `portmap visibility`, and log commands.

Acceptance:

- Runtime CLI commands return deterministic output for sanitized fixtures.
- Dry-run commands do not write local records.
- Local-write commands require explicit operator flags.
- Existing CLI tests continue to pass.
- No external transmission or automatic enforcement is added.

## Phase 69 - Runtime Health Monitor

Status: Complete Baseline

Goal:
Add lightweight local runtime health monitoring helpers for storage, scheduler, event queue, review records, dashboard providers, export readiness, and resource-conscious operation.

Build:

- `core_engine/runtime/health.py`
- `tests/test_runtime_health_monitor.py`
- `docs/runtime_health_monitor.md`

Features:

- Storage health checks.
- Event queue depth checks.
- Scheduler status checks.
- Review queue status checks.
- Dashboard provider readiness checks.
- Export bundle readiness checks.
- Runtime session health summaries.
- Resource budget warning fields.
- Raspberry Pi-friendly thresholds.
- Health events suitable for local event storage.

Acceptance:

- Health summaries are deterministic and JSON serializable.
- Failed checks are reported without crashing the monitor.
- Checks do not perform active probing or external calls.
- Health output includes safety fields.
- Tests cover healthy, degraded, and unavailable component states.

## Phase 70 - Service Mode Readiness

Status: Complete Baseline

Goal:
Prepare PortMap-AI for documented service mode by adding local preflight checks, service command previews, and configuration summaries without installing, enabling, or starting services automatically.

Build:

- `core_engine/runtime/service_mode.py`
- `tests/test_service_mode_readiness.py`
- `docs/service_mode_readiness.md`

Features:

- Service-mode preflight checks.
- Operator-readable service command previews.
- Configuration profile validation for service mode.
- Runtime session mode summaries.
- Storage readiness checks.
- Export and review queue readiness checks.
- Service template compatibility checks.
- Dry-run output only.
- Explicit documentation for manual operator review.

Acceptance:

- Service readiness summaries can be generated locally.
- Output does not install, enable, start, or stop services.
- Platform-specific fields use placeholders in public docs.
- Existing service template helpers are reused.
- Tests use sanitized fixtures and temporary records only.

## Cross-Phase Data Flow

```text
runtime profile
  -> runtime session manager
  -> scheduler and pipeline summaries
  -> local storage, topology, review, and export summaries
  -> runtime health monitor
  -> integrated runtime CLI
  -> service-mode readiness preview
```

The flow is operator-triggered and local-only. No step should add automatic enforcement, router changes, service installation, public internet exposure, or external data transmission.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm new docs are included in package metadata when applicable.
- Confirm existing CLI behavior is preserved.
- Confirm all examples use sanitized placeholders only.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Load a minimal runtime profile.
- Create and stop a dry-run runtime session.
- Run state recovery against temporary previous-session records.
- Run runtime CLI commands in dry-run mode.
- Build health summaries with small fixture inputs.
- Generate service-mode readiness previews without installation.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest.
- Confirm no raw payload bytes are stored in public outputs.
- Confirm no private identifiers, logs, screenshots, database files, cache files, or runtime artifacts are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/runtime_session_manager.md`
- `docs/unified_configuration_profiles.md`
- `docs/runtime_state_recovery.md`
- `docs/runtime_cli.md`
- `docs/runtime_health_monitor.md`
- `docs/service_mode_readiness.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Hosted SaaS.
- Cloud billing.
- Public internet exposure.
- Automatic enforcement.
- Router modification.
- Automatic service installation or startup.
- Heavy ML training.
- Third-party export delivery.
- Background collection without explicit operator opt-in.
- Replacement of the existing Textual terminal dashboard.
