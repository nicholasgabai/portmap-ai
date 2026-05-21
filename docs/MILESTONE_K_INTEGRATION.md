# Milestone K Integration

Milestone K covers Phases 65-70: Unified Runtime Operations. It turns the Milestone J runtime pipeline, persistent topology, review persistence, dashboard providers, and export bundle helpers into a clearer local operations layer with runtime sessions, profiles, recovery, CLI commands, health summaries, and service-mode readiness previews.

This milestone remains local-first, operator-controlled, advisory by default, and dry-run-first. It does not install services, start services, modify host configuration, contact external systems, transmit data, execute remediation, or replace the Textual terminal dashboard.

## Completed Phases

| Phase | Area | Implemented Baseline |
| --- | --- | --- |
| 65 | Runtime session manager | Local runtime session records, session state summaries, mode labels, component summaries, status references, errors, and warnings. |
| 66 | Unified configuration profiles | Default, edge-device, and operator-merged runtime profiles with scheduler, storage, API, dashboard, export, and validation summaries. |
| 67 | Runtime recovery | Checkpoint records, previous-session summaries, incomplete workflow detection, pending review detection, failed step detection, export readiness, and advisory recovery recommendations. |
| 68 | Runtime CLI | `portmap runtime` status, run, recover, reviews, and export commands with dry-run defaults, explicit local-write mode, JSON output, and table output. |
| 69 | Runtime health monitor | Local storage, event queue, scheduler, review queue, dashboard provider, export readiness, session, and resource-budget health summaries. |
| 70 | Service mode readiness | Dry-run service-mode preflight checks, service command previews, profile validation, runtime session summaries, service template compatibility, and manual operator checklist records. |

## Module Map

| Layer | Modules | Role |
| --- | --- | --- |
| Runtime Sessions | `core_engine.runtime.session`, `core_engine.runtime.session_state` | Track explicit operator-started runtime sessions and expose deterministic summaries for CLI, API, dashboard, recovery, health, and service-preview flows. |
| Runtime Profiles | `core_engine.runtime.profiles`, `core_engine.runtime.profile_loader` | Compose and validate local runtime configuration across scheduler, storage, API, dashboard, export, and operator-provided settings. |
| Runtime Recovery | `core_engine.runtime.checkpoints`, `core_engine.runtime.recovery` | Read prior local checkpoints and records to produce advisory recovery summaries without automatically restarting workflows. |
| Runtime CLI | `cli.runtime`, `cli.main` | Expose the unified runtime operations path through explicit operator commands while preserving existing CLI behavior. |
| Runtime Health | `core_engine.runtime.health` | Summarize local component readiness and resource budget status without active probing or external calls. |
| Service Readiness | `core_engine.runtime.service_mode` | Build service-mode preflight summaries and service command previews using existing service template helpers. |

## Integrated Data Flow

```text
runtime profile
  -> runtime session record
  -> scheduler, event queue, storage, topology, review, dashboard, and export summaries
  -> runtime recovery checkpoints
  -> runtime health checks
  -> runtime CLI output
  -> service-mode readiness preview
  -> manual operator review
```

The flow is explicit and local. Dry-run remains the default posture, and local-write paths require operator intent.

## Connections To Existing Platform Layers

Event pipeline:
Runtime health can emit health events suitable for local event storage. Runtime pipeline summaries can expose event counts and event-ready records for CLI and dashboard use.

Storage:
Runtime profiles describe local storage defaults, runtime health checks storage readability, recovery can summarize prior local records, review integration persists state through existing repositories, and export bundles package selected local evidence.

Scheduler:
Runtime sessions can record scheduler status references. Runtime profiles define scheduler defaults, health checks read scheduler state, and the CLI exposes runtime operations without creating new scheduler systems.

Topology:
Runtime pipeline and dashboard providers already consume persistent topology snapshots and drift summaries. Milestone K surfaces those summaries through runtime session, health, CLI, and service-preview readiness contexts.

Review queue:
Runtime recovery detects pending review work, runtime health summarizes review queue status, the CLI exposes review summaries, and service readiness includes review queue readiness before any manual service setup.

Dashboard providers:
Runtime sessions, profiles, recovery, health, and service readiness produce API-compatible dictionaries that dashboard providers can consume without replacing the Textual TUI.

Export bundles:
Runtime recovery detects export-ready records, runtime health checks export readiness, the CLI exposes export operations, and service-mode readiness includes export status in the operator preflight path.

Service templates:
Service-mode readiness reuses the existing dry-run service lifecycle template generator to produce systemd and Windows command previews. It does not write service files, enable services, start services, or modify host configuration.

## Operator Workflow

```text
operator selects or loads runtime profile
  -> creates a dry-run runtime session
  -> runs runtime status or workflow commands
  -> reviews recovery and health summaries
  -> inspects pending review and export readiness
  -> generates service-mode readiness previews
  -> manually decides any next host-level action outside PortMap-AI
```

All records remain advisory and local. Approval and readiness states do not execute actions.

## Current Boundaries

Milestone K does not add:

- automatic service installation
- automatic service enablement or startup
- background daemon startup
- host configuration modification
- registry changes
- privilege escalation
- public network exposure
- cloud sync
- automatic enforcement
- router or firewall changes
- replacement of the Textual terminal dashboard

## Raspberry Pi Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Load the default runtime profile.
- Load the edge-device runtime profile.
- Merge a sanitized operator profile and validate the merged result.
- Create and stop a dry-run runtime session.
- Run runtime recovery against temporary checkpoint records.
- Run `portmap runtime status` with JSON output.
- Run `portmap runtime run` in dry-run mode and confirm no storage writes occur.
- Build runtime health summaries with temporary storage, empty event queues, review queues, dashboard provider summaries, and export readiness records.
- Generate service-mode readiness previews for systemd and Windows templates.
- Confirm service preview output reports `installation_performed: false`.
- Confirm service preview output reports `service_enabled: false`.
- Confirm service preview output reports `service_started: false`.
- Confirm no service file is written by the readiness layer.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest during focused tests.
- Confirm no private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.

## Next Direction

Recommended next milestone: Service Operations Hardening and Operator Experience.

Suggested areas:

- Operator-facing runtime status views backed by session, profile, health, review, and service-readiness summaries.
- Manual service setup documentation that consumes service-mode readiness previews.
- Storage-backed local API providers for runtime sessions and health records.
- Dashboard panels for runtime health, recovery, and service readiness.
- Raspberry Pi validation notes kept private unless scrubbed for public documentation.
