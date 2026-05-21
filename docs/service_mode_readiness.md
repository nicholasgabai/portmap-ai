# Service Mode Readiness

Phase 70 adds a local service-mode readiness layer for operator review. It prepares dry-run summaries, checks existing runtime state, and generates service command previews without installing, enabling, starting, stopping, or modifying services.

## Scope

The readiness helpers are preview-only:

- Validate a service-preview runtime profile.
- Summarize storage, review queue, export, dashboard, scheduler, event queue, and session readiness.
- Generate systemd and Windows service template text through the existing service template helpers.
- Build a runtime session summary with `service-preview` mode.
- Return an operator checklist for manual review.

The module does not add service management behavior, registry changes, privilege escalation, background startup, external transport, or automatic remediation.

## Module

- `core_engine/runtime/service_mode.py`

Primary helpers:

- `build_service_mode_definition()`
- `build_service_template_compatibility()`
- `build_service_command_previews()`
- `build_service_mode_preflight()`
- `build_service_mode_readiness()`
- `summarize_service_mode_readiness()`
- `build_manual_operator_checklist()`

## Sanitized Example

```python
from core_engine.runtime import build_service_mode_readiness

readiness = build_service_mode_readiness(
    scheduler={
        "scheduler_status": "running",
        "failed_job_count": 0,
        "executed_job_count": 1,
    },
    event_queue=[],
    dashboard_provider={"status": "ok", "ready": True},
    generated_at="2026-01-02T00:00:00+00:00",
)
```

Example output shape:

```json
{
  "status": "ready",
  "profile_summary": {
    "profile_id": "runtime-service-preview",
    "runtime_mode": "service-preview"
  },
  "runtime_session": {
    "mode": "service-preview",
    "status": "running"
  },
  "command_previews": {
    "preview_count": 2
  },
  "dry_run": true,
  "installation_performed": false,
  "service_enabled": false,
  "service_started": false
}
```

Service definition placeholders are sanitized:

```json
{
  "service_id": "service.portmap.runtime",
  "name": "portmap-runtime",
  "command": ["<portmap-command>", "runtime", "status", "--output", "json"],
  "working_directory": "<portmap-app-dir>",
  "environment_file": "<portmap-env-file>",
  "user": "<portmap-service-user>"
}
```

## Preflight Checks

Service-mode preflight checks include:

- Runtime profile validation.
- Dry-run preview enforcement.
- Local storage readability.
- Review queue status.
- Export readiness.
- Service template compatibility.

Unavailable optional components are reported as local readiness details, not as automatic setup instructions.

## Manual Operator Checklist

Generated checklist records remind the operator to:

- Review the runtime profile summary.
- Confirm placeholder paths before use.
- Review storage, export, and review queue readiness.
- Inspect generated service template text.
- Perform any installation, enablement, or start command manually outside the preview.

## Safety Fields

All readiness outputs include explicit safety fields:

```json
{
  "local_only": true,
  "operator_controlled": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true,
  "dry_run": true,
  "preview_only": true,
  "installation_performed": false,
  "service_enabled": false,
  "service_started": false,
  "registry_changed": false,
  "privilege_escalation": false
}
```

## Raspberry Pi Validation

Use sanitized records and temporary local test locations only:

- Build a service-preview runtime profile.
- Generate readiness summaries with empty and populated local repositories.
- Confirm generated systemd template text is preview-only.
- Confirm no service installation, enablement, or startup command is executed.
- Confirm output remains JSON serializable and deterministic for fixed timestamps.
- Confirm public outputs contain no private identifiers, raw payload bytes, logs, screenshots, database files, cache files, or runtime artifacts.
