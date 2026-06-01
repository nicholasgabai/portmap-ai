# Service Lifecycle Readiness

Phase 118 adds cross-platform service lifecycle readiness models for operator review. The records describe how PortMap-AI could be installed, started, stopped, restarted, uninstalled, or checked by a platform service manager, but they never perform those actions.

This phase is preview-only. It does not install systemd units, create launchd plists, register Windows services, start or stop services, write to system directories, request elevation, change firewall rules, or store credentials.

## Providers

Service provider readiness covers:

- `linux-systemd` - Linux systemd preview records.
- `raspberry-pi-systemd-edge` - Raspberry Pi and Linux ARM systemd edge previews.
- `macos-launchd` - macOS launchd preview records.
- `windows-service-control-manager` - Windows Service Control Manager preview records.
- `foreground-process` - generic foreground process previews for platforms where service management is unavailable or not selected.

Provider readiness can be:

- `supported` - the provider matches the platform fixture and can produce dry-run previews.
- `degraded` - previews are available but require operator review, commonly for permissions or install path safety.
- `unavailable` - the provider does not match the platform fixture or cannot support the selected preview.
- `unknown` - insufficient information was supplied.

## Lifecycle Actions

Lifecycle preview records support:

- `install_preview`
- `start_preview`
- `stop_preview`
- `restart_preview`
- `uninstall_preview`
- `status_preview`

Every preview includes:

- `service_name`
- `platform`
- `provider`
- `action`
- `readiness_state`
- `required_permissions`
- `operator_steps`
- `safety_warnings`
- `dry_run_only: true`
- `destructive_action: false`
- sanitized `command_preview`
- `advisory_notes`

Command previews are strings and argument lists for review only. They are not executed by PortMap-AI.

## Operator Review

Lifecycle readiness is designed to make deployment work auditable before an operator acts. A production operator should review:

- selected provider and platform match
- permission requirements
- install path placeholders
- sanitized command preview text
- degraded or unavailable readiness states
- service-specific safety warnings

Any real service installation, registration, start, stop, restart, or removal remains a manual operator action outside these records.

## Safety Guarantees

The lifecycle model keeps these fields false in public outputs:

- `service_installed`
- `service_registered`
- `service_started`
- `service_stopped`
- `service_restarted`
- `service_uninstalled`
- `launch_agent_created`
- `systemd_unit_created`
- `windows_service_registered`
- `registry_changed`
- `system_directory_written`
- `admin_elevation_requested`
- `destructive_action`

Docs and tests use sanitized placeholders only. No real hostnames, IP addresses, usernames, MAC addresses, service credentials, private paths, logs, or screenshots are required.
