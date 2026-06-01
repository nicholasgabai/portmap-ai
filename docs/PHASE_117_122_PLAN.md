# Phase 117-122 Operationalization and Deployment Foundation Plan

Milestone T defines the next implementation milestone for preparing PortMap-AI for reliable real-world deployment. The focus is production-safe runtime profiles, service lifecycle readiness, deployment manifests, upgrade and migration readiness, backup and restore planning, and unified operator deployment validation.

This is a planning document only. It does not install services, create launch agents, create systemd units outside temporary test fixtures, modify firewall rules, write registry keys, store credentials, perform destructive migrations, restore data, delete files, change host configuration, or transmit data outside the local operator environment.

## Milestone T: Operationalization and Deployment Foundation

Goal:
Prepare PortMap-AI for reliable real-world deployment by adding production-safe runtime profiles, service lifecycle modeling, deployment manifests, upgrade readiness, backup/restore planning, and operator deployment validation without enabling destructive automation.

Milestone T should connect existing runtime profiles, service-mode readiness, cross-platform validation, filesystem/export safety, runtime health, historical intelligence, export bundles, and deployment documentation into operator-reviewable deployment records.

All work should remain:

- local-first
- dry-run safe
- advisory-first
- cross-platform aware
- Raspberry Pi and edge compatible
- Windows, macOS, and Linux compatible
- operator-controlled
- export-safe
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 117:

- Runtime sessions, profiles, recovery, CLI, health monitoring, and service-mode readiness previews.
- Cross-platform runtime detection, Windows compatibility, packet capture readiness, firewall readiness, filesystem/export safety, and validation summaries.
- Live telemetry, gateway readiness, behavioral intelligence, historical persistence, resource-aware retention, and long-term intelligence summaries.
- Operational export bundle helpers and local dashboard/API-ready summary records.
- Service lifecycle template records and dry-run service-mode readiness checks.

Milestone T should model deployment readiness and operator workflows only. It should not install, start, stop, restart, or remove services automatically.

## Phase 117 - Production Runtime Profiles

Status: Complete Baseline

Goal:
Add production, staging, and development runtime profile records that make deployment posture explicit before service installation or long-running operation.

Build:

- `core_engine/deployment/runtime_profiles.py`
- `core_engine/deployment/profile_validation.py`
- `core_engine/deployment/__init__.py`
- `tests/test_production_runtime_profiles.py`
- `docs/production_runtime_profiles.md`

Features:

- Production, staging, and development runtime profile records.
- Safe default profile summaries.
- Environment capability checks.
- Deployment mode summaries.
- Configuration readiness flags.
- Runtime profile compatibility summaries.
- Edge and Raspberry Pi profile hints.
- Dashboard/API-ready profile readiness dictionaries.

Acceptance:

- Runtime profile readiness summaries are deterministic.
- Production profiles remain dry-run safe by default.
- Missing or incompatible settings produce degraded readiness, not host changes.
- No credentials, private paths, real hostnames, IP addresses, MAC addresses, or usernames are stored.
- Tests use sanitized fixtures only.

## Phase 118 - Service Lifecycle Readiness

Status: Complete Baseline

Goal:
Add cross-platform service lifecycle preview records for daemon, systemd, launchd, and Windows service operation without installing or controlling services.

Build:

- `core_engine/deployment/service_lifecycle.py`
- `core_engine/deployment/service_providers.py`
- `tests/test_service_lifecycle_readiness.py`
- `docs/service_lifecycle_readiness.md`

Features:

- Service install preview records.
- Daemon, systemd, launchd, and Windows service readiness summaries.
- Start, stop, and restart preview plans.
- Permission and elevation requirement summaries.
- Operator review checklist records.
- Unsupported and degraded platform states.
- Dashboard/API-ready service lifecycle dictionaries.

Acceptance:

- Service lifecycle output is preview-only.
- No service is installed, started, stopped, restarted, enabled, disabled, or removed.
- Permission requirements are summarized without requesting elevation.
- Public docs use sanitized placeholders only.
- Tests do not create service units outside temporary fixtures.

## Phase 119 - Deployment Manifest Generation

Status: Complete Baseline

Goal:
Add sanitized deployment manifest records for standalone, orchestrator, worker, edge, lab, and production-preview deployments.

Build:

- `core_engine/deployment/manifests.py`
- `core_engine/deployment/node_profiles.py`
- `tests/test_deployment_manifest_generation.py`
- `docs/deployment_manifest_generation.md`

Features:

- Sanitized deployment manifest records.
- Node role manifest summaries.
- Master, worker, and orchestrator deployment profiles.
- Edge and Raspberry Pi deployment manifests.
- Deployment dependency summaries.
- Export-safe deployment dictionaries.
- Dashboard/API-ready manifest summaries.

Acceptance:

- Deployment manifests are deterministic for sanitized inputs.
- Node identifiers remain placeholders in public docs and tests.
- Manifests do not store credentials, private hostnames, real IP addresses, MAC addresses, or usernames.
- Manifest generation does not write host configuration.
- Export summaries preserve redaction and placeholder requirements.

## Phase 120 - Upgrade and Migration Readiness

Goal:
Add upgrade and migration preview records for configuration, schema, and rollback readiness without destructive migrations.

Build:

- `core_engine/deployment/upgrade_readiness.py`
- `core_engine/deployment/migration_previews.py`
- `tests/test_upgrade_migration_readiness.py`
- `docs/upgrade_migration_readiness.md`

Features:

- Configuration migration preview records.
- Version compatibility summaries.
- Rollback readiness summaries.
- Schema migration safety checks.
- Dry-run migration plans.
- Unsupported and degraded upgrade states.
- Dashboard/API-ready upgrade dictionaries.

Acceptance:

- Upgrade readiness is deterministic for sanitized fixtures.
- No destructive migration, database modification, file deletion, or rollback is performed.
- Schema migration output is preview-only.
- Rollback records are advisory and require operator review.
- Tests use temporary records and sanitized version placeholders only.

## Phase 121 - Backup and Restore Planning

Goal:
Add backup and restore planning records that reference export bundles and historical intelligence summaries without automatically restoring or deleting data.

Build:

- `core_engine/deployment/backup_plans.py`
- `core_engine/deployment/restore_previews.py`
- `tests/test_backup_restore_planning.py`
- `docs/backup_restore_planning.md`

Features:

- Backup plan records.
- Restore preview records.
- Export bundle references.
- Historical intelligence backup summaries.
- Storage and retention safety summaries.
- Restore conflict and missing-reference records.
- Dashboard/API-ready backup and restore dictionaries.

Acceptance:

- Backup and restore plans are deterministic.
- No automatic restore, overwrite, deletion, archive extraction, or host configuration change occurs.
- Export bundle references remain local and operator-provided.
- Tests use temporary paths and sanitized placeholders.
- Public docs do not include private paths or runtime artifacts.

## Phase 122 - Deployment Operator Summary

Goal:
Combine runtime profile readiness, service lifecycle previews, deployment manifests, upgrade readiness, backup/restore planning, and platform validation into a unified operator deployment summary.

Build:

- `core_engine/deployment/operator_summary.py`
- `core_engine/deployment/operator_views.py`
- `tests/test_deployment_operator_summary.py`
- `docs/deployment_operator_summary.md`

Features:

- Unified deployment readiness summary.
- Dashboard/API-safe deployment views.
- Operator recommendation records.
- Supported, degraded, and unavailable states.
- Release-readiness checklist.
- Cross-platform deployment rollups.
- Raspberry Pi and edge deployment readiness rollups.
- Export-ready deployment summary dictionaries.

Acceptance:

- Deployment summaries are deterministic for sanitized fixtures.
- Empty, degraded, and unsupported deployment states render cleanly.
- Recommendations remain advisory and require operator review.
- No services, firewall rules, registry keys, launch agents, systemd units, migrations, restores, or deletions are applied.
- Existing CLI, TUI, dashboard, runtime, export, and packaging tests continue to pass.

## Cross-Phase Data Flow

```text
runtime and platform compatibility summaries
  -> production runtime profiles
  -> service lifecycle readiness previews
  -> deployment manifests
  -> upgrade and migration readiness
  -> backup and restore planning
  -> deployment operator summary
  -> dashboard/API views and export bundles
```

The flow is operator-triggered and preview-only. No step should add automatic service installation, firewall changes, registry writes, launch agent creation, systemd installation, destructive migrations, automatic restore/delete behavior, credential storage, or external transmission.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, temporary files, local test files, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm public docs use sanitized placeholders only.
- Confirm dry-run remains default.
- Confirm no service installation, firewall modification, registry write, migration execution, restore execution, or deletion behavior is added.
- Confirm existing CLI, TUI, runtime, dashboard, and export behavior is preserved.

## macOS Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Build development, staging, and production runtime profile readiness records.
- Generate launchd and daemon service lifecycle previews without creating launch agents.
- Build local orchestrator, master, worker, and edge deployment manifests.
- Generate upgrade, rollback, backup, restore, and deployment operator summaries.
- Confirm no service control, firewall modification, private path exposure, credentials, logs, screenshots, archives, cache files, databases, or runtime outputs are staged.

## Raspberry Pi / Linux ARM Validation Checklist

Use sanitized records and temporary local test locations only.

- Build Raspberry Pi and edge runtime profile readiness records.
- Generate systemd preview records without installing units.
- Generate edge deployment manifests with low-resource warnings.
- Build upgrade and backup readiness with small fixture sets.
- Confirm CPU, memory, and storage assumptions remain modest.
- Confirm no service installation, firewall modification, packet capture escalation, private identifiers, logs, screenshots, archives, cache files, databases, or runtime artifacts are staged.

## Linux Validation Checklist

Use sanitized records and temporary local test locations only.

- Build production profile readiness records.
- Generate daemon and systemd preview plans without service installation.
- Generate deployment manifests and upgrade previews.
- Build backup/restore planning summaries using temporary paths.
- Confirm no host configuration, firewall rules, service files, migrations, restores, deletions, or credentials are written.

## Windows Compatibility Fixture Checklist

Use sanitized fixtures only.

- Build Windows runtime profile readiness records.
- Generate Windows service preview records without service installation or control.
- Build Windows-safe deployment manifest and path summaries.
- Generate upgrade and backup/restore preview records.
- Confirm no registry writes, Windows Firewall changes, service control, Npcap assumptions, credential storage, or private identifiers are introduced.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/production_runtime_profiles.md`
- `docs/service_lifecycle_readiness.md`
- `docs/deployment_manifest_generation.md`
- `docs/upgrade_migration_readiness.md`
- `docs/backup_restore_planning.md`
- `docs/deployment_operator_summary.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Automatic service installation.
- Service start, stop, restart, enable, disable, or removal.
- Firewall rule changes.
- Registry writes.
- Launch agent creation.
- Systemd unit installation outside temporary tests.
- Destructive migrations.
- Automatic restore, overwrite, or delete behavior.
- Credential storage.
- Public internet exposure.
- Cloud control plane.
- Hosted SaaS.
- Background collection without explicit operator opt-in.
