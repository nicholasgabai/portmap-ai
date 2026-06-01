# Upgrade And Migration Readiness

Phase 120 adds upgrade and migration readiness models for previewing PortMap-AI upgrades before any operator executes a real migration.

This phase is dry-run only. It does not execute migrations, modify configuration files, modify history stores, delete or rewrite snapshots, install services, generate credentials, or write deployment changes.

## Upgrade Readiness

Upgrade readiness records include:

- `current_version`
- `target_version`
- `compatibility_state`
- `runtime_profile_impact`
- `deployment_manifest_impact`
- `service_lifecycle_impact`
- `telemetry_impact`
- `history_retention_impact`
- `operator_action_required`
- `rollback_available`
- `advisory_notes`

Readiness states are:

- `ready` - supplied upgrade inputs are compatible for dry-run planning.
- `degraded` - upgrade can be previewed, but one or more areas requires operator review.
- `blocked` - version compatibility or a component impact blocks the upgrade preview.
- `unknown` - malformed or incomplete inputs prevent a confident readiness summary.

## Migration Previews

Migration preview records cover:

- config migration
- runtime profile migration
- deployment manifest migration
- historical snapshot schema migration
- retention policy migration
- service lifecycle plan migration

Every preview includes:

- `migration_name`
- `migration_type`
- `preview_only: true`
- `destructive_action: false`
- `required_backups`
- `rollback_notes`
- `validation_steps`
- `operator_steps`
- `safety_warnings`

No migration preview executes a migration. The records exist to show what an operator should inspect, back up, and validate before any external upgrade workflow.

## Rollback And Backups

Upgrade readiness assumes operators keep export-safe backups before real upgrades. Recommended backup references include runtime export summaries, deployment manifest exports, configuration snapshots, historical metadata snapshots, retention policy exports, and service lifecycle preview exports.

Rollback notes are advisory. PortMap-AI does not automatically restore, delete, rewrite, or downgrade files in Phase 120.

## Operator Review

Operators should review degraded, blocked, or unknown states before continuing. Public docs and tests use sanitized version labels and placeholders only. Real hostnames, IP addresses, usernames, MAC addresses, logs, screenshots, credentials, private paths, database files, and runtime artifacts must remain out of committed documentation.
