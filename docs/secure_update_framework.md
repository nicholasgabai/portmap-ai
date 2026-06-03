# Secure Update Framework

Phase 128 adds secure update framework readiness records for future PortMap-AI releases.

This phase is preview-only. It does not download updates, execute installers, modify files, restore files, delete files, overwrite configuration, create signing keys, store private keys, enable live signature trust, or apply migrations.

## Update Verification Model

`core_engine/security/update_verification.py` defines `UpdateVerificationRecord` entries for:

- `release_manifest`
- `package_digest`
- `signature_status`
- `migration_manifest`
- `compatibility_manifest`
- `rollback_manifest`

Each record includes:

- `update_target`
- `current_version`
- `target_version`
- `verification_state`
- `digest_state`
- `signature_state`
- `compatibility_state`
- `migration_required`
- `rollback_available`
- `operator_action_required`
- `advisory_notes`

Supported verification states:

- `verified`
- `degraded`
- `blocked`
- `unavailable`
- `unknown`

Exported update records include explicit safety fields:

- `export_safe: true`
- `preview_only: true`
- `update_downloaded: false`
- `installer_executed: false`
- `file_modified: false`
- `migration_executed: false`
- `private_key_material_present: false`
- `signing_material_generated: false`
- `live_signature_trust_enabled: false`

The `verified` state is fixture-safe and advisory. It means a sanitized record can model successful verification, not that a real release was downloaded, verified, installed, or trusted by a live updater.

## Future Signed Update Flow

The future signed update path should separate these concerns:

1. Operator reviews signed release metadata.
2. Package digests are compared against trusted release manifests.
3. Signature status is verified against operator-approved trust material.
4. Compatibility and migration manifests are reviewed.
5. Rollback availability is confirmed.
6. The operator explicitly approves any future install or migration workflow.

Phase 128 only creates readiness records for these steps. It does not implement trust stores, private keys, live signature verification, download transport, installer execution, or automatic migration.

## Rollback Planning

`core_engine/security/rollback_plans.py` defines `RollbackPreviewRecord` entries for:

- `config_rollback`
- `package_rollback`
- `migration_rollback`
- `identity_rollback`
- `trust_chain_rollback`
- `history_store_rollback`

Rollback preview records include:

- `rollback_name`
- `rollback_type`
- `rollback_state`
- `backup_required`
- `compatibility_required`
- `operator_steps`
- `validation_steps`
- `risk_summary`
- `preview_only`
- `destructive_action`

Supported rollback states:

- `ready`
- `degraded`
- `blocked`
- `unavailable`
- `unknown`

Every rollback preview remains:

- `preview_only: true`
- `destructive_action: false`
- `restore_executed: false`
- `file_deleted: false`
- `file_overwritten: false`
- `config_modified: false`
- `migration_executed: false`

## Migration Safety

Migration readiness is represented as metadata only. A migration manifest can indicate that a future update would require schema, configuration, runtime profile, deployment, history-store, or retention changes. Phase 128 does not execute those changes.

Before future migration execution, PortMap-AI should require backup validation, compatibility checks, rollback planning, operator approval, and audit records.

## Why Updates Are Not Applied Yet

The secure update framework needs trusted node identity, transport security, secret handling, RBAC, tamper detection, deployment readiness, backup planning, and audit linkage before live update behavior is safe.

Phase 128 intentionally stops at export-safe readiness records. Future updater work must be explicit, authenticated, authorized, auditable, reversible, and operator-approved.

Public docs and tests must use sanitized placeholders only. They must not include private hostnames, IP addresses, usernames, MAC addresses, credentials, private keys, logs, screenshots, runtime databases, cache files, or private validation notes.
