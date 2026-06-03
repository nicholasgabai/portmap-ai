# Tamper Detection

Phase 127 adds runtime integrity and tamper-detection readiness records for future production deployments.

This phase is preview-only. It does not hash private operator files, start file watchers, delete files, quarantine artifacts, execute rollback, modify configuration, modify binaries, enable blocking, or enforce remediation.

## Integrity Target Model

`core_engine/security/integrity.py` defines `IntegrityTargetRecord` entries for:

- `runtime_config`
- `deployment_manifest`
- `node_identity`
- `trust_chain`
- `transport_profile`
- `package_manifest`
- `binary_artifact`
- `history_store`

Each target record includes:

- `target_name`
- `target_class`
- `integrity_state`
- `verification_mode`
- `digest_available`
- `signature_available`
- `last_verified_preview`
- `drift_detected`
- `advisory_notes`

Supported integrity states:

- `verified`
- `drift_detected`
- `unverifiable`
- `unknown`

Exported integrity records include explicit safety fields:

- `export_safe: true`
- `preview_only: true`
- `file_watcher_started: false`
- `real_private_file_hashed: false`
- `system_file_modified: false`
- `private_path_exposed: false`

Verification modes are readiness labels only. They describe whether digest or signature verification can be represented in future production workflows. Phase 127 does not require hashing real private files and does not expose absolute local paths.

## Tamper Detection Preview Model

`core_engine/security/tamper_detection.py` defines `TamperDetectionPreview` entries for:

- `config_change`
- `manifest_change`
- `identity_rotation_mismatch`
- `trust_chain_drift`
- `transport_downgrade`
- `package_digest_mismatch`
- `history_store_drift`

Supported detection states:

- `clean`
- `suspicious`
- `tampered`
- `unverifiable`
- `unknown`

Preview records include:

- `detection_name`
- `severity`
- `affected_target`
- `detection_state`
- `evidence_summary`
- `operator_action_required`
- `remediation_preview`
- `enforcement_mode`
- `preview_only`
- `destructive_action`

Safety fields remain explicit:

- `preview_only: true`
- `destructive_action: false`
- `live_blocking_enabled: false`
- `quarantine_performed: false`
- `file_deleted: false`
- `rollback_executed: false`
- `config_modified: false`

## Safe Operator Review Workflow

Phase 127 is intended to help operators see whether future integrity evidence is clean, suspicious, tampered, unverifiable, or unknown. The output can be consumed by dashboard, API, export, deployment validation, and federation readiness summaries.

Recommended operator review flow:

1. Review the affected target class.
2. Compare preview evidence against operator-approved manifests.
3. Check whether the target is unverifiable because verification material is missing.
4. Review transport downgrade, trust-chain drift, and package digest mismatch records before production rollout.
5. Escalate to future signed update or restore workflows only after explicit operator approval.

## Future Enforcement Path

Future phases may add signed artifact verification, protected digest stores, audit-chain linkage, update verification, and rollback previews. Live enforcement must remain separate from this phase and must include authentication, authorization, audit logging, rollback planning, and explicit operator approval.

Phase 127 does not enable automatic blocking, quarantine, file deletion, firewall changes, service changes, router changes, binary modification, configuration modification, or rollback execution.

Public docs and tests must use sanitized placeholders only. They must not include private hostnames, IP addresses, usernames, MAC addresses, absolute local paths, credentials, logs, screenshots, runtime databases, cache files, or private validation notes.
