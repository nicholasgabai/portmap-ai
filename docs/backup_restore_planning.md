# Backup And Restore Planning

Phase 121 adds backup and restore planning records for PortMap-AI deployment operations. The records describe what an operator should include, exclude, validate, and review before creating backups or attempting restores outside PortMap-AI.

This phase is planning-only. It does not create backups, restore files, delete files, overwrite files, compress runtime artifacts, extract archives, copy credentials, or store secrets.

## Backup Plans

Backup plan records cover:

- configuration backup
- deployment manifest backup
- runtime export backup
- historical intelligence backup
- operator evidence bundle backup

Each backup plan includes:

- `backup_name`
- `backup_type`
- `included_components`
- `excluded_components`
- `destination_class`
- `retention_recommendation`
- `encryption_recommended`
- `operator_steps`
- `validation_steps`
- `dry_run_only: true`
- `destructive_action: false`
- `advisory_notes`

Backup plans intentionally exclude credentials, secrets, raw packet payloads, raw runtime logs, screenshots, cache files, local databases, temporary files, and unredacted evidence.

## Restore Previews

Restore preview records cover:

- config restore
- deployment manifest restore
- runtime profile restore
- historical intelligence restore
- evidence bundle restore

Each restore preview includes:

- `restore_name`
- `restore_type`
- `source_class`
- `target_class`
- `compatibility_checks`
- `rollback_notes`
- `conflict_warnings`
- `operator_steps`
- `validation_steps`
- `preview_only: true`
- `destructive_action: false`

Restore previews do not restore files, overwrite existing data, delete records, rewrite snapshots, modify history stores, or extract archives.

## Historical Intelligence Backups

Historical intelligence backups should include metadata summaries such as historical snapshot summaries, baseline rollups, topology evolution rollups, and retention summaries. They should not include raw packet payloads, credentials, raw DNS payloads, raw browsing history, screenshots, cache files, local databases, or private runtime artifacts.

## Evidence Bundle Safety

Evidence bundle backup plans preserve redaction expectations and placeholder validation summaries. Operators should verify redaction status before storing or sharing an evidence bundle backup. Phase 121 does not create evidence archives or transmit data externally.

## Operator Review

Operators should review backup destination classes, retention recommendations, encryption recommendations, excluded components, restore compatibility checks, rollback notes, and conflict warnings before any external backup or restore workflow. Public docs and tests use sanitized placeholders only and must not include real hostnames, IP addresses, usernames, MAC addresses, credentials, private paths, logs, screenshots, databases, or runtime artifacts.
