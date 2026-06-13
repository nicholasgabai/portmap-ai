# Audit Logging Governance

Phase 165 adds metadata-only governance records for audit events, daily log rotation readiness, last export summaries, export validation summaries, retention previews, compression previews, and deletion previews. The records are advisory and export-safe; they do not delete logs, rotate live files, compress files, extract archives, read private exports by default, write files, or change runtime behavior.

## Audit Event Records

`core_engine/governance/audit_events.py` defines audit event records for runtime events, exports, operator actions, policy reviews, remediation previews, configuration, packaging, security reviews, and unknown categories. Event records sanitize actor, action, target, and evidence references so public exports do not contain private identifiers.

Supported event states are recorded, pending, degraded, invalid, and unknown. Every audit event record includes fixed preview-only and no-destructive-action safety fields.

## Daily Rotating Log Readiness

`core_engine/governance/log_rotation.py` defines daily log rotation readiness records for master, worker, audit, export, runtime, TUI, and unknown log families. The records summarize current log references, daily rotation periods, retention days, file-size budgets, estimated log counts, and validation status.

The rotation layer is readiness-only. It does not move, rotate, compress, truncate, or delete live files.

## Last Export Summary

`core_engine/governance/export_audit.py` defines Last Export Summary records with an export reference, export type, file count, total size, and metadata-only safety flags. These records summarize export evidence without reading private export contents by default.

## Export Validation Summary

Export audit records compare expected, observed, and missing file summaries and track schema validation, sensitive-data scan, and artifact/private-file check states. The summaries do not require zip extraction, do not read private exports by default, and do not write validation artifacts.

## Retention, Compression, And Deletion Previews

Retention previews describe expected retention posture. Compression previews describe whether compression may be useful later. Deletion previews are advisory only and explicitly record that deletion was not performed.

## Future TUI Path

Runtime Export Validation Panel should be added later when the TUI gains tabbed or multi-screen navigation. Phase 165 does not force new validation panels into the current dashboard.

## Safety Boundary

Phase 165 does not delete logs, rotate live files destructively, compress files, extract zip files, read private exports by default, write files, store credentials, store private identifiers in docs or exports, execute remediation, modify firewall/process/service state, or change runtime behavior.
