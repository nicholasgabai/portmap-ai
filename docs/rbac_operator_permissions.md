# RBAC And Operator Permissions

Phase 126 adds role-based access control and operator permission readiness records for future dashboard, API, federation, enrollment, export, and remediation workflows.

This phase is advisory and preview-only. It does not create user accounts, store passwords, store tokens, create a user database, enforce live authentication, or modify API access behavior.

## RBAC Model

`core_engine/security/rbac.py` defines `RBACRole` records for:

- `admin`
- `security_operator`
- `analyst`
- `auditor`
- `read_only`
- `service_account`

Role records include:

- `role_name`
- `permission_scope`
- `remediation_authority`
- `configuration_authority`
- `enrollment_authority`
- `audit_visibility`
- `export_authority`
- `dashboard_access`
- `api_access`
- `advisory_notes`

Exported records include explicit safety fields:

- `export_safe: true`
- `preview_only: true`
- `live_auth_enforced: false`
- `user_database_created: false`
- `credentials_stored: false`

## Operator Roles

`admin` has full readiness authority, including configuration, enrollment, export, and role-management previews. Future live enforcement must still require explicit authentication and audit controls.

`security_operator` can approve remediation, enrollment, and export requests in preview records, but cannot directly manage RBAC roles.

`analyst` can view telemetry and request remediation or export workflows, but approval requires a higher-authority role.

`auditor` has broad audit visibility and read-focused access.

`read_only` can view operator summaries but cannot approve remediation, enrollment, configuration changes, role changes, or exports.

`service_account` is a non-human readiness record. It does not perform operator actions in this phase.

## Permission Preview Model

`core_engine/security/permissions.py` defines `PermissionEvaluationPreview` records for:

- `view_telemetry`
- `view_history`
- `export_runtime`
- `approve_remediation`
- `execute_remediation`
- `rotate_node_identity`
- `approve_enrollment`
- `modify_config`
- `view_audit_log`
- `manage_roles`

Supported preview states:

- `allowed`
- `denied`
- `requires_approval`
- `unavailable`

Every permission preview remains:

- `preview_only: true`
- `destructive_action: false`
- `live_auth_enforced: false`
- `user_data_stored: false`
- `credential_stored: false`

## Future Dashboard And API Enforcement Path

Phase 126 creates the vocabulary and export-safe records that future dashboard/API authorization can consume. It intentionally does not enforce those decisions yet.

Future enforcement work should add authenticated operator identity, session lifecycle controls, audit-linked permission decisions, role-management workflows, service account scoping, and API/dashboard access gates.

Those future changes must be explicit, tested, reversible, and auditable.

## Remediation Approval Boundaries

Remediation remains advisory by default. Even where a role can approve remediation, execution-sensitive actions remain preview-only until a future enforcement phase adds live authorization, safety guardrails, and rollback controls.

Phase 126 does not enable automatic blocking, firewall changes, service changes, router changes, or live remediation execution.

## Why Live Auth Is Not Enforced Yet

PortMap-AI already has earlier enterprise auth primitives, but Phase 126 does not connect RBAC readiness records to live API or TUI enforcement. Keeping this phase preview-only allows role and permission semantics to stabilize before live authentication, user storage, session state, and audit enforcement are wired together.

Public docs and tests must not include real hostnames, private IP addresses, usernames, MAC addresses, passwords, tokens, logs, screenshots, runtime databases, cache files, or private validation notes.
