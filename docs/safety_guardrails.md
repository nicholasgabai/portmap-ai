# Safety Guardrails

Phase 139 adds advisory-only safety guardrail records for remediation simulation, rollback previews, blast-radius analysis, approval gates, and safety blockers.

This phase does not execute rollback, modify firewall rules, quarantine services, kill processes, disable services, write configuration, create backups, restore files, store credentials, or perform enforcement.

## Guardrail Evaluations

`core_engine/remediation/safety_guardrails.py` defines guardrail evaluation records with:

- `guardrail_id`
- `guardrail_type`
- `guardrail_state`
- `evaluated_action`
- `action_class`
- `approval_required`
- `rollback_required`
- `blast_radius_level`
- `safety_blockers`
- `operator_actions`
- `recommended_safe_mode`
- `confidence_score`
- `preview_only`
- `destructive_action`
- `advisory_notes`

Supported guardrail types are:

- `approval_gate`
- `rollback_gate`
- `blast_radius_gate`
- `provider_readiness_gate`
- `confidence_gate`
- `runtime_health_gate`
- `policy_scope_gate`
- `emergency_stop_gate`

Supported states are `allowed_preview`, `requires_approval`, `blocked`, `degraded`, `unavailable`, and `unknown`.

## Approval Gates

Approval gates identify whether a future response preview has explicit operator approval. Missing approval produces `requires_approval` and keeps the recommended safe mode in supervised preview or monitoring.

## Rollback Simulation

`core_engine/remediation/rollback_simulation.py` defines rollback simulation previews with rollback availability, confidence, rollback steps, validation steps, failure modes, required backups, and operator actions.

Supported rollback simulation states are `ready`, `degraded`, `blocked`, `unavailable`, and `unknown`.

Rollback simulations do not create backups, restore files, execute commands, or modify any local state.

## Blast-Radius Analysis

Blast-radius gates classify preview impact as `none`, `low`, `medium`, `high`, `critical`, or `unknown`. High and critical blast-radius previews require approval or become blocked until operators resolve safety concerns.

## Emergency Stop Model

The emergency stop gate is a preview-only safety record. If active, it blocks future response planning and recommends monitor mode. It does not stop services, kill processes, change firewall rules, or alter node state.

## Safety Fields

Every Phase 139 record exports:

- `preview_only: true`
- `destructive_action: false`
- `automatic_changes: false`
- `enforcement_executed: false`
- `rollback_executed: false`
- `firewall_changes: false`
- `service_changes: false`
- `process_changes: false`
- `credentials_stored: false`
- `raw_payload_stored: false`

## Future Path

These guardrails prepare future supervised and autonomous-preview modes. Real enforcement still requires separate provider validation, RBAC enforcement, audit trails, rollback verification, production validation, and explicit operator approval.
