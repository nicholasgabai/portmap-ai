# Autonomous Enforcement Modes

Phase 140 adds advisory-only autonomous enforcement mode records for PortMap-AI. The records define monitor, supervised, autonomous-preview, and hardened-preview operating modes while keeping all actual enforcement disabled.

This phase does not execute remediation, modify firewall rules, quarantine services, kill processes, disable services, write configuration, create backups, restore files, store credentials, or enable automatic containment.

## Enforcement Modes

`core_engine/remediation/enforcement_modes.py` defines mode records with:

- `mode_id`
- `mode_name`
- `mode_state`
- `allowed_action_classes`
- `blocked_action_classes`
- `approval_requirements`
- `safety_guardrails_required`
- `rollback_requirements`
- `provider_requirements`
- `runtime_health_requirements`
- `audit_requirements`
- `preview_only`
- `destructive_action`
- `advisory_notes`

Supported modes are:

- `monitor`
- `supervised`
- `autonomous_preview`
- `hardened_preview`

Supported states are `available`, `degraded`, `blocked`, `unavailable`, and `unknown`.

## Monitor vs Supervised vs Preview Modes

Monitor mode allows observation, operator review, advisory recommendations, and audit previews only.

Supervised mode models a future operator-approved review workflow. It requires approval, rollback previews, guardrails, runtime health, and audit readiness before it can be considered available.

Autonomous-preview and hardened-preview modes model future prerequisites for stronger automation, including provider readiness and emergency stop readiness. They are still preview-only and do not activate enforcement.

## Autonomy Controls

`core_engine/remediation/autonomy_controls.py` defines autonomy control summaries with:

- selected mode
- autonomy level
- escalation permission
- containment permission
- approval requirement
- emergency stop requirement
- audit requirement
- safety blockers
- operator actions
- recommended mode
- readiness state

Containment remains disabled:

- `containment_allowed: false`
- `enforcement_active: false`
- `preview_only: true`
- `destructive_action: false`

## Approval, Audit, and Emergency Stop

Supervised and preview autonomy levels require explicit approval paths. Autonomous-preview and hardened-preview modes require emergency stop readiness, audit readiness, provider readiness, rollback readiness, and safety guardrail readiness.

Missing prerequisites degrade or block the mode and recommend a safer mode, usually `monitor`.

## Future Path

Real supervised enforcement remains a later milestone. Before any live action can be considered, PortMap-AI still needs RBAC enforcement, provider-specific validation, tamper-resistant audit trails, tested rollback execution, operator approval workflows, and production validation.
