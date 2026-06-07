# Adaptive Remediation Logic

Phase 136 adds advisory, confidence-weighted remediation recommendation records for PortMap-AI. The logic consumes policy evaluations, risk scores, flow intelligence, attribution confidence, drift signals, topology context, and runtime health summaries, then returns preview-only operator guidance.

This phase does not execute remediation. It does not change firewall rules, quarantine services, stop processes, disable services, modify system configuration, store credentials, inspect packet payloads, or perform rollback actions.

## Records

`core_engine/remediation/adaptive_actions.py` defines `RemediationRecommendation` records with:

- `recommendation_id`
- `recommendation_type`
- `recommended_action`
- `action_class`
- `confidence_score`
- `risk_score`
- `supporting_signals`
- `policy_references`
- `flow_references`
- `attribution_references`
- `drift_references`
- `topology_references`
- `approval_required`
- `enforcement_mode`
- `preview_only`
- `destructive_action`
- `rollback_required`
- `advisory_notes`

Supported recommendation types are:

- `monitor`
- `review`
- `rate_limit_preview`
- `quarantine_preview`
- `block_preview`
- `isolate_node_preview`

The preview labels describe future response planning. They are not executable actions.

## Escalation Previews

`core_engine/remediation/escalation.py` defines escalation decision previews with:

- `escalation_id`
- `escalation_state`
- `escalation_reason`
- `confidence_score`
- `safety_blockers`
- `operator_actions`
- `recommended_next_step`
- `preview_only`
- `destructive_action`

Supported escalation states are:

- `none`
- `monitor`
- `review_required`
- `approval_required`
- `escalation_candidate`
- `blocked_by_safety`

High risk does not bypass operator review. Low confidence, blocked runtime health, or unsafe context keeps the output in review or safety-blocked states.

## Confidence Weighting

Adaptive recommendation selection considers:

- matched advisory policies
- policy confidence
- flow reconstruction confidence
- attribution confidence
- drift severity and confidence
- topology risk and relationship confidence
- runtime health state

Low-confidence evidence dampens action strength. Higher-risk and higher-confidence evidence can raise the recommendation to a stronger preview, but `approval_required` remains true and `destructive_action` remains false.

## Safety Boundary

Every Phase 136 record includes export-safe safety fields:

- `preview_only: true`
- `destructive_action: false`
- `automatic_changes: false`
- `firewall_changes: false`
- `service_changes: false`
- `process_changes: false`
- `credentials_stored: false`
- `raw_payload_stored: false`

Unsafe live verbs and active enforcement modes are rejected. The module is pure metadata processing and does not call operating-system remediation providers.

## Future Path

Later Milestone W phases can add provider readiness, risk escalation pipelines, guardrails, and enforcement-mode modeling. Those phases must still keep live enforcement disabled until separate operator approval, rollback safety, auditability, and production validation exist.
