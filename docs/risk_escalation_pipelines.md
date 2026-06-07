# Risk Escalation Pipelines

Phase 138 adds advisory-only risk escalation pipelines for PortMap-AI. These records combine policy evaluations, adaptive remediation recommendations, flow intelligence, application attribution, behavioral drift, topology relationships, runtime health, and provider readiness into bounded incident-candidate summaries.

This phase does not produce final threat verdicts. It does not execute remediation, modify firewall rules, quarantine services, kill processes, disable services, write system configuration, store credentials, inspect payloads, or perform response actions.

## Risk Escalation Records

`core_engine/remediation/risk_escalation.py` defines `RiskEscalationRecord` with:

- `escalation_pipeline_id`
- `escalation_state`
- `input_signal_count`
- `combined_risk_score`
- `confidence_score`
- `severity_level`
- `escalation_reason`
- signal references for policies, remediation previews, attribution, drift, topology, runtime health, and provider readiness
- `safety_blockers`
- `operator_actions`
- `preview_only`
- `destructive_action`

Supported escalation states are:

- `none`
- `monitor`
- `investigate`
- `review_required`
- `approval_required`
- `blocked_by_safety`
- `unknown`

The pipeline aggregates evidence into review-oriented states only. Safety blockers override higher escalation states and keep records advisory.

## Incident Candidates

`core_engine/remediation/incident_candidates.py` defines incident candidate records with:

- `candidate_id`
- `candidate_type`
- `candidate_state`
- `severity_level`
- `confidence_score`
- related escalation, flow, policy, and topology references
- evidence and operator summaries
- recommended next step
- approval and preview safety fields

Supported candidate types are:

- `exposed_service_review`
- `unusual_flow_review`
- `attribution_conflict_review`
- `drift_review`
- `topology_risk_review`
- `runtime_health_review`
- `containment_readiness_review`

Supported candidate states are `informational`, `candidate`, `needs_review`, `blocked_by_safety`, and `unknown`.

## Candidate vs Threat Verdict

Incident candidates are review objects. They are not threat verdicts, detection conclusions, or enforcement decisions. Records deliberately omit final verdict fields and include:

- `candidate_only: true`
- `preview_only: true`
- `destructive_action: false`

## Multi-Signal Aggregation

The aggregation layer considers:

- matched advisory policies
- adaptive remediation preview risk
- flow and relationship confidence
- attribution uncertainty
- drift severity
- topology risk
- runtime health state
- provider readiness state

Missing or malformed inputs are normalized into bounded scores and degraded advisory summaries instead of side effects or false certainty.

## Safety Blockers

Safety blockers include unavailable providers, unsafe runtime health, non-preview remediation records, and any destructive-action flags discovered in upstream summaries. Blocked records are still exported for operator review, but no response action is executed.

## Future SOC Path

Later work can connect these records to SOC-style consoles, case management, and supervised response review. That path still requires guardrails, audit controls, rollback planning, RBAC enforcement, provider validation, and explicit operator approval before any live containment can be considered.
