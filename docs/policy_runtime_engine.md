# Policy Runtime Engine

Phase 135 adds a dry-run, advisory-only policy runtime engine for PortMap-AI. It loads, validates, and evaluates policy records against metadata-only telemetry, flow, attribution, drift, topology, and runtime context records.

The runtime engine does not enforce policies. It does not modify firewall rules, quarantine services, stop processes, disable services, write system configuration, load remote policy definitions, store credentials, inspect packet payloads, or execute rollback actions.

## Policy Records

Policy runtime records include:

- `policy_id`
- `policy_name`
- `policy_type`
- `enabled`
- `severity`
- `match_conditions`
- `recommended_action`
- `approval_required`
- `enforcement_mode`
- `source_mode`
- `advisory_notes`

Supported policy types:

- `port_exposure`
- `service_behavior`
- `flow_behavior`
- `application_attribution`
- `drift_behavior`
- `topology_relationship`
- `runtime_health`

Safe enforcement modes are preview-only:

- `monitor`
- `advisory`
- `dry_run`
- `supervised_preview`

Unsafe modes and destructive recommendations are rejected during loading and validation.

## Match Conditions

Match conditions are metadata-only. They can compare exact fields, nested fields, list/string containment, numeric minimums or maximums, and severity thresholds.

Sanitized example:

```json
{
  "policy_id": "policy-port-exposure",
  "policy_name": "Review Exposed Management Port",
  "policy_type": "port_exposure",
  "enabled": true,
  "severity": "high",
  "match_conditions": {
    "equals": {
      "port": 22,
      "source_mode": "live"
    },
    "minimums": {
      "confidence_score": 0.7
    }
  },
  "recommended_action": "operator_review",
  "approval_required": true,
  "enforcement_mode": "dry_run",
  "source_mode": "fixture",
  "advisory_notes": [
    "Review exposed management service metadata."
  ]
}
```

## Evaluation Records

Policy evaluation records include:

- `evaluation_id`
- `policy_id`
- `matched`
- `evaluation_state`
- `match_reason`
- `confidence_score`
- `recommended_action`
- `approval_required`
- `enforcement_mode`
- `destructive_action`
- `preview_only`
- `source_mode`

Supported evaluation states:

- `matched`
- `not_matched`
- `degraded`
- `invalid`
- `unknown`

Every evaluation record sets `destructive_action: false` and `preview_only: true`.

## Loader Behavior

The policy loader accepts in-memory dictionaries, lists, and fixture-safe JSON strings. It validates required fields, normalizes disabled policies, rejects unsafe enforcement modes, rejects destructive recommendations, and returns export-safe bundle summaries.

The loader does not write files and does not load remote policy definitions.

## Safety Boundary

Phase 135 is advisory-only. It prepares structured policy records for future supervised response workflows, but future response phases must still add operator approval gates, guardrails, rollback previews, provider readiness, and separate validation before any enforcement mode can be considered.

Public examples must use sanitized placeholders only. Do not include real IP addresses, hostnames, usernames, MAC addresses, tokens, credentials, private paths, screenshots, logs, runtime databases, or validation artifacts.
