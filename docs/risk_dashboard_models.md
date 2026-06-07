# Risk Dashboard Models

Phase 144 adds visualization-ready risk dashboard models for PortMap-AI. Risk cards and dashboard panels convert existing metadata-only risk, policy, remediation, incident, drift, attribution, topology, asset inventory, runtime health, and guardrail summaries into bounded operator-facing records for future dashboard/API/export views.

This phase is model-only. It does not add a browser UI, execute remediation, modify firewall/process/service state, write runtime databases, inspect packet payloads, store raw packets, retain raw DNS history, or export private identifiers.

## Risk Cards

`core_engine.visualization.risk_cards` defines `RiskCard` records with:

- `card_id`
- `card_type`
- `card_title`
- `severity_level`
- `confidence_score`
- `risk_score`
- `summary`
- explanation points
- related asset, flow, policy, incident, and guardrail references
- recommended next step
- source modes
- preview-only and destructive-action safety fields
- advisory notes

Supported card types are:

- `asset_risk`
- `flow_risk`
- `policy_risk`
- `drift_risk`
- `attribution_risk`
- `topology_risk`
- `remediation_preview`
- `guardrail_block`
- `runtime_health`
- `unknown`

Cards sanitize references before export and preserve source modes such as `live`, `fixture`, `simulated`, `replay`, and `unknown`.

## Dashboard Panels

`core_engine.visualization.risk_dashboard` defines `RiskDashboardPanel` records with:

- `dashboard_id`
- `generated_at`
- `risk_state`
- `overall_risk_score`
- `highest_severity`
- `card_count`
- severity counts
- category counts
- recommendation count
- blocked-action count
- bounded card rows
- `max_cards`
- export-safe safety fields

Dashboard builders deduplicate related cards, sort high-risk cards first, apply `max_cards`, and produce empty dashboards when no risk records are available.

## Inputs

Risk dashboard panels can be built from:

- asset inventory summaries
- topology graphs
- flow summaries
- policy evaluations
- remediation recommendations
- incident candidates
- guardrail records
- runtime health summaries
- drift records
- attribution records

Malformed collection inputs raise structured errors. Malformed individual rows are ignored when they are not dictionaries.

## Explanation Points

Explanation points summarize why a card exists, such as policy matches, observed service hints, drift state, guardrail blockers, runtime degradation, or recommendation context. They are operator-facing metadata summaries only, not final threat verdicts.

## Recommendation And Blocked-Action Counts

`recommendation_count` tracks cards that recommend review or follow-up. `blocked_action_count` tracks guardrail or safety-blocked records. These counts help future UI panels highlight review pressure without executing response actions.

## Safety Boundary

Phase 144 explicitly guarantees:

- No browser UI is added.
- No remediation is executed.
- No firewall, process, service, quarantine, rollback, or isolation action is performed.
- No runtime database is written.
- No packet payload is inspected.
- No raw packet is stored.
- No raw DNS history is retained.
- No private hostnames, addresses, usernames, MAC addresses, credentials, certs, keys, logs, screenshots, runtime outputs, or local databases are required or exported.

## Future GUI Path

These records provide a stable data contract for later dashboard panels, risk cards, explanation drawers, and recommendation summaries. Future UI work can render these records without changing collectors or host/network state.

## Validation

Use sanitized fixtures only:

- Run `python -m pytest tests/test_risk_dashboard_models.py`.
- Run the full test suite before committing.
- Run `git diff --check`.
- Run a sensitive-data scan.
- Confirm `docs/real_device_validation.md`, local test files, logs, artifacts, screenshots, caches, runtime outputs, and databases remain unstaged.
