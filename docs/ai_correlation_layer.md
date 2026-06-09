# AI Correlation Layer

Phase 150 adds deterministic, metadata-only AI correlation records for PortMap-AI. The layer combines IOC inventory and match records, DNS analytics, local signature matches, flow intelligence, application attribution, topology context, drift signals, risk dashboard summaries, policy evaluations, remediation previews, and guardrail records into explainable advisory evidence chains.

This phase does not call external AI APIs, call model providers, make network requests, inspect payloads, produce final threat verdicts, mark entities, or execute enforcement.

## Model Scope

The implementation lives in:

- `core_engine/intelligence/evidence_chains.py`
- `core_engine/intelligence/ai_correlation.py`

`evidence_chains.py` builds bounded evidence chain records for:

- `ioc_dns_signature`
- `flow_attribution_drift`
- `topology_policy_risk`
- `remediation_guardrail`
- `composite`
- `unknown`

Supported chain states are `correlated`, `partially_correlated`, `weakly_correlated`, `not_correlated`, `degraded`, and `unknown`.

`ai_correlation.py` builds summary records with correlation state, chain counts, highest severity, confidence, evidence-chain summaries, recommendation summaries, risk summaries, explanation points, source modes, and safety flags.

## Evidence Chains

Evidence chains preserve only export-safe references and bounded summaries. They can reference:

- IOC inventory and match records
- DNS analytics and domain pattern records
- local signature match records
- flow summaries
- application attribution summaries
- topology summaries
- drift records
- policy evaluations
- remediation recommendations
- guardrail records
- risk dashboard summaries

The chain output keeps references sanitized and does not export raw payloads, raw DNS history, private identifiers, credentials, or packet contents.

## Deterministic Local Correlation

Phase 150 uses local deterministic aggregation rules. It does not call an AI provider or remote scoring service. The term AI correlation here means an explainable correlation layer designed for later AI-assisted workflows, not an external model call.

Correlation states are advisory:

- `correlated` means multiple local metadata signals align.
- `partially_correlated` means a smaller local signal set aligns.
- `weak_signal` means evidence exists but is limited.
- `empty` means no usable evidence was provided.
- `degraded` means malformed input was isolated.

## Safety Boundary

AI correlation does not:

- call external AI APIs
- make network requests
- inspect packet payloads
- store raw payloads
- store raw DNS history
- generate final threat verdicts
- mark entities
- execute enforcement
- modify firewall, process, or service state

Phase 151 threat scoring can consume these correlation summaries as advisory inputs while preserving the same no-verdict and no-enforcement boundary.
