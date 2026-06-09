# Phase 151 - Threat Scoring Expansion

Phase 151 adds metadata-only advisory threat scoring records for Milestone Y. The scoring layer combines local IOC intelligence, DNS analytics, signature matches, AI correlation chains, flow behavior, attribution confidence, drift, topology, runtime health, remediation previews, and safety guardrails into bounded operator-facing risk scores.

This layer is advisory only. It does not generate final threat verdicts, assign malicious labels, execute enforcement, change firewall rules, stop processes, disable services, call external feeds, call AI APIs, inspect packet payloads, store raw payloads, or retain raw DNS history.

## Model Scope

The implementation lives in:

- `core_engine/intelligence/scoring_weights.py`
- `core_engine/intelligence/threat_scoring.py`

`ScoringWeightProfile` defines the local advisory weighting profile. The default profile includes weights for IOC, DNS, signature, correlation, flow, attribution, drift, topology, runtime health, remediation, and guardrail signals. Weight values and confidence bounds are normalized into safe ranges before scoring.

`AdvisoryThreatScoringRecord` is the export-safe scoring result. It includes:

- `advisory_score` bounded from `0.0` to `1.0`
- `confidence_score` bounded from `0.0` to `1.0`
- `scoring_state` values of `low`, `moderate`, `elevated`, `high`, `degraded`, `empty`, or `unknown`
- `severity_level` as an operator-facing severity label
- category-level score breakdowns
- supporting references for IOC, DNS, signature, correlation, flow, attribution, drift, topology, runtime, remediation, and guardrail records
- explanation points and a recommended next step
- `preview_only: true`
- `destructive_action: false`

## Advisory Score Versus Verdict

The `advisory_score` is a local risk-prioritization value. It helps an operator decide which evidence chain or dashboard card deserves review first. It is not a final threat verdict and does not mark an entity, domain, service, process, node, or flow as malicious.

The score uses local metadata supplied by callers. It is deterministic for the same inputs and does not perform reputation checks, feed downloads, model calls, DNS lookups, packet inspection, or payload analysis.

## Confidence Aggregation

Each input contributes a signal score and confidence score. Category weights scale the category contribution, and confidence floors or ceilings can dampen or cap the final confidence. Low-confidence evidence can still appear in the breakdown, but it does not become an enforcement decision.

Empty inputs produce an `empty` scoring record. Malformed-only inputs produce a `degraded` scoring record with an operator next step to collect more metadata.

## Future Phase 152 Consumption

Phase 152 threat-hunting query models can consume Phase 151 scoring records as local filter and ranking inputs. Hunting queries should continue to use score records as advisory metadata, not as blocking rules or final determinations.

## Safety Boundary

Phase 151 guarantees:

- no final threat verdict fields
- no malicious labels
- no enforcement execution
- no firewall, process, or service changes
- no external feeds, DNS lookups, or AI calls
- no packet payload inspection or storage
- no raw DNS history storage
- no private identifiers in exported records
- preview-only, export-safe serialization
