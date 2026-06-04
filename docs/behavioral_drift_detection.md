# Behavioral Drift Detection

Phase 133 adds metadata-only behavioral drift detection for comparing current observations against local historical baselines. It helps operators see when learned application, service, destination, flow, topology, or protocol behavior is changing without treating drift as a threat verdict.

This feature is advisory-only. It does not inspect packet payloads, store packets, generate PCAP files, store credentials, retain raw DNS browsing history, block traffic, modify firewall rules, or perform remediation.

## Drift Records

`core_engine.behavior.drift_detection` builds deterministic drift records with:

- `drift_id`
- `drift_class`
- `baseline_reference`
- `current_reference`
- `drift_score`
- `drift_severity`
- `recurrence_state`
- `confidence_score`
- `source_mode`
- `advisory_notes`

Supported drift classes are:

- `application_behavior`
- `service_behavior`
- `destination_behavior`
- `flow_behavior`
- `topology_behavior`
- `protocol_behavior`
- `unknown`

Supported states are:

- `stable`
- `minor_drift`
- `moderate_drift`
- `major_drift`
- `unknown`

The evidence summary compares bounded metadata fields such as normalized scores, rolling frequency, and behavior labels. It intentionally omits payloads, raw packet bytes, raw DNS contents, host identifiers, user identifiers, and credentials.

## Baseline Comparison

Drift scoring is based on local metadata-only signals:

- score changes between baseline and current observations
- frequency changes
- label changes
- novelty indicators
- explicit local drift flags
- recurrence state

Confidence scoring considers whether both baseline and current records are present, whether recurrence is visible, and how strong the measured drift is. Scores are deterministic and bounded from `0.0` to `1.0`.

## Environment Drift

`core_engine.behavior.environment_drift` aggregates individual drift records into environment-level summaries:

- affected behavior categories
- stability score
- drift trend
- recurring change detection
- unusual change detection
- confidence score
- operator summary
- dashboard/API-safe records

Environment drift output is suitable for local dashboards, APIs, exports, and offline operator review. It does not create a threat verdict and does not trigger enforcement.

## Drift Is Not A Threat Verdict

Behavioral drift means observed metadata differs from the local baseline. It can be benign, expected, temporary, misconfigured, incomplete, or worth review. Phase 133 deliberately separates drift detection from threat detection.

Future threat-detection work can use drift records as one advisory input, but this phase only reports change and confidence. Operators remain responsible for reviewing context before taking action.

## Safety Boundaries

Phase 133 preserves the PortMap-AI safety model:

- local-first
- metadata-only
- advisory-only
- read-only
- source-mode aware
- export-safe
- no payload inspection
- no raw packet storage
- no PCAP generation
- no credential storage
- no raw DNS browsing-history storage
- no threat verdicts
- no blocking or automatic remediation

Public examples should use sanitized placeholders such as `baseline-redacted-service` and `current-redacted-service`.
