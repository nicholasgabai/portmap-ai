# Temporal Anomaly Windows

Phase 106 adds advisory time-window anomaly summaries on top of local historical behavior baselines.

The anomaly layer is metadata-only, local-first, dry-run safe, and bounded. It does not store packet payloads, credentials, packet captures, raw DNS payloads, or enforcement actions. It does not call external reputation services, modify firewall rules, or trigger remediation.

## Window Records

Temporal anomaly records reuse Phase 105 baseline windows and summarize:

- `short`
- `medium`
- `long`

Each anomaly window includes retained observation counts, observation rates, category counts, bounded key counts, novel key counts, stable key counts, rare key counts, and dropped key counts.

## Detection Summaries

The report builder emits advisory labels for:

- `burst_detected`
- `rare_service_timing`
- `volume_drift_hint`
- `new_behavior_in_window`
- `malformed_baseline_input`

Labels are baseline-aware and review-oriented. They do not create blocking, firewall, remediation, or service-management actions.

## Confidence And Explanations

Anomaly confidence is deterministic and based on:

- baseline entry confidence
- short-window to historical-window ratio
- anomaly label type
- observed recurrence and novelty state

Each anomaly includes an operator-readable explanation and bounded evidence fields such as observed counts, expected counts, behavior state, and window name.

## Operator Surfaces

Temporal anomaly reports include:

- anomaly window records
- anomaly records
- summary counts by label and window
- dashboard-safe dictionaries
- API-safe dictionaries
- export-ready summaries with deterministic digests

The live telemetry operator summary can include a `temporal_anomalies` panel when a temporal anomaly report is supplied. Existing telemetry dashboards remain unchanged when no anomaly report is provided.

## Safety Boundaries

Phase 106 does not:

- store raw packet payloads
- store credentials
- store full packet captures
- call external reputation services
- create enforcement actions
- trigger firewall changes
- execute remediation
- start collectors or services
- create unbounded in-memory windows

## Sanitized Flow

```text
historical baseline report
  -> short, medium, and long anomaly windows
  -> burst, rarity, drift, and novelty labels
  -> advisory confidence and explanation records
  -> dashboard/API/export-ready summaries
```

Public examples must use sanitized fixture addresses, domains, service names, node IDs, and process labels only.
