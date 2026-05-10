# Threat Correlation Engine

Phase 32 adds a local threat-correlation layer that links scanner, flow, behavior, payload, service, TLS, and DPI evidence into advisory incident records. It explains why events were linked, preserves supporting evidence, and avoids remediation side effects.

## Scope

The implementation lives in `ai_agent.threat_correlation` and supports:

- Event normalization across behavior, payload, flow, scan, service, OS, TLS, and generic records.
- Repeated anomaly linking by entity.
- Suspicious scan behavior from many destination ports or peers in a short window.
- Lateral-movement indicators from administrative or file-sharing access patterns across multiple peers.
- Behavior-plus-payload chains when behavior anomalies and sensitive/suspicious payload indicators occur in the same window.
- Stable incident IDs.
- Supporting evidence summaries capped to metadata.
- Advisory severity and risk scoring.

Threat correlation produces operator-review evidence for future dashboard and recommendation phases. This phase follows the global PortMap-AI safety guarantees.

## CLI Usage

Correlate events:

```bash
portmap correlate \
  --events-json '[{"timestamp":1,"device_id":"worker-1","score":0.6,"findings":[{"type":"new_peer"}]},{"timestamp":2,"device_id":"worker-1","score":0.6,"findings":[{"type":"new_destination_port"}]},{"timestamp":3,"device_id":"worker-1","score":0.6,"findings":[{"type":"unusual_hour"}]}]' \
  --output json
```

Use a shorter correlation window:

```bash
portmap correlate --events-json '[...]' --window 120 --output json
```

## Output Fields

The command returns:

- `ok`
- `event_count`
- `incident_count`
- `incidents`
- `risk_score`
- `window_seconds`
- `raw_payload_stored`
- `model`

Each incident includes:

- `incident_id`
- `type`
- `severity`
- `score`
- `entity`
- `event_count`
- `first_seen`
- `last_seen`
- `peers`
- `ports`
- `findings`
- `event_ids`
- `explanation`
- `supporting_evidence`

Supporting evidence contains event IDs, event kind, score, severity, and a metadata summary. Raw payload bytes are not stored.

## Developer API

```python
from ai_agent.threat_correlation import correlate_events, normalize_event

event = normalize_event(raw_event)
report = correlate_events(events, window_seconds=300)
```

Inputs can be direct behavior analyses, payload classifications, flow records, scan rows, service detections, or records with nested `metadata`.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. Threat correlation stores no raw payload bytes in incident output.

Future recommendation and remediation phases should consume these incidents as advisory evidence and keep operator approval requirements intact.
