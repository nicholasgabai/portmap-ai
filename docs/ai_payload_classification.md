# AI Payload Classification

Phase 31 adds a local payload classification layer for safe payload observations and DPI-derived metadata. It labels payloads, detects suspicious content markers, identifies protocol misuse, and reports aggregate beaconing or possible exfiltration indicators without storing raw payload bytes by default.

## Scope

The implementation lives in `ai_agent.payload_classifier` and supports:

- Single-observation and batch payload classification.
- Input from `payload_text`, `payload_hex`, `payload_b64`, or existing safe payload metadata.
- Redacted optional previews for operator review.
- Credential marker detection.
- Script, SQL injection, and command marker detection.
- High-entropy and large-payload review signals.
- Protocol misuse signals, such as HTTP-looking payloads labeled as TLS.
- Possible tunneled payload indicators.
- Possible exfiltration indicators based on high-entropy public-destination payload metadata and aggregate public-destination volume.
- Beaconing candidates from regular small-payload timing patterns.
- Confidence and risk scores for downstream review and future correlation.

Payload classification is advisory. This phase follows the global PortMap-AI safety guarantees and stores no raw payload bytes by default.

## CLI Usage

Classify one observation:

```bash
portmap payload \
  --events-json '{"protocol":"HTTP","payload_text":"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret"}' \
  --output json
```

Classify a list of observations:

```bash
portmap payload \
  --events-json '[{"timestamp":10,"session_key":"flow-1","payload":{"length":100}},{"timestamp":20,"session_key":"flow-1","payload":{"length":100}},{"timestamp":30,"session_key":"flow-1","payload":{"length":100}},{"timestamp":40,"session_key":"flow-1","payload":{"length":100}}]' \
  --output json
```

Include a short redacted preview:

```bash
portmap payload \
  --events-json '{"protocol":"HTTP","payload_text":"GET /?token=secret HTTP/1.1\r\nHost: local\r\n\r\n"}' \
  --include-payload-preview \
  --output json
```

## Output Fields

The command returns:

- `ok`
- `classification_count`
- `classifications`
- `aggregate_findings`
- `risk_score`
- `raw_payload_stored`
- `model`

Each classification includes:

- `label`
- `confidence`
- `risk_score`
- `protocol`
- `network`
- safe `payload` metadata
- `findings`
- `raw_payload_stored`

Raw payload bytes are not emitted. Optional previews are bounded and redacted.

## Developer API

```python
from ai_agent.payload_classifier import classify_payload_events, classify_payload_observation

single = classify_payload_observation({
    "protocol": "HTTP",
    "payload_text": "GET / HTTP/1.1\r\nHost: local\r\n\r\n",
})

batch = classify_payload_events([single_observation, another_observation])
```

Inputs can be direct payload observations, Phase 27 DPI payload metadata, or Phase 29 flow/capture context with nested `metadata`.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. Payload classification stores no raw payload bytes in default output.

Future threat-correlation phases should consume these classifications as advisory evidence alongside behavior, flow, TLS, service, and scanner findings.
