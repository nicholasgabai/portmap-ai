# AI Behavioral Learning

Phase 30 adds a local behavioral baseline layer for device and flow observations. It learns normal destination ports, peers, application protocols, transports, and time-of-day buckets, then scores new observations against that baseline for operator review.

## Scope

The implementation lives in:

- `ai_agent.baseline_store`
- `ai_agent.behavior_model`

It supports:

- Local JSON baseline storage under `~/.portmap-ai/data/behavior_baseline.json` by default.
- Offline analysis from packet, flow, service, scan, or DPI-derived JSON records.
- Optional learning only when `--learn` is explicitly provided.
- Per-device profiles with event counts, common ports, common peers, common application protocols, transports, and active hour buckets.
- Anomaly findings for new devices, new destination ports, new peers, new application protocols, unusual hours, rare values, and low-confidence baselines.
- JSON-serializable analysis results for CLI, future dashboard views, and future threat-correlation phases.

Behavioral learning is advisory. This phase follows the global PortMap-AI safety guarantees and stores no raw payload bytes.

## CLI Usage

Analyze events without changing the baseline:

```bash
portmap behavior \
  --events-json '[{"device_id":"worker-1","metadata":{"protocol":"TCP","dst_ip":"10.0.0.10","dst_port":443},"application_protocol":"TLS"}]' \
  --output json
```

Analyze and learn from the same events:

```bash
portmap behavior \
  --events-json '[{"device_id":"worker-1","metadata":{"protocol":"TCP","dst_ip":"10.0.0.10","dst_port":443},"application_protocol":"TLS"}]' \
  --learn \
  --output json
```

Use a specific baseline path:

```bash
portmap behavior --baseline ./artifacts/behavior_baseline.json --events-json '[...]' --learn --output json
```

## Output Fields

The command returns:

- `ok`
- `analysis_count`
- `analyses`
- `baseline_updated`
- `baseline`
- optional `baseline_path` when learning writes a baseline

Each analysis includes:

- `device_id`
- normalized `observation`
- `status`
- `score`
- `findings`
- `baseline_event_count`
- `model`
- `raw_payload_stored`

Scores are advisory review signals. They do not imply automatic remediation.

## Developer API

```python
from ai_agent.baseline_store import load_baseline, save_baseline
from ai_agent.behavior_model import analyze_events, update_baseline

baseline = load_baseline()
result = analyze_events(events, baseline, learn=False)
updated = update_baseline(baseline, events)
save_baseline(updated)
```

Inputs can be Phase 29 flow records, packet metadata, DPI records, or rows with a nested `metadata` object. Raw payloads are not required and are not retained.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. Behavioral learning stores no raw payload bytes in analysis output or baselines.

Future payload classification and threat-correlation phases should consume these behavior summaries as advisory evidence alongside scanner, DPI, TLS, and flow records.
