# Runtime Health Monitor

The runtime health monitor builds local health summaries for PortMap-AI runtime components. It is an inspection layer only. It does not start services, run background collection, execute remediation, perform active probing, or transmit data externally.

## Checks

The monitor can summarize:

- Local storage repository readability and record counts.
- Local event queue depth.
- Scheduler status and failed job counts.
- Operator review queue status.
- Dashboard provider readiness.
- Operational export readiness.
- Runtime session status.
- Resource budget warnings for default and edge-device profiles.

## Health Events

Health summaries include a normalized `runtime_health` event suitable for local event storage:

```json
{
  "event_type": "runtime_health",
  "severity": "info",
  "source": "runtime.health",
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

The event is created in memory. Persisting it remains an explicit operator-controlled workflow.

## Example

```python
from core_engine.runtime import build_runtime_health_summary

summary = build_runtime_health_summary(
    generated_at="2026-01-01T00:00:00+00:00"
)
```

Example summary shape:

```json
{
  "status": "ok",
  "summary": {
    "check_count": 7
  },
  "automatic_changes": false,
  "administrator_controlled": true,
  "raw_payload_stored": false
}
```

## Raspberry Pi Thresholds

Use `edge_device=True` to apply more conservative thresholds for event queue depth, storage record counts, and pending review counts. These thresholds are intended for Raspberry Pi and other lightweight Linux deployments.

## Safety Notes

Runtime health checks are local and read-only. They do not:

- Probe networks.
- Modify configuration.
- Install, enable, start, or stop services.
- Execute plugins.
- Execute remediation.
- Send data to external systems.
