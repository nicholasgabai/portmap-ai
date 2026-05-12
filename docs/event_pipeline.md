# Local Event Pipeline

PortMap-AI uses a local-only event model to normalize visibility observations, service metadata, flow summaries, snapshots, baseline deltas, operator review records, policy review prompts, runtime health notices, and system notices.

The Phase 44 event pipeline is intentionally in-process and advisory. It does not open network transports, export data, modify routers, change host configuration, execute remediation, start scans, or sync with a cloud service.

## Event Shape

Each event contains:

- `event_id`
- `event_type`
- `severity`
- `source`
- `timestamp`
- `message`
- Optional references for assets, services, flows, snapshots, findings
- `metadata`
- `raw_payload_stored`
- `automatic_changes`
- `administrator_controlled`

Safety defaults:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

## Event Types

Supported local event types:

- `asset_observed`
- `service_observed`
- `flow_observed`
- `snapshot_created`
- `baseline_delta_detected`
- `operator_review_created`
- `policy_review_required`
- `runtime_health`
- `system_notice`

Supported severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`

## Sanitized Example

```json
{
  "event_id": "evt-sample",
  "event_type": "asset_observed",
  "severity": "low",
  "source": "visibility",
  "timestamp": "sample-timestamp",
  "message": "Sample asset observed in local visibility evidence.",
  "asset_ref": "asset-sample-001",
  "service_ref": null,
  "flow_ref": null,
  "snapshot_ref": "snapshot-sample-001",
  "finding_ref": null,
  "metadata": {
    "example_network": "TEST-NET",
    "operator_review": true
  },
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

The example uses placeholders only. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, or local paths in event examples.

## Python Usage

```python
from core_engine.events import LocalEventBus, create_event, event_to_json

bus = LocalEventBus()
events = []
bus.subscribe(events.append, event_type="snapshot_created")

event = create_event(
    "snapshot_created",
    severity="info",
    source="visibility",
    message="Sample visibility snapshot created.",
    snapshot_ref="snapshot-sample-001",
    metadata={"operator_review": True},
)

bus.publish(event)
payload = event_to_json(event)
```

Publishing stores the event in the in-memory queue and delivers it to matching in-process subscribers. Subscriber failures are isolated so one failing handler does not prevent other handlers from receiving the event.

## Queue and Replay

`LocalEventQueue` provides FIFO consume/drain behavior for in-process workflows. `LocalEventBus` also retains bounded in-memory history for replay into subscribers or a one-off handler.

Replay is local-only and memory-backed in Phase 44. Durable event history belongs to the planned local storage phase.

## Safety Boundaries

- No external transport is included.
- No cloud sync is included.
- No automatic enforcement is included.
- No router or firewall modification is included.
- No background scanning is included.
- Raw payload bytes are not stored by the event model.
