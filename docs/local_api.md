# Local API Layer

Phase 48 adds reusable local read-only API primitives for future PortMap-AI dashboard and operator tooling work. The local API can expose event history, asset inventory, visibility snapshots, node summaries, and topology relationships from in-memory providers or local storage abstractions.

This API layer does not replace the existing orchestrator API.

## Default Binding

The default documented bind address is localhost:

```text
127.0.0.1:9200
```

Operators may configure a host and port in future integrations, but localhost remains the default posture.

## Endpoints

Read-only JSON endpoints:

- `GET /health`
- `GET /events`
- `GET /assets`
- `GET /snapshots`
- `GET /nodes`
- `GET /topology`

There are no write endpoints in Phase 48.

## Response Shape

Collection endpoints return:

```json
{
  "status": "ok",
  "count": 1,
  "items": [
    {
      "id": "sample-item"
    }
  ],
  "generated_at": "sample-generated-at",
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Health responses include local bind information:

```json
{
  "status": "ok",
  "generated_at": "sample-generated-at",
  "bind_host": "127.0.0.1",
  "port": 9200,
  "local_only": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Python Example

```python
from core_engine.api import create_local_api_app

app = create_local_api_app(
    events=[{"event_id": "event-sample"}],
    assets=[{"asset_id": "asset-sample"}],
    snapshots=[{"snapshot_id": "snapshot-sample"}],
    topology_edges=[{"edge_id": "edge-sample"}],
)

status, payload = app.get("/events")
```

## Safety Boundaries

- Local-first and operator-controlled.
- Read-only endpoints only.
- No external network transport beyond the local listener used by an operator.
- No cloud sync.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No dependency on a running orchestrator for unit tests.

## Sanitization Guidance

Use placeholders in examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
