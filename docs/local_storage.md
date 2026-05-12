# Persistent Local Storage

Phase 45 adds a local SQLite storage layer for PortMap-AI event history, visibility snapshots, asset inventory records, service metadata, topology relationships, and advisory findings.

The storage layer is local-first and operator-controlled. It does not add cloud sync, network transport, external export, automatic enforcement, router changes, or background jobs.

## Stored Records

The local database initializes these tables:

- `schema_version`
- `events`
- `snapshots`
- `assets`
- `services`
- `topology_edges`
- `findings`

Structured payloads are stored as JSON text so future dashboard, API, and correlation phases can read the same records without changing the core data shape.

## Safety Defaults

- Storage is SQLite-backed and local-only.
- Database paths are operator-provided by calling code.
- Tests use temporary databases.
- No raw packet payloads are required by the storage schema.
- No automatic remediation or configuration changes are triggered by inserts.
- No external data transmission is included.

## Python Example

```python
from core_engine.events import create_event
from core_engine.storage import LocalStorageRepository, SQLiteStore

store = SQLiteStore("<LOCAL_DB_FILE>")
repository = LocalStorageRepository(store)

event = create_event(
    "system_notice",
    severity="info",
    source="storage",
    message="Sample local storage event.",
    metadata={"example": True},
)

repository.insert_event(event)
events = repository.list_events()
```

Use placeholders in public examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, or local paths.

## Sanitized Asset Example

```json
{
  "asset_id": "asset-sample-001",
  "host": "192.0.2.10",
  "status": "reachable",
  "metadata": {
    "source": "sample"
  }
}
```

`192.0.2.10` is from a documentation-only TEST-NET range and is not a local infrastructure value.

## Repository Surface

The repository provides insert/list methods for:

- Events.
- Snapshots.
- Assets.
- Services.
- Topology edges.
- Findings.

Each method stores the full JSON payload and returns decoded dictionaries on list calls. Duplicate IDs are rejected by SQLite uniqueness checks and reported as storage errors.
