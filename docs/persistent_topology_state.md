# Persistent Topology State

Phase 59 adds persistent topology state helpers for building topology snapshot records, summarizing topology history, and importing or exporting topology snapshots. The implementation reuses the existing topology graph helpers and local storage repository primitives; it does not create a separate persistence system.

The module is local-first and operator-controlled. It does not run scans, collect traffic, change configuration, transmit data externally, or trigger remediation.

## What It Provides

- Topology snapshot records built from existing assets, services, topology edges, and findings.
- Snapshot summaries for node, edge, service, relationship, and finding counts.
- Storage-ready snapshot payloads compatible with the existing local snapshot repository.
- Topology state and history summaries across multiple snapshots.
- JSON import/export helpers for local operator-controlled snapshot files.
- Export bundle helpers with snapshot manifests and integrity digests.

## Modules

- `core_engine.topology.snapshots`
- `core_engine.topology.state`
- `core_engine.topology.import_export`

## Snapshot Shape

Sanitized example:

```json
{
  "snapshot_type": "topology_state",
  "label": "sample-topology",
  "observed_at": "2026-01-01T00:00:00+00:00",
  "topology": {
    "nodes": [],
    "edges": [],
    "summary": {
      "node_count": 0,
      "edge_count": 0,
      "service_count": 0
    }
  },
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Build A Snapshot

```python
from core_engine.topology.snapshots import build_topology_snapshot

snapshot = build_topology_snapshot(
    assets=asset_records,
    services=service_records,
    topology_edges=edge_records,
    findings=finding_records,
    label="sample-topology",
    observed_at="2026-01-01T00:00:00+00:00",
)
```

The builder uses `core_engine.topology.graph.build_topology_graph()` to normalize nodes and edges, then wraps the graph in a storage-ready snapshot record.

## Persist A Snapshot

Use the existing `LocalStorageRepository` snapshot table:

```python
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore
from core_engine.topology.state import persist_topology_snapshot

repository = LocalStorageRepository(SQLiteStore("<operator-db-path>"))
persist_topology_snapshot(repository, snapshot)
```

This writes a topology snapshot through `repository.insert_snapshot()`. No new database or parallel persistence path is introduced.

## Import And Export

```python
from core_engine.topology.import_export import (
    export_topology_snapshot,
    import_topology_snapshot,
    write_topology_snapshot,
    load_topology_snapshot,
)

text = export_topology_snapshot(snapshot)
loaded = import_topology_snapshot(text)
write_topology_snapshot("<operator-output-file>", snapshot)
loaded_from_file = load_topology_snapshot("<operator-output-file>")
```

Import/export helpers validate snapshot structure and keep file paths out of public result payloads.

## History Summaries

```python
from core_engine.topology.state import build_topology_state

state = build_topology_state([baseline_snapshot, current_snapshot])
```

History summaries include:

- snapshot count
- first observed timestamp
- last observed timestamp
- maximum node count
- maximum edge count
- maximum service count
- total finding count

## Export Bundles

```python
from core_engine.topology.import_export import build_topology_export_bundle

bundle = build_topology_export_bundle([snapshot], label="sample-bundle")
```

Bundles include a manifest, snapshot IDs, history summary, and a digest. They are local data structures only; this phase does not send bundles anywhere.

## Safety Properties

All snapshot, state, and bundle records include:

```json
{
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Phase 59 does not add scanning, collection, enforcement, external transport, router modification, or automatic workflow execution.
