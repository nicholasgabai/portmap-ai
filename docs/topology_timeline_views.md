# Topology and Timeline Views

Phase 50 adds reusable topology graph and historical timeline view models for local dashboard and operator reporting layers.

These helpers consume existing local evidence such as assets, services, topology edges, visibility snapshots, local events, and baseline delta findings. They do not collect new data.

## Topology Graph

`build_topology_graph()` can normalize:

- Asset inventory rows.
- Service metadata rows.
- Topology edge rows.
- Visibility snapshots.
- Local API-compatible dictionaries.

Graph output includes:

- `nodes`
- `edges`
- `node_count`
- `edge_count`
- `service_count`
- `relationship_count`
- `generated_at`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

Sanitized example:

```json
{
  "nodes": [
    {
      "asset_id": "asset-sample-a",
      "label": "Sample App",
      "category": "application",
      "service_count": 1,
      "finding_count": 0,
      "confidence": 0.8,
      "source_refs": ["asset:asset-sample-a"]
    }
  ],
  "edges": [
    {
      "source_asset": "asset-sample-a",
      "target_asset": "asset-sample-b",
      "relationship_type": "service_dependency",
      "protocol_service_label": "TLS",
      "observation_count": 2,
      "confidence": 0.85,
      "source_refs": ["edge:edge-sample"]
    }
  ],
  "node_count": 2,
  "edge_count": 1,
  "service_count": 2,
  "relationship_count": 2,
  "generated_at": "sample-generated-at",
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Timeline Entries

`build_timeline_entries()` converts local events, baseline deltas, and findings into operator-readable timeline rows.

Timeline entries include:

- `timeline_id`
- `timestamp`
- `category`
- `severity`
- `title`
- `summary`
- optional asset, service, and snapshot references
- `source_refs`
- `recommended_review`

`summarize_timeline()` groups entries by severity and category and reports the highest observed severity.

## Safety Boundaries

- Local-only and read-only.
- No external network transport.
- No cloud sync.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No write endpoints.
- No raw payload storage.

Use placeholders in public examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
