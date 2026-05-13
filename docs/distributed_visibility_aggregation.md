# Distributed Visibility Aggregation

Phase 52 adds local aggregation helpers for combining visibility summaries from multiple authorized local nodes. The aggregation layer merges already-provided node reports and preserves source-node attribution for assets, services, topology edges, and findings.

This phase does not contact nodes directly and does not add cloud sync or active collection behavior.

## Node Report Shape

Node reports include:

- `node_id`
- `node_label`
- `collected_at`
- `assets`
- `services`
- `topology_edges`
- `findings`
- `metadata`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

Sanitized example:

```json
{
  "node_id": "node-sample-a",
  "node_label": "Sample Node A",
  "collected_at": "sample-time-a",
  "assets": [
    {
      "asset_id": "asset-sample",
      "label": "Sample App",
      "category": "application"
    }
  ],
  "services": [
    {
      "service_id": "service-sample",
      "asset_id": "asset-sample",
      "port": 8443,
      "service": "HTTPS"
    }
  ],
  "topology_edges": [
    {
      "edge_id": "edge-sample",
      "src": "asset-sample",
      "dst": "asset-peer",
      "relationship_type": "service_dependency"
    }
  ],
  "findings": [
    {
      "finding_id": "finding-sample",
      "title": "Sample Finding",
      "severity": "medium"
    }
  ],
  "metadata": {
    "profile": "sample"
  },
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Aggregation Helpers

Collector helpers:

- `normalize_node_report()`
- `validate_node_report()`
- `collect_node_reports()`
- `summarize_collection()`

Merger helpers:

- `merge_assets()`
- `merge_services()`
- `merge_topology_edges()`
- `merge_findings()`
- `merge_node_reports()`

Merged records preserve:

- `source_node_ids`
- `source_refs`
- `first_seen_at`
- `last_seen_at`
- `confidence`

## Conflict Records

Conflicts are reported, not hidden. Conflict records include:

- `conflict_id`
- `conflict_type`
- `affected_ref`
- `source_node_ids`
- `summary`
- `recommended_review`
- `severity`

Conflict examples include duplicate assets with conflicting labels, service name disagreements, duplicate topology edges, and differing confidence values.

## Safety Boundaries

- Local-only and operator-controlled.
- Merges already-provided reports only.
- No direct node contact.
- No external network transport.
- No cloud sync.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No write endpoints.
- No raw payload storage.

Use placeholders in public examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
