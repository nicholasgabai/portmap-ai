# Node Identity and Local Coordination

Phase 47 adds reusable local node identity and registry primitives for PortMap-AI. These helpers support stable node identity records, capability records, heartbeat metadata, lifecycle states, and operator-readable node summaries.

This phase does not replace the existing orchestrator behavior. It provides local coordination primitives for future distributed visibility and dashboard work.

## Safety Boundaries

- Local-first and operator-controlled.
- No external network transport.
- No cloud sync.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No always-on service integration in this phase.

## Node Identity

Node identity helpers provide:

- `generate_node_id()`
- `create_node_identity()`
- `save_node_identity()`
- `load_node_identity()`
- stable node identity fingerprinting
- `created_at` and `updated_at` timestamps

Sanitized example:

```json
{
  "node_id": "worker-sample",
  "role": "worker",
  "created_at": "sample-created-at",
  "updated_at": "sample-updated-at",
  "fingerprint": "sample-fingerprint",
  "metadata": {
    "profile": "sample"
  },
  "local_only": true
}
```

## Capability Records

Capability records describe what a local node can do without exposing private infrastructure details:

```json
{
  "node_id": "worker-sample",
  "role": "worker",
  "platform": "Linux",
  "architecture": "aarch64",
  "supported_features": ["visibility", "events"],
  "runtime_version": "sample-version",
  "metadata": {
    "profile": "sample"
  },
  "local_only": true
}
```

## Lifecycle States

The local registry supports these states:

- `registered`
- `online`
- `stale`
- `offline`
- `removed`

Heartbeat metadata can include:

- `last_seen_at`
- `heartbeat_count`
- `status_message`
- `health_status`
- `scheduler_status`
- `event_queue_depth`

## Registry Operations

The local registry exposes:

- `register_node`
- `update_heartbeat`
- `mark_stale_nodes`
- `list_nodes`
- `get_node`
- `remove_node`
- `summarize_nodes`

`summarize_nodes` returns operator-readable state counts and compact node summaries suitable for future local API and dashboard work.

## Sanitization Guidance

Use placeholders in examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
