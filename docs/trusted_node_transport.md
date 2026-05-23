# Trusted Node Transport Models

Phase 77 adds local trusted-node transport records for Milestone M. These records describe which operator-approved nodes may exchange runtime summaries in future federation workflows.

This phase is model-only. It does not open network listeners, contact peers, create cryptographic signatures, execute remote commands, install services, or transmit data.

## Scope

The implementation provides:

- local node trust profiles
- approved peer records
- trusted transport session records
- handshake summary records
- expiration timestamps
- trust scope labels
- source and destination node attribution
- replay-window metadata
- deterministic JSON serialization helpers

The models reuse existing node identity, distributed runtime state, runtime session, profile, health, and operator visibility structures by reference.

## Trust Profile

`core_engine.federation.trust.build_local_node_trust_profile()` creates a local trust profile for one source node. A profile includes:

- `local_node`
- `approved_peers`
- `trust_scope_labels`
- `default_transport_modes`
- `replay_window_seconds`
- `source_refs`
- safety fields such as `network_listener_enabled: false`, `cryptographic_signing_enabled: false`, and `remote_control_enabled: false`

Approved peers are explicit operator-controlled records. A peer can be approved for selected scopes such as:

- `runtime-summary`
- `health-summary`
- `topology-summary`
- `review-summary`
- `export-summary`
- `operator-visibility`
- `service-readiness`

## Transport Session

`core_engine.federation.transport.create_trusted_transport_session()` creates a session record between a source node and an approved destination node.

Session records include:

- `session_id`
- `source_node_id`
- `destination_node_id`
- `transport_mode`
- `status`
- `trust_scope_label`
- `started_at`
- `expires_at`
- `handshake_summary`
- `replay_window`

Transport modes are labels only in this phase:

- `local-file`
- `loopback-api`
- `trusted-lan-preview`

No socket is opened and no peer is contacted.

## Replay Window Metadata

Replay-window metadata records the permitted local validation window for future exchanged summaries. It includes:

- `window_started_at`
- `window_expires_at`
- `replay_window_seconds`
- `accepted_sequence_floor`
- `accepted_sequence_ceiling`
- `nonce_required`
- `replay_safe_records`

Phase 77 does not validate signatures or nonce values. Later phases can use these metadata fields when signed exchange records are added.

## Example

```json
{
  "record_type": "trusted_node_transport_session",
  "source_node_id": "node-master",
  "destination_node_id": "node-worker-a",
  "transport_mode": "local-file",
  "trust_scope_label": "runtime-summary",
  "status": "planned",
  "network_listener_enabled": false,
  "cryptographic_signing_enabled": false,
  "remote_control_enabled": false
}
```

All examples use sanitized node IDs and placeholders only.

## Validation

Phase 77 tests cover:

- trust profile construction
- approved peer scope and transport checks
- trusted transport session creation
- handshake summary records
- replay-window metadata
- unapproved peer rejection
- deterministic JSON serialization
- private identifier scanning

## Safety Boundaries

These helpers remain:

- local-first
- trusted-node scoped
- operator-approved
- advisory by default
- source-attributed
- replay-window aware
- remote-control disabled

They do not add discovery, public exposure, background collection, automatic enforcement, service installation, remote execution, cryptographic signing, or external transport.
