# Trusted Peer Lifecycle

Phase 84 adds local trusted peer lifecycle records and registry summaries for the active federation runtime path.

This module does not open network listeners, start background workers, execute federation exchange loops, or store private signing material. It only normalizes operator-approved peer records into deterministic lifecycle and registry summaries.

## Purpose

Trusted peer lifecycle records answer these operator questions:

- Which trusted peers are enrolled, approved, paused, revoked, or expired?
- Which trust scopes are currently assigned to each peer?
- Which transport session records are linked to each peer?
- When was each peer last seen or last verified?
- Which peer records require review because they are stale, expired, or revoked?

The output is suitable for CLI, local API, dashboard, diagnostics, and future federation runtime scheduling.

## Modules

- `core_engine.federation.peer_lifecycle`
- `core_engine.federation.peer_registry`

The helpers reuse the existing federation trust, transport, runtime manager, signing/exchange, synchronization, diagnostics, node identity, and distributed node state record patterns.

## Lifecycle States

Trusted peer lifecycle states are:

- `enrolled`
- `approved`
- `paused`
- `revoked`
- `expired`

Supported transition actions are:

- `enroll`
- `approve`
- `pause`
- `resume`
- `revoke`
- `expire`
- `update_scopes`

Invalid transitions are rejected with structured validation output. Revoked and expired peers are terminal in the baseline model.

## Peer Lifecycle Records

A lifecycle record includes:

- `peer_lifecycle_record_id`
- `peer_id`
- `node_id`
- `node_role`
- `lifecycle_state`
- `trust_scope_labels`
- `transport_session_ids`
- `last_seen_at`
- `last_verified_at`
- `approved_at`
- `expires_at`
- `source_refs`
- `validation`
- `lifecycle_history`
- `operator_summary`

Safety fields remain present:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `local_only: true`
- `network_listener_created: false`
- `background_daemon_started: false`

## Registry Records

A trusted peer registry record combines lifecycle records, trust profile peers, and transport session references into a local summary.

Registry output includes:

- peer counts by lifecycle state
- stale, expired, and revoked peer summaries
- transport session linkage counts
- dashboard-ready rows
- local API-compatible dictionaries
- review-required status when operator attention is needed

The registry does not persist a new peer database. Callers may store the resulting records through existing storage and export paths when a later phase explicitly wires that behavior.

## Operator Workflow

1. Load a local trust profile with placeholder or operator-approved trusted peers.
2. Build peer lifecycle records from the approved peer records.
3. Apply explicit lifecycle transitions such as approve, pause, resume, revoke, expire, or update trust scopes.
4. Build a registry summary from lifecycle records and existing transport sessions.
5. Review stale, expired, revoked, or invalid peers before future federation exchange loops use them.

Approval remains a local peer state change only. It does not contact the peer, open a listener, start a daemon, or enable exchange scheduling.

## Sanitized Example

```json
{
  "peer_id": "peer-node-worker-example",
  "node_id": "node-worker-example",
  "node_role": "worker",
  "lifecycle_state": "approved",
  "trust_scope_labels": ["runtime-summary", "cluster-health"],
  "transport_session_ids": ["transport-session-example"],
  "last_seen_at": "2026-01-01T00:00:00Z",
  "last_verified_at": "2026-01-01T00:00:00Z",
  "operator_summary": "Peer node-worker-example is approved with 2 trust scope(s)."
}
```

## Validation Notes

Phase 84 validation uses sanitized fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no private identifiers, logs, screenshots, archives, database files, environment files, or runtime artifacts are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
