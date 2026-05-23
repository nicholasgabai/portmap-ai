# Live Cluster State Synchronization

Phase 79 adds local synchronization-window models for trusted signed summary envelopes. The helpers verify exchange metadata, classify updates, track per-node replay state, and build deterministic merged cluster summaries.

This phase does not open network listeners, poll peers, persist records, or execute remote commands.

## Scope

The implementation provides:

- synchronization window records
- cluster state update envelopes
- accepted, rejected, stale, replayed, untrusted, and malformed update classification
- signed summary verification integration
- replay-window validation integration
- per-node last accepted sequence tracking
- per-node last digest tracking
- last-seen update summaries
- conflict and drift records
- deterministic merged cluster state summaries
- dashboard/API-ready sync status records

The helpers reuse the existing trusted transport, trust profile, signed exchange, distributed node state, cluster health, topology, review, export, and operator visibility structures.

## Synchronization Window

`build_synchronization_window()` creates a local window record with:

- `window_id`
- `opened_at`
- `closes_at`
- `replay_window_seconds`
- `trusted_node_ids`
- `runtime_session_ref`
- `last_sequence_by_node`
- `last_digest_by_node`
- `seen_nonces`

The record is local state only. It does not start background polling or create a persistence system.

## Applying Updates

`apply_signed_summary_updates()` accepts already-provided signed summary envelopes and:

1. Finds the matching trusted transport session.
2. Validates the envelope with the Phase 78 verification hooks.
3. Applies replay-window checks using window nonce and sequence state.
4. Classifies each update.
5. Updates last sequence, digest, nonce, and last-seen records for accepted updates.
6. Produces conflict records for rejected updates.
7. Produces drift records when an accepted digest changes for a node and trust scope.
8. Builds a deterministic merged cluster state.

Accepted runtime-summary updates are merged through existing distributed node-state helpers.

## Dashboard And API Status

`build_cluster_sync_dashboard_status()` produces API-compatible status data for future local dashboards:

- update counts
- stale/replayed/rejected counts
- source node count
- merged runtime node count
- conflict and drift counts
- review recommendation flag

The output remains read-only and remote-control disabled.

## Safety Boundaries

Phase 79 remains:

- local-first
- trusted-node scoped
- operator-approved
- source-attributed
- replay-window aware
- advisory by default
- remote-control disabled

It does not add live network listeners, public exposure, untrusted discovery, automatic remediation, service installation, cloud sync, or external transmission.
