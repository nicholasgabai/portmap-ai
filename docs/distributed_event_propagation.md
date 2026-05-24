# Distributed Event Propagation

Phase 80 adds local distributed event propagation records for trusted federation. The helpers wrap existing `LocalEvent` records in source-attributed, replay-aware propagation envelopes and validate them through the trusted signed exchange path.

This phase does not open network listeners, contact peers, persist events, or execute remote commands.

## Scope

The implementation provides:

- distributed event envelope records
- event propagation window records
- source and destination node attribution
- event sequence numbers
- deterministic event digest summaries
- accepted, rejected, stale, duplicate, malformed, and untrusted classification
- replay-window integration
- signed exchange verification integration
- event batch summaries
- cluster event rollups
- dashboard/API-ready event propagation summaries

The event payload remains the existing local event dictionary shape. No parallel event schema or persistence system is introduced.

## Event Window

`build_event_propagation_window()` creates a local window with:

- `window_id`
- `opened_at`
- `closes_at`
- `trusted_node_ids`
- `last_sequence_by_node`
- `last_event_digest_by_node`
- `seen_event_digests`
- `seen_nonces`
- `runtime_session_ref`

The window is an in-memory-compatible record. Operators can persist it later through existing storage workflows if explicitly wired by a future phase.

## Event Envelope

`build_distributed_event_envelope()` accepts a `LocalEvent` or existing event dictionary and builds:

- `distributed_event_envelope`
- event digest
- event sequence and nonce
- source and destination node fields
- signed exchange envelope with `event-summary` trust scope
- local-event-storage-ready metadata

The signed exchange envelope reuses Phase 78 canonical digest, signature metadata, trust profile validation, and replay-window metadata.

## Batch Application

`apply_distributed_event_batch()` verifies already-provided event envelopes and classifies each record:

- `accepted`
- `rejected`
- `stale`
- `duplicate`
- `malformed`
- `untrusted`

Accepted events update the window's last sequence, last event digest, seen nonce, and last-seen event records. Rejected events preserve source attribution and classification reasons.

## Rollups

The batch result includes:

- accepted event records
- rejected event records
- cluster event rollup by source node
- dashboard/API status
- deterministic summary counts

These records are suitable for future cluster health and operator visibility panels without replacing the Textual TUI.

## Safety Boundaries

Phase 80 remains:

- local-first
- trusted-node scoped
- operator-approved
- advisory by default
- source-attributed
- replay-window aware
- remote-control disabled

It does not add live network listeners, public exposure, untrusted discovery, automatic remediation, service installation, cloud sync, external transmission, or a parallel event persistence system.
