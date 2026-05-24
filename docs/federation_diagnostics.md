# Federation Diagnostics

Phase 81 adds local diagnostics for trusted runtime federation. The diagnostics summarize trusted peer readiness, transport sessions, signed exchange verification, synchronization windows, distributed event propagation, replay-window counters, and distributed runtime health.

This phase does not open network listeners, contact peers, persist records, execute remote commands, or create a parallel health system.

## Scope

The implementation provides:

- federation diagnostic summary records
- trusted peer status summaries
- transport session health summaries
- signed exchange verification summaries
- synchronization window health summaries
- distributed event propagation health summaries
- replay-window status summaries
- stale, duplicate, replayed, malformed, and rejected counters
- federation readiness score
- operator-readable diagnostic recommendations
- dashboard/API-ready federation health records
- local runtime-health event records

The helpers reuse existing trust profiles, transport sessions, signed exchanges, synchronization windows, event propagation batches, distributed node state, cluster health, and operator visibility structures.

## Health Checks

`core_engine.federation.health.build_federation_health_summary()` builds a deterministic health record with checks for:

- `trusted_peers`
- `transport_sessions`
- `signed_exchanges`
- `synchronization_window`
- `distributed_events`
- `replay_windows`
- `distributed_runtime`

Each check uses the same local-only safety fields used by the rest of the federation models.

## Diagnostics

`core_engine.federation.diagnostics.build_federation_diagnostics()` combines health checks with:

- readiness scoring
- operator recommendations
- dashboard status records
- API-compatible dictionaries
- a local runtime-health event

Recommendations are advisory only. They never trigger remediation, remote execution, listener startup, or configuration changes.

## Readiness Score

The readiness score starts at 100 and subtracts for degraded, unavailable, high-severity, or critical checks. Thresholds are configurable, and Raspberry Pi-friendly thresholds are available through `edge_device=True`.

## Dashboard And API Records

Dashboard/API output includes:

- readiness score
- degraded and unavailable check counts
- rejected update count
- stale update count
- replayed update count
- duplicate event count
- rejected event count
- recommendation count

The output is suitable for future local dashboard/API views without replacing the Textual TUI.

## Safety Boundaries

Phase 81 remains:

- local-first
- trusted-node scoped
- operator-approved
- advisory by default
- source-attributed
- replay-window aware
- remote-control disabled

It does not add live network listeners, public exposure, untrusted discovery, automatic remediation, service installation, cloud sync, external transmission, or a separate persistence system.
