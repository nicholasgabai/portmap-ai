# Active Federation Validation

Phase 86 adds validation records for active federation readiness.

This module does not open network listeners, start background daemons, execute exchange jobs, contact peers, or persist a new validation store. It builds deterministic validation summaries from existing federation runtime, peer lifecycle, exchange scheduler, diagnostics, signed exchange, synchronization, event propagation, runtime health, and operator visibility records.

## Purpose

Active federation validation answers these operator questions:

- Are trusted peer lifecycle and registry records ready?
- Are signed runtime summary exchange records valid enough for review?
- Are synchronization windows free of stale, replayed, rejected, or conflicting updates?
- Are distributed event propagation records free of duplicate, stale, malformed, or rejected events?
- Are replay-window counters within expected bounds?
- Are runtime exchange scheduler jobs ready and free of failure counters?
- Is the federation runtime manager in a reviewable state?

The output is suitable for CLI, local API, dashboard, diagnostics, and future explicit active federation runtime execution.

## Modules

- `core_engine.federation.runtime_checks`
- `core_engine.federation.validation`

The helpers reuse existing health-check and diagnostics shapes. They do not introduce a parallel validation persistence system.

## Validation Checks

Phase 86 builds these validation summaries:

- `trusted_peers`
- `signed_exchanges`
- `synchronization_window`
- `event_propagation`
- `replay_windows`
- `runtime_scheduler`
- `federation_runtime`

Each check includes:

- `status`
- `severity`
- `message`
- `details`
- `generated_at`
- explicit safety fields

Statuses use the existing federation health posture:

- `ok`
- `degraded`
- `unavailable`

## Active Validation Record

The active federation validation record includes:

- validation ID
- generated timestamp
- overall status
- validation checks
- readiness score
- summary counts
- diagnostics summary
- operator-readable recommendations
- dashboard-ready status
- local API-compatible dictionary

Safety fields remain explicit:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `local_only: true`
- `network_listener_enabled: false`
- `background_daemon_enabled: false`
- `job_execution_enabled: false`

## Sanitized Example

```json
{
  "record_type": "active_federation_validation",
  "status": "ready",
  "summary": {
    "check_count": 7,
    "degraded_count": 0,
    "unavailable_count": 0
  },
  "readiness": {
    "score": 100,
    "status": "ready"
  }
}
```

## Operator Workflow

1. Build trusted peer registry and lifecycle summaries.
2. Build runtime manager and exchange scheduler records.
3. Validate signed exchanges, synchronization windows, event propagation batches, and replay counters.
4. Review readiness score, recommendations, and dashboard/API dictionaries.
5. Only a later explicit runtime phase may execute approved exchange jobs.

Phase 86 remains validation-only. Approval does not start federation loops or contact peers.

## Validation Notes

Phase 86 validation uses sanitized fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no private identifiers, logs, screenshots, archives, database files, environment files, or runtime artifacts are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
