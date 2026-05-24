# Runtime Exchange Scheduler

Phase 85 adds federation exchange scheduler records for active federation planning.

This module does not start scheduler threads, open network listeners, contact peers, execute signed exchange loops, or run background daemons. It only produces deterministic job and schedule summaries that can be reviewed by operators and later wired into explicit runtime execution.

## Purpose

Runtime exchange scheduler records answer these operator questions:

- Which trusted peers have planned signed-summary exchange jobs?
- Which trusted peers have planned cluster-state synchronization jobs?
- Which trusted peers have planned distributed event propagation jobs?
- Which jobs are enabled or disabled by peer lifecycle state?
- When did each job last run and when is it next eligible to run?
- Which jobs have failure counters or last-error summaries?

The output is suitable for CLI, local API, dashboard, diagnostics, and future active federation runtime execution.

## Modules

- `core_engine.federation.exchange_jobs`
- `core_engine.federation.exchange_scheduler`

The helpers reuse the existing federation runtime manager, trusted peer lifecycle, signed exchange, synchronization, event propagation, diagnostics, runtime scheduler, runtime health, and trust record structures.

## Job Types

Supported federation exchange job types are:

- `signed_summary_exchange`
- `cluster_state_sync`
- `event_propagation`

The job records derive from existing federation runtime loop plans:

- `signed_exchange` becomes `signed_summary_exchange`
- `synchronization` becomes `cluster_state_sync`
- `event_propagation` remains `event_propagation`

## Job Records

A federation exchange job record includes:

- `job_id`
- `job_type`
- `loop_type`
- `peer_node_id`
- `trust_scope_label`
- `enabled`
- `job_status`
- `interval_seconds`
- `backoff_seconds`
- `max_backoff_seconds`
- `effective_backoff_seconds`
- `last_run_at`
- `next_run_at`
- `failure_count`
- `last_error_summary`
- `runtime_job_metadata`
- `operator_summary`

Safety fields remain explicit:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `local_only: true`
- `network_listener_enabled: false`
- `background_daemon_enabled: false`
- `job_execution_enabled: false`

## Scheduler Records

Runtime exchange scheduler summaries include:

- all planned exchange jobs
- per-peer schedule records
- job counts by type and status
- enabled and disabled job counts
- failure counters
- last-run and next-run timestamps
- dashboard-ready summaries
- local API-compatible dictionaries

Disabled, paused, expired, or revoked peer lifecycle records disable exchange jobs for that peer. Failed jobs remain visible with failure counters and last-error summaries for operator review.

## Sanitized Example

```json
{
  "record_type": "federation_exchange_job",
  "job_type": "signed_summary_exchange",
  "peer_node_id": "node-worker-example",
  "trust_scope_label": "runtime-summary",
  "enabled": true,
  "job_status": "enabled",
  "interval_seconds": 60,
  "backoff_seconds": 30,
  "failure_count": 0,
  "next_run_at": "2026-01-01T00:00:00Z"
}
```

## Operator Workflow

1. Build or load a trusted peer registry.
2. Build runtime manager loop plans for approved peers.
3. Convert loop plans into federation exchange job records.
4. Review disabled jobs, failed jobs, stale peer lifecycle states, and next-run timestamps.
5. Use future explicit runtime execution phases to run approved jobs.

Phase 85 is planning-only. It does not run the jobs it describes.

## Validation Notes

Phase 85 validation uses sanitized fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no private identifiers, logs, screenshots, archives, database files, environment files, or runtime artifacts are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
