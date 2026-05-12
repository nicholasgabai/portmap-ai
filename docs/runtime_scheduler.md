# Continuous Local Runtime Scheduler

Phase 46 adds lightweight scheduler primitives for recurring local PortMap-AI runtime work. The scheduler is intended for future visibility refreshes, event generation, health checks, and policy review refreshes.

This phase does not wire the scheduler into always-on service execution. It provides local primitives only.

## Safety Boundaries

- Local-only and operator-controlled.
- No network transport.
- No cloud sync.
- No external export.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No always-on service integration in this phase.

## Built-In Job Types

Supported local job names:

- `health_check`
- `snapshot_refresh`
- `event_flush`
- `policy_review_refresh`

Each job tracks:

- `job_id`
- `name`
- `interval_seconds`
- `enabled`
- `last_run_at`
- `next_run_at`
- `status`
- `last_error`
- `run_count`
- `failure_count`
- `metadata`

## Python Example

```python
from core_engine.runtime import LocalRuntimeScheduler, create_runtime_job

scheduler = LocalRuntimeScheduler()
job = create_runtime_job(
    "health_check",
    interval_seconds=60,
    job_id="job-sample-health",
    metadata={"profile": "sample"},
)

scheduler.add_job(job)
scheduler.run_due_jobs_once()
status = scheduler.status()
```

The default job handler records a local-only no-op result. Future phases can pass explicit handlers for snapshot refresh, event flushing, and policy review updates.

## Failure Isolation

Job handler failures are captured in the job state:

- `status` becomes `failed`
- `last_error` stores the error message
- `failure_count` increments
- Scheduler-level failed job counters increment

Other due jobs continue running. A failed job does not crash the scheduler.

## Runtime State

The scheduler tracks:

- Scheduler status.
- Start time.
- Stop time.
- Uptime seconds.
- Executed job count.
- Failed job count.

These counters are local-only and intended for future dashboard and health views.

## Sanitized Documentation Guidance

Use placeholders in examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
