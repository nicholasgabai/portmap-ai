# Distributed Cluster Scanning

Phase 39 adds local distributed scan planning primitives for multi-worker PortMap-AI deployments. The feature is a control-plane foundation: it creates bounded scan jobs and worker assignments, but it does not execute scans by itself. This phase follows the global PortMap-AI safety guarantees.

## Scope

The cluster layer includes:

- `core_engine.cluster.worker_registry` for worker health, capabilities, stale status, and available capacity.
- `core_engine.cluster.job_queue` for scan jobs, task assignment, retry state, and result aggregation.
- `core_engine.cluster.scheduler` for partitioning authorized targets and ports into distributed TCP connect-scan tasks.
- `portmap cluster plan` for dry-run scan planning from the CLI.

This phase prepares for future orchestrator-backed distributed execution without changing the current worker heartbeat/remediation behavior.

## CLI Usage

Create a dry-run distributed scan plan:

```bash
portmap cluster plan \
  --target 127.0.0.1 \
  --ports 80,443 \
  --worker worker-a@10.0.0.2 \
  --worker worker-b@10.0.0.3 \
  --output json
```

Pass worker records as JSON:

```bash
portmap cluster plan \
  --target 10.0.0.0/30 \
  --ports 22,80,443 \
  --workers-json '{"workers":[{"node_id":"worker-a","status":"ready","max_concurrency":2}]}' \
  --output json
```

The command returns:

- `mode: dry_run`
- `job`
- `workers`
- `assignments`
- `summary`
- `warnings`
- `raw_payload_stored: false`
- `automatic_changes: false`

## Scheduling Model

The scheduler:

- Reuses the Phase 24 safe scan planner for target, port, concurrency, and rate validation.
- Splits target and port sets into bounded tasks.
- Filters unavailable, stale, or unsupported workers.
- Assigns tasks round-robin across available worker capacity.
- Leaves tasks queued when no workers are available.
- Reports warnings instead of starting network probes.

`JobQueue` supports later execution layers by tracking task status, assigned worker, attempts, retry state, result rows, and errors.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees.

Actual distributed execution should be added only through explicit future worker/orchestrator commands with the existing authorization, audit, and safety boundaries.

## Developer API

```python
from core_engine.cluster.scheduler import plan_distributed_scan

payload = plan_distributed_scan(
    "127.0.0.1",
    [80, 443],
    workers=[{"node_id": "worker-a", "status": "ready"}],
)
```

For stateful execution prototypes:

```python
from core_engine.cluster.job_queue import JobQueue

queue = JobQueue()
```

## Verification

Focused checks:

```bash
python -m pytest tests/test_cluster_scanning.py tests/test_cli_main.py tests/test_packaging.py
portmap cluster plan --target 127.0.0.1 --ports 80,443 --worker worker-a --worker worker-b --output json
```
