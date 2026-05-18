# Runtime Pipeline Wiring

Phase 61 adds an explicit local workflow runner that connects already-collected visibility evidence with events, topology snapshots, snapshot drift, policy review drafts, timeline records, correlation records, and optional local storage writes.

The runtime pipeline is operator-triggered and dry-run by default. It does not scan, collect packets, contact nodes, execute plugins, install services, change configuration, modify routers, transmit data, or perform remediation.

## Modules

- `core_engine.runtime.pipeline`
- `core_engine.runtime.workflows`

## Inputs

The pipeline consumes records that already exist in memory or were explicitly provided by an operator:

- asset inventory rows
- service metadata rows
- flow summaries
- advisory findings
- baseline topology snapshot
- current topology snapshot
- policy records
- an optional local storage repository

Example identifiers should remain generic:

```json
{
  "asset_id": "asset-alpha",
  "service_id": "svc-alpha-admin",
  "snapshot_id": "topology-snapshot-sample",
  "finding_id": "finding-sample-review"
}
```

## Basic Dry Run

```python
from core_engine.runtime.pipeline import run_runtime_pipeline

result = run_runtime_pipeline(
    assets=[{"asset_id": "asset-alpha", "label": "Asset Alpha"}],
    services=[{"asset_id": "asset-alpha", "service": "ssh", "port": 22, "state": "open"}],
    dry_run=True,
)
```

Dry-run output includes workflow summaries but performs no local database writes:

```json
{
  "status": "ok",
  "dry_run": true,
  "write_local": false,
  "summary": {
    "event_count": 2,
    "snapshot_count": 1,
    "storage_write_count": 0
  },
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Snapshot Drift Wiring

When both baseline and current topology snapshots are provided, the pipeline uses Phase 60 drift helpers. The drift output is converted into:

- normalized local events
- storage-ready drift records
- policy-ready findings
- timeline entries
- correlation-ready records

This keeps downstream modules connected without creating parallel schemas.

## Policy Review Drafts

When policy records are provided, the pipeline evaluates findings and drift records through the existing policy review engine. Review drafts are local advisory records only. Approval changes are not executed by this phase.

## Explicit Local Write Mode

Local writes require both:

- `dry_run=False`
- `write_local=True`

The caller must also provide an existing `LocalStorageRepository`. The pipeline writes only selected local records through the existing repository methods:

- events
- topology snapshots
- findings

No external transport is added.

## Failure Isolation

Each pipeline step reports its own status. If one step fails, later steps still run where possible and the overall result becomes `partial`.

```json
{
  "status": "partial",
  "summary": {
    "failed_step_count": 1
  }
}
```

## Safety Properties

Runtime pipeline outputs include:

```json
{
  "local_only": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Phase 61 is wiring only. It does not start an always-on service or replace existing CLI, orchestrator, worker, or dashboard behavior.
