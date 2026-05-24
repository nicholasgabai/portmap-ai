# Federation Runtime Manager

Phase 83 adds active federation runtime manager records for trusted runtime federation. The implementation summarizes planned runtime exchange loops, trusted peer enrollment state, per-peer counters, runtime session references, diagnostics, and dashboard/API-ready dictionaries.

This phase is metadata-only. It does not create live network listeners, start background daemon execution, contact peers, persist new storage schemas, execute remote commands, or replace the Textual terminal dashboard.

## Build Targets

- `core_engine/federation/runtime_manager.py`
- `core_engine/federation/runtime_state.py`
- `tests/test_federation_runtime_manager.py`

## Runtime States

Federation runtime state records support:

- `active`
- `inactive`
- `paused`
- `error`

The state is descriptive. An `active` record means the runtime plan is ready for operator-approved execution in a later phase; it does not start exchange loops in Phase 83.

## Runtime Manager Records

`build_federation_runtime_manager()` composes:

- local trust profile summaries
- trusted transport session summaries
- runtime session references
- signed exchange loop plans
- synchronization loop plans
- event propagation loop plans
- trusted peer runtime enrollment summaries
- per-peer counters
- last-success and last-error timestamps
- federation diagnostics
- dashboard/API-ready runtime state dictionaries

The output includes explicit safety fields:

- `local_only: true`
- `trusted_node_scoped: true`
- `operator_approved: true`
- `network_listener_enabled: false`
- `background_daemon_enabled: false`
- `remote_command_execution: false`
- `raw_payload_stored: false`
- `automatic_changes: false`

## Loop Planning Records

Phase 83 adds planning helpers for:

- signed exchange loops
- synchronization loops
- event propagation loops

Loop plans include peer node IDs, trust scope labels, interval seconds, enabled flags, runtime state, last-success timestamps, last-error timestamps, and source references. Every loop plan includes `loop_execution_enabled: false`.

## Peer Runtime Counters

Per-peer counters summarize:

- transport session counts
- signed exchange counts
- successful exchange counts
- accepted and rejected synchronization updates
- accepted and rejected propagated events
- error counts
- last-success timestamps
- last-error timestamps

Counters are derived from already-provided federation records. The manager does not fetch new data from peers.

## Dashboard And API Readiness

Runtime state records include:

- `summary`
- `dashboard_status`
- `api_status`

These dictionaries are intended for local dashboard providers and future local API views. They do not start a web server or expose public endpoints.

## Sanitized Example

```json
{
  "record_type": "active_federation_runtime_manager",
  "state": "active",
  "summary": {
    "peer_count": 1,
    "loop_plan_count": 3,
    "status": "active"
  },
  "network_listener_enabled": false,
  "background_daemon_enabled": false,
  "remote_command_execution": false
}
```

## Safety Boundaries

Phase 83 does not add:

- live federation transport execution
- network listeners
- background daemons
- peer discovery
- remote command execution
- automatic remediation
- service installation or startup
- new persistence systems
- raw payload storage
- public exposure

## Validation

- Run `python -m pytest`.
- Run `git diff --check`.
- Confirm staged public files use sanitized placeholders only.
- Confirm no logs, screenshots, archives, database files, cache files, environment files, runtime artifacts, private keys, tokens, local paths, or private validation notes are staged.
- Keep `docs/real_device_validation.md` unstaged unless separately scrubbed and explicitly approved.
