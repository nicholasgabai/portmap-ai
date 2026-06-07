# Multi-Node Fleet Visibility

Phase 145 adds visualization-ready multi-node fleet visibility models for PortMap-AI. Fleet records summarize sites, groups, node roles, collector health, runtime status, version compatibility, telemetry freshness, observed asset and flow counts, risk state, and last check-in metadata for future dashboard/API/export views.

This phase is model-only. It does not add cloud sync, remote control, browser UI, remediation execution, firewall/process/service changes, runtime database writes, raw payload storage, or private identifier export.

## Fleet Node Records

`core_engine.visualization.fleet_models` defines `FleetNodeRecord` entries with:

- `fleet_node_id`
- sanitized `node_reference`
- advisory `node_label`
- `node_role`
- site and group references
- runtime state
- health state
- version state
- last check-in
- telemetry freshness
- collector status
- observed asset and flow counts
- risk state
- source mode
- preview-only and destructive-action safety fields
- advisory notes

Supported node roles are:

- `orchestrator`
- `master`
- `worker`
- `edge_collector`
- `gateway_collector`
- `unknown`

Supported node and collector states are `active`, `degraded`, `stale`, `offline`, and `unknown`.

## Site And Group Summaries

Fleet site and group summary records include:

- node count
- active count
- degraded count
- stale count
- offline count
- highest risk state
- health summary
- source modes
- export-safe safety fields

Summaries group nodes by sanitized site and group references. They do not require hostnames, addresses, hardware identifiers, usernames, or cloud workspace IDs.

## Fleet Visibility Panels

`core_engine.visualization.fleet_visibility` builds bounded `FleetVisibilityPanel` records from:

- runtime node summaries
- federation summaries
- deployment summaries
- cluster health summaries
- topology summaries
- asset inventory summaries
- risk dashboard summaries

Builders deduplicate repeated nodes, calculate freshness from explicit freshness state or check-in age, calculate version compatibility, calculate collector health, group nodes by site and group, and apply `max_nodes` bounds.

## Empty And Degraded Views

Empty inputs produce safe empty fleet panels. Degraded, stale, and offline nodes remain explicit in panel counts so future UI views can render useful empty/degraded states without performing remote actions.

## Source Mode Preservation

Fleet records preserve `source_mode` values such as `live`, `fixture`, `simulated`, `replay`, and `unknown`. This allows future dashboards to distinguish real runtime observations from fixtures, simulations, and replayed summaries.

## Safety Boundary

Phase 145 explicitly guarantees:

- No cloud sync is added.
- No remote control is added.
- No browser UI is added.
- No remediation is executed.
- No firewall, process, service, quarantine, rollback, or isolation action is performed.
- No runtime database is written.
- No packet payload is inspected or stored.
- No private hostnames, addresses, usernames, MAC addresses, hardware identifiers, credentials, certs, keys, logs, screenshots, runtime outputs, or local databases are required or exported.

## Future Fleet Path

These records provide a stable data contract for later enterprise dashboard and fleet views. Future UI work can render site health, group status, collector freshness, version readiness, and node risk summaries without changing collectors or host/network state.

## Validation

Use sanitized fixtures only:

- Run `python -m pytest tests/test_multi_node_fleet_visibility.py`.
- Run the full test suite before committing.
- Run `git diff --check`.
- Run a sensitive-data scan.
- Confirm `docs/real_device_validation.md`, local test files, logs, artifacts, screenshots, caches, runtime outputs, and databases remain unstaged.
