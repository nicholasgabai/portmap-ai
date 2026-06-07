# Visualization Operator Summary

Phase 146 adds unified visualization operator summary models for PortMap-AI. These records combine topology graphs, timeline windows, asset inventory, risk dashboards, fleet visibility, runtime health, degraded components, empty components, recommendations, and readiness checks into dashboard/API/export-safe visual intelligence summaries.

This phase is model-only. It does not add browser UI, remote control, remediation execution, firewall/process/service changes, runtime database writes, raw payload storage, raw DNS history retention, or private identifier export.

## Operator Summary Model

`core_engine.visualization.operator_summary` defines `VisualizationOperatorSummary` records with:

- `summary_id`
- `generated_at`
- `visualization_state`
- topology summary
- timeline summary
- asset inventory summary
- risk dashboard summary
- fleet visibility summary
- runtime summary
- degraded components
- empty components
- recommendation summary
- source modes
- readiness state
- preview-only and destructive-action safety fields
- export-safe safety fields
- advisory notes

Supported visualization states are `ready`, `degraded`, `empty`, `unavailable`, and `unknown`.

## Readiness Checks

`core_engine.visualization.readiness` defines `VisualizationReadinessRecord` entries with:

- readiness state
- required components
- available components
- missing components
- degraded components
- empty components
- operator actions
- dashboard/API readiness
- export readiness
- preview-only and destructive-action safety fields
- advisory notes

Supported readiness states are `ready`, `degraded`, `blocked`, `unavailable`, and `unknown`.

## Component Rollups

Operator summaries roll up:

- topology graph counts, node counts, and edge counts
- timeline window and event counts
- asset inventory counts
- risk dashboard cards, recommendations, and blocked-action counts
- fleet node counts and degraded fleet state
- runtime health summary counts

Malformed collection inputs raise structured readiness errors. Malformed individual rows are ignored when they are not dictionaries.

## Degraded And Empty States

Empty components are explicitly listed when a component is available but has no records to display. Degraded components are listed when runtime, risk, fleet, or other summaries report degraded or elevated states. Missing components produce a blocked readiness state and an unavailable visualization state unless no components are available, in which case the visualization state is empty.

## Source Mode Preservation

Visualization summaries preserve source modes from nested topology, timeline, asset, risk, fleet, and runtime summaries. This keeps live, fixture, simulated, replay, and unknown sources distinguishable in future dashboard/API/export views.

## Safety Boundary

Phase 146 explicitly guarantees:

- No browser UI is added.
- No remote control is added.
- No remediation is executed.
- No firewall, process, service, quarantine, rollback, or isolation action is performed.
- No runtime database is written.
- No packet payload is inspected or stored.
- No raw DNS history is retained.
- No private hostnames, addresses, usernames, MAC addresses, hardware identifiers, credentials, certs, keys, logs, screenshots, runtime outputs, or local databases are required or exported.

## Future GUI Path

These records provide the final Milestone X data contract for future GUI and dashboard work. Later UI layers can render topology, timeline, inventory, risk, fleet, runtime, readiness, and recommendation summaries without changing collectors or host/network state.

## Validation

Use sanitized fixtures only:

- Run `python -m pytest tests/test_visualization_operator_summary.py`.
- Run the full test suite before committing.
- Run `git diff --check`.
- Run a sensitive-data scan.
- Confirm `docs/real_device_validation.md`, local test files, logs, artifacts, screenshots, caches, runtime outputs, and databases remain unstaged.
