# Remote Operator Visibility Prep

Phase 76 adds read-only trusted-node visibility models for future local operator views. It prepares API-compatible dictionaries for distributed runtime state, federated topology, cluster health, distributed reviews, coordinated exports, and service-readiness previews.

This phase does not start a web server, expose public routes, contact remote nodes, synchronize to cloud services, execute commands, approve reviews, install services, or replace the existing Textual terminal dashboard.

## Visibility Inputs

The operator visibility model reuses existing Milestone L records:

- distributed node state summaries
- federated topology summaries
- cluster runtime health summaries
- distributed review summaries
- coordinated export bundle plans
- service-mode readiness previews by node

All inputs are already trusted-node scoped and operator-provided.

## Output Models

`build_operator_visibility_summary()` returns:

- trusted node visibility summaries
- cluster runtime status panel
- federated topology status panel
- distributed review status panel
- coordinated export status panel
- service-readiness status panel by node
- stale-node rendering records
- empty-state model
- API-compatible dictionary for future local dashboard use

Every output includes:

- `local_only: true`
- `trusted_node_scoped: true`
- `read_only: true`
- `api_compatible: true`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`
- `remote_control_enabled: false`
- `public_exposure_enabled: false`
- `cloud_sync_enabled: false`

## Dashboard View Helpers

`gui.web.distributed_views` converts the runtime visibility model into section records and API responses. It does not render or launch a replacement for the Textual TUI. The helpers are intended as reusable groundwork for future local browser views.

## Empty And Stale States

Empty-state output is explicit when no distributed records are available. Stale-node rendering records preserve node IDs, roles, last-seen timestamps, and the stale reason so an operator can review local trusted-node state without hiding degraded conditions.

## Raspberry Pi Validation

Use sanitized records and temporary local test locations only.

- Build a visibility summary for one master and one worker node.
- Build cluster runtime, federated topology, distributed review, coordinated export, and service-readiness panels.
- Verify stale-node rendering with a stale worker fixture.
- Verify empty-state output when no node records are present.
- Verify API dictionaries are JSON serializable.
- Confirm remote-control, public exposure, and cloud sync fields remain disabled.
- Confirm no web server is started and the Textual TUI is not replaced.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest with small fixture inputs.
- Confirm no raw payload bytes, private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime data, or private validation notes are staged.
