# Manifest-Based Plugin Registry

Phase 56 adds a governed local plugin registry for operational utility wrappers. It gives PortMap-AI a consistent way to validate plugin metadata, register allowlisted local utilities, preview execution, and produce structured records for event, storage, dashboard, policy, timeline, and correlation layers.

The registry is local-first and operator-controlled. It does not fetch plugins, transmit data externally, modify routers, change system configuration, or execute anything automatically.

## What It Provides

- Structured plugin manifests with metadata, capabilities, permissions, outputs, and lifecycle state.
- Manifest validation with operator-readable summaries.
- Local registry entries with lifecycle states such as `registered`, `enabled`, `disabled`, and `retired`.
- Allowlisted local execution scopes.
- Dry-run execution previews by default.
- Optional controlled subprocess execution when explicitly requested by the caller.
- Timeout, environment variable, stdout, and stderr bounds.
- Structured operational records for existing platform layers.

## Manifest Shape

Use sanitized placeholders in public docs and examples:

```json
{
  "plugin_id": "plugin.sample.inventory",
  "name": "Sample Inventory Utility",
  "version": "1.0.0",
  "description": "Produces a sanitized local inventory summary.",
  "command": ["<local-runtime>", "<utility-entrypoint>"],
  "capabilities": ["inventory_summary", "metadata_review"],
  "permissions": ["execute_local", "read_metadata"],
  "outputs": ["text", "metadata"],
  "lifecycle_state": "registered",
  "metadata": {
    "owner": "operator-placeholder"
  }
}
```

Supported permissions:

- `execute_local`
- `read_fixture`
- `read_metadata`
- `write_temp`

Supported output types:

- `text`
- `json`
- `metadata`

## Registry Flow

1. An operator provides a local manifest from an allowlisted location.
2. The registry validates the manifest.
3. The plugin entry is registered locally with source attribution.
4. The runner can generate a dry-run preview.
5. Explicit callers may request bounded local execution.
6. Execution results become structured records for review and future storage.

## Operational Records

The Phase 56 modules produce integration-ready records:

- Event pipeline records through `build_manifest_event()` and `build_execution_event()`.
- Storage records through `build_manifest_storage_record()` and `build_execution_storage_record()`.
- Policy findings through `build_manifest_finding()` and `build_execution_finding()`.
- Timeline entries through `build_execution_timeline_entry()`.
- Correlation records through `build_execution_correlation_record()`.

All generated records include:

```json
{
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Dry-Run First

The runner defaults to `dry_run: true`. Dry-run mode validates the plugin record and returns a preview without launching the command.

```python
from core_engine.plugins.runner import run_plugin

result = run_plugin(plugin_manifest, dry_run=True)
```

Explicit local execution requires the caller to pass `dry_run=False` and should be paired with operator policy checks:

```python
result = run_plugin(
    plugin_manifest,
    dry_run=False,
    timeout_seconds=5,
    stdout_limit=4096,
    stderr_limit=4096,
    env={"SAMPLE_ALLOWED": "enabled"},
    env_allowlist=["SAMPLE_ALLOWED"],
)
```

## Safety And Resource Controls

- No plugin execution is automatic.
- No remote plugin download is supported.
- No network transport is added by this phase.
- Environment variables are empty by default unless allowlisted.
- Output summaries are bounded by caller-provided limits.
- Timeout handling returns a structured `timed_out` record instead of interrupting surrounding workflows.
- Plugin command summaries avoid storing full command paths.

## Dashboard And Policy Integration

Dashboard layers can use the registry summary for plugin counts, lifecycle state counts, and capability coverage. Policy review layers can consume non-successful execution records as advisory findings. Approval states remain separate from execution; updating a review state does not execute a plugin or change system configuration.

## Raspberry Pi And Edge Use

The implementation uses standard-library primitives and deterministic local execution controls. Operators should keep timeouts short, output limits bounded, and plugin manifests scoped to small utility wrappers when running on low-resource devices.
