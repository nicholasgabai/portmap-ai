# Operational Export Bundle

Phase 64 adds a local operational export bundle for snapshots, topology records, findings, review records, runtime summaries, and diagnostic summaries.

The export workflow is operator-controlled and local-only. It does not send data externally, contact cloud services, execute plugins, install services, modify routers, change configuration, or trigger remediation.

## Modules

- `core_engine.export.bundle`
- `core_engine.export.redaction`

## Bundle Contents

An operational export bundle contains:

- `manifest`
- `snapshots`
- `topology`
- `findings`
- `reviews`
- `runtime`
- `diagnostics`

The manifest includes:

- bundle type
- label
- generated timestamp
- record counts
- placeholder validation status
- redaction status
- SHA-256 integrity digest
- safety fields

## Basic Use

```python
from core_engine.export import build_operational_export_bundle, export_operational_bundle_json

bundle = build_operational_export_bundle(
    repository=repository,
    review_store=review_store,
    runtime_state=runtime_state,
    diagnostics=[{"diagnostic_id": "diagnostic-sample", "status": "ok"}],
    generated_at="2026-01-03T00:00:00+00:00",
)

text = export_operational_bundle_json(bundle)
```

The JSON output is deterministic for the same sanitized inputs and uses sorted keys.

## Redaction And Placeholder Validation

`redact_operational_record()` removes common private/local identifiers from export data:

- private IPv4 ranges
- MAC addresses
- local home-directory paths
- known local validation host placeholders
- secret-like fields through the shared security scrubber

`validate_placeholder_safe()` reports whether a payload still contains private/local identifiers.

## Archive Creation

Archive creation is explicit and uses an operator-provided local output path:

```python
from core_engine.export import write_operational_export_archive

result = write_operational_export_archive("operator-provided-output.zip", bundle)
```

The archive contains:

- `manifest.json`
- `bundle.json`

The result does not store the local output path in the bundle.

## Safety Properties

Bundle outputs include:

```json
{
  "local_only": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Phase 64 is export packaging only. Review approval remains a state change only, and exported records do not trigger actions.
