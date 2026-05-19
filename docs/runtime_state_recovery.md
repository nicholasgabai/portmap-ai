# Runtime State Recovery

Runtime state recovery helpers summarize previous local runtime sessions, checkpoints, pipeline results, review state, storage state, and export readiness so an operator can decide what to inspect next.

This phase does not restart services, resume workflows automatically, run collection, execute remediation, modify configuration, or transmit data externally.

## Checkpoint Records

Runtime checkpoints are local JSON-ready records with:

- `checkpoint_id`
- `status`
- `created_at`
- `session_summary`
- `profile_summary`
- `pipeline_result`
- `runtime_summary`
- `storage_summary`
- `review_summary`
- `export_summary`
- `metadata`

Checkpoint records include:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

## Recovery Summary

The recovery summary can report:

- Last-known runtime session.
- Incomplete workflows.
- Failed runtime pipeline steps.
- Pending operator reviews.
- Export-ready local records.
- Operator-readable recovery recommendations.

Recommendations are advisory only. They do not execute actions.

## Example

```python
from core_engine.runtime import build_runtime_checkpoint, build_runtime_recovery_summary

checkpoint = build_runtime_checkpoint(
    checkpoint_id="checkpoint-example",
    session_summary={"session_id": "session-example", "status": "running"},
    created_at="2026-01-01T00:00:00+00:00",
)

summary = build_runtime_recovery_summary(
    checkpoints=[checkpoint],
    generated_at="2026-01-01T00:05:00+00:00",
)
```

Example summary shape:

```json
{
  "status": "needs_review",
  "recommendation_count": 1,
  "automatic_changes": false,
  "administrator_controlled": true,
  "raw_payload_stored": false
}
```

## Malformed Checkpoints

`load_runtime_checkpoint()` returns a structured invalid result for malformed JSON or invalid checkpoint records. It does not raise through normal operator workflows.

## Integration Points

Recovery helpers reuse existing PortMap-AI records:

- Runtime sessions from `core_engine.runtime.session`.
- Runtime profiles from `core_engine.runtime.profiles`.
- Pipeline results from `core_engine.runtime.pipeline`.
- Review summaries from `core_engine.policy`.
- Storage counts from `core_engine.storage`.
- Export readiness from `core_engine.export`.

No parallel persistence system is introduced.

## Safety Notes

Recovery recommendations are advisory and local-only. Operators remain responsible for deciding whether to resume workflows, inspect reviews, or create local export bundles.
