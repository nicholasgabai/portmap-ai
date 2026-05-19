# Runtime Session Manager

The runtime session manager provides local records for explicit operator-started PortMap-AI runtime sessions. It is a coordination primitive for future CLI, API, dashboard, health, and service-mode workflows.

This phase does not start services, execute jobs, run collection, install components, change host configuration, or transmit data externally.

## Purpose

A runtime session describes one local operating window. It can summarize:

- Session ID, mode, status, start time, and stop time.
- Enabled runtime components.
- Runtime pipeline result summaries.
- Event, storage, review, and export summaries.
- Status references for CLI, API, and dashboard views.
- Last warning and last error details.

Session records are local-only and include:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

## Session Modes

Supported session modes:

- `dry-run` - default advisory mode with no local storage writes.
- `local-write` - explicit operator-approved mode for local storage writes by other workflow components.
- `service-preview` - dry-run service-mode planning and readiness summaries.

Creating a session does not enable write mode by itself. Other workflow components must still require their own explicit local-write controls.

## Example

```python
from core_engine.runtime import RuntimeSessionManager

manager = RuntimeSessionManager()
session = manager.start_session(
    session_id="session-example",
    mode="dry-run",
    started_at="2026-01-01T00:00:00+00:00",
    enabled_components=["pipeline", "events", "storage", "reviews", "export"],
)

summary = manager.summarize_sessions()
```

Example summary shape:

```json
{
  "session_count": 1,
  "sessions_by_mode": {
    "dry-run": 1
  },
  "sessions_by_status": {
    "running": 1
  },
  "automatic_changes": false,
  "administrator_controlled": true,
  "raw_payload_stored": false
}
```

## Integration Points

Runtime sessions are designed to reference existing PortMap-AI records instead of creating a parallel persistence model:

- Runtime pipeline summaries from `core_engine.runtime.pipeline`.
- Scheduler status from `core_engine.runtime.scheduler`.
- Event summaries from `core_engine.events`.
- Storage summaries from `core_engine.storage`.
- Review summaries from `core_engine.policy`.
- Topology and drift summaries from `core_engine.topology`.
- Export summaries from `core_engine.export`.

The session manager stores these references in memory for now. Future phases can persist selected session records through the existing storage layer.

## Operator Safety

The session manager is descriptive. It does not:

- Start or stop services.
- Execute remediation.
- Run plugins.
- Modify router or firewall state.
- Perform active probing.
- Send data to external systems.
- Store raw payload bytes.

## Raspberry Pi Notes

Runtime session records are small JSON-ready dictionaries and are suitable for edge-device operation. Validation should use sanitized fixtures and temporary local test locations only.
