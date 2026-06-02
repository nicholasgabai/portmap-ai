# Source Mode Labeling

This pre-Milestone U hardening fix makes PortMap-AI distinguish live observations from demo, fixture, simulated, replay, and unknown records in TUI, dashboard, API, and export-safe summaries.

## Source Modes

PortMap-AI uses these operator-facing source modes:

- `live` - local runtime, socket, telemetry, or worker observations from the running stack.
- `simulated` - generated demo data used only when a caller explicitly asks for simulation.
- `fixture` - deterministic test or documentation fixture data.
- `replay` - bounded historical replay data reconstructed from stored metadata summaries.
- `unknown` - incomplete or malformed records that do not declare a source.

## Labeling Rules

- Live/default runtime views must not show `dummy_app` or `dummy_db`.
- `dummy_app` and `dummy_db` are valid only in explicit `simulated` or `fixture` mode.
- Live unresolved process attribution is displayed as `Unattributed`.
- Unsupported or unavailable process visibility is displayed as `Unknown`.
- TUI scan-result rows include a source-mode column so operators can distinguish live observations from fixture or replay records.
- Dashboard, API, and export dictionaries preserve `source_mode` and `data_source` where attribution or telemetry source context is available.

## Safety Boundary

Source labeling is metadata-only. It does not start collectors, capture packets, install services, modify firewall rules, create backups, restore files, or perform enforcement. It only prevents demo labels from appearing in live/default operator views unless simulation or fixture mode is explicit.
