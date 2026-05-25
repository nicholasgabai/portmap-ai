# Real-Time Telemetry Dashboard Integration

Phase 92 adds dashboard/API-ready live telemetry view models. It composes existing passive interface, packet ingestion, flow reconstruction, protocol metadata, dynamic topology, runtime health, federation diagnostics, and operator visibility records into bounded read-only summaries.

This phase does not start a web server, render raw packet payloads, add packet replay, block traffic, replace the existing Textual TUI, or create a separate dashboard schema.

## Modules

- `core_engine.telemetry.operator_views` builds live telemetry operator summaries, panel records, bounded update controls, empty-state records, stale-state records, health summaries, and local API dictionaries.
- `gui.web.live_telemetry_views` converts those records into web dashboard section models and render helpers compatible with the existing lightweight dashboard renderer.

## Panels

The live telemetry view exposes these dashboard-safe panels:

- Interfaces: interface counts, selectable interface counts, address-family summaries, and capability rows.
- Packet rate: metadata record counts, accepted/duplicate/stale/malformed counters, packet rates, transport distribution, and interface distribution.
- Flow rate: reconstructed flow counts, complete/partial/malformed counts, packet and byte totals, flow rates, transport distribution, and service distribution.
- Live topology: node and edge counts, topology warnings, protocol anomaly counts, and topology rendering rows.
- Protocol distribution: HTTP/TLS/DNS summary counts, anomalies, confidence, and truncation counts.
- Resource usage: CPU, memory, storage, runtime health checks, and warning counts.
- Federation rollup: source node count, readiness score, rejected update counters, duplicate event counters, and federation-aware state.
- Telemetry health: panel status rollup, stale-state status, update interval bounds, and review-required state.

## Update Controls

`build_bounded_update_interval_controls` clamps requested dashboard update intervals into configured bounds. It reports the effective interval and does not start an update loop.

Stale-state rendering is explicit. Callers can pass `last_updated_at` and `stale_after_seconds`; stale telemetry becomes a review-oriented status field, not an automatic action.

## Safety Fields

Every view model includes:

- `raw_payload_stored: false`
- `raw_payload_rendered: false`
- `packet_replay_enabled: false`
- `automatic_blocking: false`
- `tui_replaced: false`
- `parallel_dashboard_schema_created: false`
- `local_only: true`
- `administrator_controlled: true`

## Sanitized Example

```python
from core_engine.telemetry import build_live_telemetry_operator_summary

summary = build_live_telemetry_operator_summary(
    interface_inventory=sanitized_interface_inventory,
    packet_window=sanitized_packet_window,
    flows=sanitized_flow_records,
    protocol_report=sanitized_protocol_report,
    live_topology=sanitized_live_topology,
    requested_update_interval_seconds=5,
    generated_at="2026-01-01T00:00:00+00:00",
)

api_response = summary["api_status"]
```

The example uses sanitized metadata records only. It does not include packet payloads, credentials, local paths, private hostnames, or runtime artifacts.

## Validation Checklist

- Run `python -m pytest`.
- Run `git diff --check`.
- Confirm dashboard/API records do not include raw payload contents.
- Confirm update interval controls remain bounded.
- Confirm stale and empty states render explicitly.
- Confirm the Textual TUI is not replaced.
- Confirm no packet replay, injection, automatic blocking, or external transmission is added.
- Confirm `docs/real_device_validation.md`, logs, screenshots, archives, database files, cache files, and runtime artifacts are not staged.
