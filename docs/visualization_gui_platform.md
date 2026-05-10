# Visualization and GUI Platform

Phase 38 expands the existing Textual terminal dashboard into a visualization platform for local operators. It keeps PortMap-AI's current terminal-first product shape while adding reusable visualization helpers for risk trends, topology edges, and passive traffic flows.

## Scope

The visualization layer includes:

- Risk timeline summaries from scan and remediation events.
- Topology edge summaries from passive flow telemetry.
- Traffic flow tables with initiator, responder, protocol, packet count, byte count, and findings.
- Dashboard metrics that show flow counts and topology size alongside node and remediation status.
- Help text that explains the visual panels without requiring browser UI assumptions.

The implementation is split between:

- `gui.visualization` for testable data normalization and rendering helpers.
- `gui.app` for Textual widgets and panel refresh wiring.

## Dashboard Panels

The terminal dashboard now includes:

- `Node Overview`: registered worker status and heartbeat visibility.
- `Scan Results`: recent sampled ports, risk scores, providers, and scoring signals.
- `Remediation Feed`: recent remediation decisions and enforcement mode.
- `Expected Services`: observed service candidates and allowlisted normal services.
- `Risk Timeline`: compact score buckets for recent event trends.
- `Topology Edges`: passive initiator-to-responder relationships when flow telemetry is available.
- `Traffic Flows`: bidirectional flow summaries without storing raw payload bytes.
- `Command Outcomes`: worker command audit status.
- `Master Log Tail`: recent master runtime lines.

## Flow Data Sources

The dashboard reads flow telemetry from:

- `~/.portmap-ai/logs/flow_events.jsonl` when present.
- `~/.portmap-ai/logs/master_events.log` when entries contain flow, packet, or DPI observation rows.

Missing flow telemetry is treated as an empty visualization state. The dashboard still loads and shows node, scan, remediation, and command information.

## Safety Boundaries

Visualization is read-only and follows the global PortMap-AI safety guarantees. It stores no raw payload bytes.

Existing dashboard buttons remain explicit operator controls. Visualization panels only summarize data already collected by other explicit PortMap-AI workflows.

## Developer API

```python
from gui.visualization import build_flow_visualization, build_risk_timeline

timeline = build_risk_timeline(remediation_events)
flow_view = build_flow_visualization(packet_or_flow_events)
```

`gui.visualization` functions return JSON-serializable structures that can be reused by future GUI, topology, or SaaS-facing presentation layers.

## Verification

Focused checks:

```bash
python -m pytest tests/test_gui_app.py tests/test_packaging.py
```

Runtime smoke:

```bash
portmap tui
```

The runtime smoke requires a terminal environment with Textual installed. The automated tests validate the visualization helpers and dashboard wiring without requiring a live orchestrator or packet capture privileges.
