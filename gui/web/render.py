from __future__ import annotations

from html import escape
from typing import Any


def render_status_card(model: dict[str, Any]) -> str:
    status = str(model.get("health_status") or "unknown")
    generated_at = str(model.get("generated_at") or "not-generated")
    badge = "ok" if status == "ok" else "attention"
    return (
        '<section class="status-card">'
        "<h2>Health</h2>"
        f'<p class="status {escape(badge)}">{escape(status)}</p>'
        f"<p>Generated: {escape(generated_at)}</p>"
        "</section>"
    )


def render_metric_panel(label: str, value: Any, detail: str = "") -> str:
    return (
        '<section class="metric-panel">'
        f"<h3>{escape(str(label))}</h3>"
        f'<p class="metric-value">{escape(str(value))}</p>'
        f"<p>{escape(str(detail))}</p>"
        "</section>"
    )


def render_dashboard_html(model: dict[str, Any]) -> str:
    metrics = model.get("metrics") or {}
    title = str(model.get("title") or "PortMap-AI Local Dashboard")
    panels = [
        render_status_card(model),
        render_metric_panel("Assets", metrics.get("asset_count", 0), "Observed local assets"),
        render_metric_panel("Events", metrics.get("event_count", 0), "Local telemetry events"),
        render_metric_panel("Snapshots", metrics.get("snapshot_count", 0), "Visibility snapshots"),
        render_metric_panel("Nodes", metrics.get("node_count", 0), "Local coordination nodes"),
        render_metric_panel(
            "Topology",
            f"{metrics.get('topology_node_count', 0)} / {metrics.get('topology_edge_count', 0)}",
            "Nodes / edges",
        ),
        render_metric_panel("Operator Review", metrics.get("operator_review_count", 0), "Advisory items"),
        render_metric_panel("Diagnostics", metrics.get("diagnostic_count", 0), "Local diagnostic records"),
    ]
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{escape(title)}</title>",
            "<style>",
            _style(),
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            f"<h1>{escape(title)}</h1>",
            '<p class="subtle">Local-first, read-only infrastructure visibility.</p>',
            '<section class="dashboard-grid">',
            *panels,
            "</section>",
            '<footer>raw_payload_stored=false automatic_changes=false administrator_controlled=true</footer>',
            "</main>",
            "</body>",
            "</html>",
        ]
    )


def _style() -> str:
    return """
body {
  margin: 0;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #f6f7f9;
  color: #1f2933;
}
main {
  max-width: 1120px;
  margin: 0 auto;
  padding: 24px;
}
h1 {
  font-size: 28px;
  margin: 0 0 6px;
}
.subtle, footer {
  color: #52606d;
}
.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-top: 18px;
}
.status-card, .metric-panel {
  background: #ffffff;
  border: 1px solid #d9e2ec;
  border-radius: 8px;
  padding: 16px;
}
.status, .metric-value {
  font-size: 28px;
  font-weight: 700;
  margin: 8px 0;
}
.ok {
  color: #0f7b57;
}
.attention {
  color: #b54708;
}
footer {
  margin-top: 18px;
  font-size: 13px;
}
"""
