from __future__ import annotations

from typing import Any

from gui.web.dashboard import build_dashboard_model
from gui.web.providers import DashboardProvider
from gui.web.render import render_dashboard_html, render_metric_panel


def build_dashboard_view(source: dict[str, Any] | DashboardProvider | None = None) -> dict[str, Any]:
    """Build a read-only dashboard view model from provider-backed data."""
    model = build_dashboard_model(source)
    metrics = model.get("metrics") if isinstance(model.get("metrics"), dict) else {}
    model["empty_state"] = not any(int(metrics.get(key) or 0) for key in _COUNT_KEYS)
    model["sections"] = build_dashboard_sections(model)
    model["raw_payload_stored"] = False
    model["automatic_changes"] = False
    model["administrator_controlled"] = True
    model["local_only"] = True
    model["read_only"] = True
    return model


def build_dashboard_sections(model: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = model.get("metrics") if isinstance(model.get("metrics"), dict) else {}
    return [
        _section("Health", model.get("health_status", "unknown"), "Local API health status"),
        _section("Assets", metrics.get("asset_count", 0), "Observed asset records"),
        _section("Events", metrics.get("event_count", 0), "Local telemetry events"),
        _section("Snapshots", metrics.get("snapshot_count", 0), "Stored visibility snapshots"),
        _section("Nodes", metrics.get("node_count", 0), "Local coordination nodes"),
        _section("Topology Nodes", metrics.get("topology_node_count", 0), "Topology graph nodes"),
        _section("Topology Edges", metrics.get("topology_edge_count", 0), "Topology graph edges"),
        _section("Operator Reviews", metrics.get("operator_review_count", 0), "Advisory review records"),
        _section("Diagnostics", metrics.get("diagnostic_count", 0), "Local diagnostic records"),
    ]


def render_dashboard_view(source: dict[str, Any] | DashboardProvider | None = None) -> str:
    return render_dashboard_html(build_dashboard_view(source))


def render_dashboard_sections(model: dict[str, Any]) -> str:
    return "\n".join(render_metric_panel(section["title"], section["value"], section["detail"]) for section in build_dashboard_sections(model))


def _section(title: str, value: Any, detail: str) -> dict[str, Any]:
    return {
        "title": title,
        "value": value,
        "detail": detail,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
        "read_only": True,
    }


_COUNT_KEYS = (
    "asset_count",
    "event_count",
    "snapshot_count",
    "node_count",
    "topology_node_count",
    "topology_edge_count",
    "operator_review_count",
    "diagnostic_count",
)
