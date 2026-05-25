from __future__ import annotations

from typing import Any, Iterable

from core_engine.telemetry.operator_views import (
    LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    build_live_telemetry_operator_summary,
)
from gui.web.render import render_metric_panel


def build_live_telemetry_dashboard_view(
    *,
    interface_inventory: dict[str, Any] | None = None,
    packet_window: dict[str, Any] | None = None,
    flows: Iterable[dict[str, Any]] | None = None,
    flow_summary: dict[str, Any] | None = None,
    protocol_report: dict[str, Any] | None = None,
    live_topology: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    federation_diagnostics: dict[str, Any] | None = None,
    operator_visibility: dict[str, Any] | None = None,
    resource_usage: dict[str, Any] | None = None,
    requested_update_interval_seconds: int = 5,
    stale_after_seconds: int = 300,
    last_updated_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    model = build_live_telemetry_operator_summary(
        interface_inventory=interface_inventory,
        packet_window=packet_window,
        flows=flows,
        flow_summary=flow_summary,
        protocol_report=protocol_report,
        live_topology=live_topology,
        runtime_health=runtime_health,
        federation_diagnostics=federation_diagnostics,
        operator_visibility=operator_visibility,
        resource_usage=resource_usage,
        requested_update_interval_seconds=requested_update_interval_seconds,
        stale_after_seconds=stale_after_seconds,
        last_updated_at=last_updated_at,
        generated_at=generated_at,
    )
    model["sections"] = build_live_telemetry_dashboard_sections(model)
    return model


def build_live_telemetry_dashboard_sections(model: dict[str, Any]) -> list[dict[str, Any]]:
    panels = model.get("panels") if isinstance(model.get("panels"), dict) else {}
    return [
        _section("Interfaces", panels.get("interfaces"), "interface_count"),
        _section("Packet Rate", panels.get("packet_rate"), "metadata_record_count"),
        _section("Flow Rate", panels.get("flow_rate"), "flow_count"),
        _section("Live Topology", panels.get("live_topology"), "node_count"),
        _section("Protocols", panels.get("protocol_distribution"), "record_count"),
        _section("Resources", panels.get("resource_usage"), "warning_count"),
        _section("Federation", panels.get("federation_rollup"), "source_node_count"),
        _section("Telemetry Health", model.get("health_summary"), "warning_count"),
    ]


def render_live_telemetry_sections(model: dict[str, Any]) -> str:
    return "\n".join(
        render_metric_panel(section["title"], section["value"], section["detail"])
        for section in build_live_telemetry_dashboard_sections(model)
    )


def live_telemetry_api_response(model: dict[str, Any]) -> dict[str, Any]:
    api = model.get("api_status") if isinstance(model.get("api_status"), dict) else {}
    return {
        "record_type": "live_telemetry_dashboard_api_response",
        "status": api.get("status", model.get("status", "unknown")),
        "generated_at": api.get("generated_at", model.get("generated_at")),
        "count": api.get("count", 0),
        "summary": api.get("summary", model.get("summary", {})),
        "panels": api.get("panels", model.get("panels", {})),
        "health_summary": api.get("health_summary", model.get("health_summary", {})),
        "update_controls": api.get("update_controls", model.get("update_controls", {})),
        "empty_state": api.get("empty_state", model.get("empty_state")),
        "stale_state": api.get("stale_state", model.get("stale_state")),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_empty_live_telemetry_dashboard_view(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_live_telemetry_dashboard_view(generated_at=generated_at)


def _section(title: str, panel: Any, primary_metric: str) -> dict[str, Any]:
    payload = panel if isinstance(panel, dict) else {}
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    value = metrics.get(primary_metric, 0)
    return {
        "title": title,
        "value": value,
        "detail": str(payload.get("status") or "empty"),
        "panel": str(payload.get("panel") or title.lower().replace(" ", "_")),
        "metrics": dict(metrics),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }
