from __future__ import annotations

from typing import Any

from core_engine.runtime.operator_visibility import (
    VISIBILITY_SAFETY_FLAGS,
    build_operator_visibility_summary,
)
from gui.web.render import render_metric_panel


def build_distributed_operator_view(
    *,
    distributed_state: dict[str, Any] | None = None,
    federated_topology: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    distributed_review: dict[str, Any] | None = None,
    coordinated_export: dict[str, Any] | None = None,
    service_readiness_by_node: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    model = build_operator_visibility_summary(
        distributed_state=distributed_state,
        federated_topology=federated_topology,
        cluster_health=cluster_health,
        distributed_review=distributed_review,
        coordinated_export=coordinated_export,
        service_readiness_by_node=service_readiness_by_node,
        generated_at=generated_at,
    )
    model["sections"] = build_distributed_operator_sections(model)
    return model


def build_distributed_operator_sections(model: dict[str, Any]) -> list[dict[str, Any]]:
    panels = model.get("panels") if isinstance(model.get("panels"), dict) else {}
    return [
        _section("Cluster Runtime", panels.get("cluster_runtime")),
        _section("Federated Topology", panels.get("federated_topology")),
        _section("Distributed Reviews", panels.get("distributed_review")),
        _section("Coordinated Exports", panels.get("coordinated_export")),
        _section("Service Readiness", panels.get("service_readiness")),
    ]


def render_distributed_operator_sections(model: dict[str, Any]) -> str:
    return "\n".join(
        render_metric_panel(section["title"], section["value"], section["detail"])
        for section in build_distributed_operator_sections(model)
    )


def distributed_operator_api_response(model: dict[str, Any]) -> dict[str, Any]:
    api = model.get("api") if isinstance(model.get("api"), dict) else {}
    return {
        "status": api.get("status", "ok"),
        "generated_at": model.get("generated_at"),
        "count": api.get("count", 0),
        "items": api.get("items", []),
        "panels": api.get("panels", {}),
        "summary": api.get("summary", model.get("summary", {})),
        **VISIBILITY_SAFETY_FLAGS,
    }


def _section(title: str, panel: Any) -> dict[str, Any]:
    payload = panel if isinstance(panel, dict) else {}
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    value = _primary_value(metrics)
    return {
        "title": title,
        "value": value,
        "detail": str(payload.get("status") or "empty"),
        "panel": str(payload.get("panel") or title.lower().replace(" ", "_")),
        **VISIBILITY_SAFETY_FLAGS,
    }


def _primary_value(metrics: dict[str, Any]) -> int:
    for key in ("node_count", "source_node_count", "review_count", "conflict_count"):
        if key in metrics:
            return int(metrics.get(key) or 0)
    return sum(int(value or 0) for value in metrics.values() if isinstance(value, int))
