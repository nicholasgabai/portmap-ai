from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable

from core_engine.visualization.readiness import (
    VISUALIZATION_COMPONENTS,
    VISUALIZATION_READINESS_SAFETY_FLAGS,
    VisualizationReadinessError,
    VisualizationReadinessRecord,
    build_visualization_readiness,
    normalize_readiness_state,
)
from core_engine.visualization.timeline_models import sanitize_reference, sanitize_summary
from core_engine.visualization.topology_models import clamp_score, normalize_source_mode, now_timestamp


VISUALIZATION_OPERATOR_RECORD_VERSION = 1
VISUALIZATION_STATES = {"ready", "degraded", "empty", "unavailable", "unknown"}


@dataclass(frozen=True)
class VisualizationOperatorSummary:
    summary_id: str
    generated_at: str
    visualization_state: str
    topology_summary: dict[str, Any] = field(default_factory=dict)
    timeline_summary: dict[str, Any] = field(default_factory=dict)
    asset_inventory_summary: dict[str, Any] = field(default_factory=dict)
    risk_dashboard_summary: dict[str, Any] = field(default_factory=dict)
    fleet_visibility_summary: dict[str, Any] = field(default_factory=dict)
    runtime_summary: dict[str, Any] = field(default_factory=dict)
    degraded_components: list[str] = field(default_factory=list)
    empty_components: list[str] = field(default_factory=list)
    recommendation_summary: dict[str, Any] = field(default_factory=dict)
    source_modes: list[str] = field(default_factory=list)
    readiness_state: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        modes = sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"]
        return {
            "record_type": "visualization_operator_summary",
            "record_version": VISUALIZATION_OPERATOR_RECORD_VERSION,
            "summary_id": sanitize_reference(self.summary_id),
            "generated_at": str(self.generated_at or ""),
            "visualization_state": normalize_visualization_state(self.visualization_state),
            "topology_summary": _safe_summary_dict(self.topology_summary),
            "timeline_summary": _safe_summary_dict(self.timeline_summary),
            "asset_inventory_summary": _safe_summary_dict(self.asset_inventory_summary),
            "risk_dashboard_summary": _safe_summary_dict(self.risk_dashboard_summary),
            "fleet_visibility_summary": _safe_summary_dict(self.fleet_visibility_summary),
            "runtime_summary": _safe_summary_dict(self.runtime_summary),
            "degraded_components": _normalize_components(self.degraded_components),
            "empty_components": _normalize_components(self.empty_components),
            "recommendation_summary": _safe_summary_dict(self.recommendation_summary),
            "source_modes": modes,
            "data_sources": modes,
            "readiness_state": normalize_readiness_state(self.readiness_state),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            "advisory_notes": [sanitize_summary(note) for note in self.advisory_notes],
            **VISUALIZATION_READINESS_SAFETY_FLAGS,
        }


def build_visualization_operator_summary(
    *,
    topology_graphs: Iterable[dict[str, Any]] | None = None,
    timeline_windows: Iterable[dict[str, Any]] | None = None,
    asset_inventory: dict[str, Any] | None = None,
    risk_dashboards: Iterable[dict[str, Any]] | None = None,
    fleet_visibility: dict[str, Any] | None = None,
    runtime_health_summaries: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> VisualizationOperatorSummary:
    _validate_iterable("topology_graphs", topology_graphs)
    _validate_iterable("timeline_windows", timeline_windows)
    _validate_iterable("risk_dashboards", risk_dashboards)
    _validate_iterable("runtime_health_summaries", runtime_health_summaries)
    timestamp = generated_at or now_timestamp()
    topology_rows = _dict_rows(topology_graphs)
    timeline_rows = _dict_rows(timeline_windows)
    risk_rows = _dict_rows(risk_dashboards)
    runtime_rows = _dict_rows(runtime_health_summaries)
    component_summaries = {
        "topology": _topology_summary(topology_rows),
        "timeline": _timeline_summary(timeline_rows),
        "asset_inventory": _asset_summary(asset_inventory),
        "risk_dashboard": _risk_summary(risk_rows),
        "fleet_visibility": _fleet_summary(fleet_visibility),
        "runtime": _runtime_summary(runtime_rows),
    }
    available = [component for component, summary in component_summaries.items() if summary.get("available")]
    degraded = [component for component, summary in component_summaries.items() if summary.get("degraded")]
    empty = [component for component, summary in component_summaries.items() if summary.get("empty")]
    missing = [component for component in sorted(VISUALIZATION_COMPONENTS) if component not in available]
    readiness = build_visualization_readiness(
        available_components=available,
        missing_components=missing,
        degraded_components=degraded,
        empty_components=empty,
        operator_actions=_operator_actions(missing=missing, degraded=degraded, empty=empty),
    )
    visualization_state = _visualization_state(readiness, empty_components=empty, available_components=available)
    source_modes = _source_modes(topology_rows, timeline_rows, [asset_inventory] if isinstance(asset_inventory, dict) else [], risk_rows, [fleet_visibility] if isinstance(fleet_visibility, dict) else [], runtime_rows)
    summary_id = "visual-summary-" + _digest(
        {
            "generated_at": timestamp,
            "state": visualization_state,
            "available": available,
            "degraded": degraded,
            "empty": empty,
        }
    )[:16]
    return VisualizationOperatorSummary(
        summary_id=summary_id,
        generated_at=timestamp,
        visualization_state=visualization_state,
        topology_summary=component_summaries["topology"],
        timeline_summary=component_summaries["timeline"],
        asset_inventory_summary=component_summaries["asset_inventory"],
        risk_dashboard_summary=component_summaries["risk_dashboard"],
        fleet_visibility_summary=component_summaries["fleet_visibility"],
        runtime_summary=component_summaries["runtime"],
        degraded_components=degraded,
        empty_components=empty,
        recommendation_summary=_recommendation_summary(readiness, component_summaries),
        source_modes=source_modes,
        readiness_state=readiness.readiness_state,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
        advisory_notes=["visualization operator summary is dashboard/API/export-safe and advisory-only"],
    )


def empty_visualization_operator_summary(*, generated_at: str | None = None) -> VisualizationOperatorSummary:
    return build_visualization_operator_summary(generated_at=generated_at or now_timestamp())


def deterministic_visualization_summary_json(record: VisualizationOperatorSummary | VisualizationReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (VisualizationOperatorSummary, VisualizationReadinessRecord)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def normalize_visualization_state(value: Any) -> str:
    state = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return state if state in VISUALIZATION_STATES else "unknown"


def _topology_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    node_count = sum(_safe_int(_nested(row, "summary", "node_count", default=row.get("node_count"))) for row in rows)
    edge_count = sum(_safe_int(_nested(row, "summary", "edge_count", default=row.get("edge_count"))) for row in rows)
    return _component_summary("topology", rows, item_count=node_count + edge_count, details={"graph_count": len(rows), "node_count": node_count, "edge_count": edge_count})


def _timeline_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    event_count = sum(_safe_int(row.get("event_count") or len(row.get("events") or [])) for row in rows)
    return _component_summary("timeline", rows, item_count=event_count, details={"window_count": len(rows), "event_count": event_count})


def _asset_summary(record: dict[str, Any] | None) -> dict[str, Any]:
    rows = [record] if isinstance(record, dict) else []
    count = _safe_int(record.get("asset_count") or len(record.get("assets") or [])) if isinstance(record, dict) else 0
    return _component_summary("asset_inventory", rows, item_count=count, details={"asset_count": count})


def _risk_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    card_count = sum(_safe_int(row.get("card_count") or len(row.get("cards") or [])) for row in rows)
    recommendation_count = sum(_safe_int(row.get("recommendation_count")) for row in rows)
    blocked_count = sum(_safe_int(row.get("blocked_action_count")) for row in rows)
    degraded = any(str(row.get("risk_state") or "").lower() in {"degraded", "elevated", "high", "critical"} for row in rows)
    return _component_summary(
        "risk_dashboard",
        rows,
        item_count=card_count,
        degraded=degraded,
        details={"dashboard_count": len(rows), "card_count": card_count, "recommendation_count": recommendation_count, "blocked_action_count": blocked_count},
    )


def _fleet_summary(record: dict[str, Any] | None) -> dict[str, Any]:
    rows = [record] if isinstance(record, dict) else []
    count = _safe_int(record.get("node_count") or len(record.get("nodes") or [])) if isinstance(record, dict) else 0
    degraded = bool(record.get("degraded_state")) if isinstance(record, dict) else False
    return _component_summary("fleet_visibility", rows, item_count=count, degraded=degraded, details={"node_count": count})


def _runtime_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    degraded = any(str(row.get("health_state") or row.get("runtime_state") or row.get("state") or "").lower() in {"degraded", "blocked", "unavailable", "offline", "stale"} for row in rows)
    return _component_summary("runtime", rows, item_count=len(rows), degraded=degraded, details={"runtime_summary_count": len(rows)})


def _component_summary(component: str, rows: list[dict[str, Any]], *, item_count: int, details: dict[str, Any], degraded: bool = False) -> dict[str, Any]:
    available = bool(rows)
    empty = available and item_count <= 0
    return {
        "component": component,
        "available": available,
        "empty": empty,
        "degraded": bool(degraded),
        "item_count": max(0, int(item_count or 0)),
        **details,
    }


def _recommendation_summary(readiness: VisualizationReadinessRecord, summaries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    risk = summaries.get("risk_dashboard", {})
    return {
        "operator_action_count": len(readiness.operator_actions),
        "recommendation_count": _safe_int(risk.get("recommendation_count")),
        "blocked_action_count": _safe_int(risk.get("blocked_action_count")),
        "actions": [sanitize_summary(action) for action in readiness.operator_actions],
        "preview_only": True,
        "destructive_action": False,
    }


def _operator_actions(*, missing: list[str], degraded: list[str], empty: list[str]) -> list[str]:
    actions = []
    if missing:
        actions.append("provide missing visualization components")
    if degraded:
        actions.append("review degraded visualization components")
    if empty:
        actions.append("confirm expected empty visualization components")
    if not actions:
        actions.append("visualization summaries are ready for dashboard/API/export review")
    return actions


def _visualization_state(readiness: VisualizationReadinessRecord, *, empty_components: list[str], available_components: list[str]) -> str:
    if not available_components:
        return "empty"
    if readiness.readiness_state == "blocked":
        return "unavailable"
    if readiness.readiness_state == "degraded":
        return "degraded"
    if empty_components:
        return "degraded"
    return "ready"


def _source_modes(*groups: list[dict[str, Any]]) -> list[str]:
    modes = set()
    for rows in groups:
        for row in rows:
            modes.update(_source_modes_from_row(row))
    return sorted(modes) or ["unknown"]


def _source_modes_from_row(row: dict[str, Any]) -> set[str]:
    modes = {normalize_source_mode(row.get("source_mode") or row.get("data_source"))}
    for key in ("source_modes", "data_sources"):
        values = row.get(key) or []
        if isinstance(values, list):
            modes.update(normalize_source_mode(value) for value in values)
    for key in ("nodes", "cards", "events", "assets"):
        values = row.get(key) or []
        if isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    modes.update(_source_modes_from_row(item))
    return {mode for mode in modes if mode}


def _safe_summary_dict(summary: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in summary.items():
        if isinstance(value, str):
            safe[key] = sanitize_summary(value) if "/" in value or "\\" in value else value
        elif isinstance(value, (int, float, bool)):
            safe[key] = value
        elif isinstance(value, list):
            safe[key] = [sanitize_summary(item) for item in value]
        elif isinstance(value, dict):
            safe[key] = _safe_summary_dict(value)
    return safe


def _normalize_components(values: list[Any]) -> list[str]:
    return sorted({str(value).strip().lower().replace("-", "_").replace(" ", "_") for value in values if str(value).strip().lower().replace("-", "_").replace(" ", "_") in VISUALIZATION_COMPONENTS})


def _dict_rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _validate_iterable(name: str, values: Any) -> None:
    if values is None:
        return
    try:
        iter(values)
    except TypeError as exc:
        raise VisualizationReadinessError(f"{name} must be iterable") from exc
    if isinstance(values, (str, bytes)):
        raise VisualizationReadinessError(f"{name} must be iterable")


def _nested(row: dict[str, Any], parent: str, child: str, *, default: Any = 0) -> Any:
    value = row.get(parent)
    if isinstance(value, dict):
        return value.get(child, default)
    return default


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
