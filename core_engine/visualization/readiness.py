from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from core_engine.visualization.fleet_models import FLEET_SAFETY_FLAGS
from core_engine.visualization.timeline_models import sanitize_reference, sanitize_references, sanitize_summary


VISUALIZATION_READINESS_RECORD_VERSION = 1
VISUALIZATION_READINESS_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}
VISUALIZATION_COMPONENTS = {
    "topology",
    "timeline",
    "asset_inventory",
    "risk_dashboard",
    "fleet_visibility",
    "runtime",
}
VISUALIZATION_READINESS_SAFETY_FLAGS = {
    **FLEET_SAFETY_FLAGS,
    "visualization_summary_model_only": True,
    "dashboard_api_ready": True,
    "browser_ui_started": False,
    "remote_call_performed": False,
    "live_control_enabled": False,
}


class VisualizationReadinessError(ValueError):
    """Raised when visualization readiness inputs are malformed."""


@dataclass(frozen=True)
class VisualizationReadinessRecord:
    readiness_id: str
    readiness_state: str
    required_components: list[str] = field(default_factory=list)
    available_components: list[str] = field(default_factory=list)
    missing_components: list[str] = field(default_factory=list)
    degraded_components: list[str] = field(default_factory=list)
    empty_components: list[str] = field(default_factory=list)
    operator_actions: list[str] = field(default_factory=list)
    dashboard_api_ready: bool = True
    export_ready: bool = True
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "visualization_readiness",
            "record_version": VISUALIZATION_READINESS_RECORD_VERSION,
            **VISUALIZATION_READINESS_SAFETY_FLAGS,
            "readiness_id": sanitize_reference(self.readiness_id),
            "readiness_state": normalize_readiness_state(self.readiness_state),
            "required_components": _normalize_components(self.required_components),
            "available_components": _normalize_components(self.available_components),
            "missing_components": _normalize_components(self.missing_components),
            "degraded_components": _normalize_components(self.degraded_components),
            "empty_components": _normalize_components(self.empty_components),
            "operator_actions": [sanitize_summary(action) for action in self.operator_actions],
            "dashboard_api_ready": bool(self.dashboard_api_ready),
            "export_ready": bool(self.export_ready),
            "preview_only": True,
            "destructive_action": False,
            "advisory_notes": [sanitize_summary(note) for note in self.advisory_notes],
        }


def build_visualization_readiness(
    *,
    available_components: list[Any] | None = None,
    missing_components: list[Any] | None = None,
    degraded_components: list[Any] | None = None,
    empty_components: list[Any] | None = None,
    required_components: list[Any] | None = None,
    operator_actions: list[Any] | None = None,
) -> VisualizationReadinessRecord:
    required = _normalize_components(required_components or sorted(VISUALIZATION_COMPONENTS))
    available = _normalize_components(available_components or [])
    missing = _normalize_components(missing_components or [component for component in required if component not in available])
    degraded = _normalize_components(degraded_components or [])
    empty = _normalize_components(empty_components or [])
    state = readiness_state_from_components(missing_components=missing, degraded_components=degraded, empty_components=empty)
    actions = [sanitize_summary(action) for action in operator_actions or []]
    if missing and not actions:
        actions.append("review missing visualization components")
    if degraded and "review degraded visualization components" not in actions:
        actions.append("review degraded visualization components")
    if empty and "confirm expected empty visualization state" not in actions:
        actions.append("confirm expected empty visualization state")
    readiness_id = "visual-readiness-" + _digest(
        {
            "required": required,
            "available": available,
            "missing": missing,
            "degraded": degraded,
            "empty": empty,
        }
    )[:16]
    return VisualizationReadinessRecord(
        readiness_id=readiness_id,
        readiness_state=state,
        required_components=required,
        available_components=available,
        missing_components=missing,
        degraded_components=degraded,
        empty_components=empty,
        operator_actions=actions,
        dashboard_api_ready=state in {"ready", "degraded"},
        export_ready=True,
        preview_only=True,
        destructive_action=False,
        advisory_notes=["visualization readiness is advisory-only and does not start a browser UI"],
    )


def readiness_state_from_components(
    *,
    missing_components: list[Any] | None = None,
    degraded_components: list[Any] | None = None,
    empty_components: list[Any] | None = None,
) -> str:
    missing = _normalize_components(missing_components or [])
    degraded = _normalize_components(degraded_components or [])
    empty = _normalize_components(empty_components or [])
    if missing:
        return "blocked"
    if degraded:
        return "degraded"
    if empty:
        return "degraded"
    return "ready"


def empty_visualization_readiness() -> VisualizationReadinessRecord:
    return build_visualization_readiness(
        available_components=[],
        missing_components=sorted(VISUALIZATION_COMPONENTS),
        empty_components=sorted(VISUALIZATION_COMPONENTS),
        operator_actions=["provide visualization inputs before rendering summaries"],
    )


def deterministic_visualization_readiness_json(record: VisualizationReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, VisualizationReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def normalize_readiness_state(value: Any) -> str:
    state = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return state if state in VISUALIZATION_READINESS_STATES else "unknown"


def _normalize_components(values: list[Any]) -> list[str]:
    components = []
    for value in values:
        component = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
        if component in VISUALIZATION_COMPONENTS:
            components.append(component)
    return sorted(set(components))


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
