from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from core_engine.visualization.risk_cards import RISK_DASHBOARD_SAFETY_FLAGS
from core_engine.visualization.risk_dashboard import normalize_risk_state
from core_engine.visualization.timeline_models import sanitize_reference, sanitize_references, sanitize_summary
from core_engine.visualization.topology_models import clamp_score, normalize_source_mode


FLEET_RECORD_VERSION = 1
FLEET_NODE_ROLES = {
    "orchestrator",
    "master",
    "worker",
    "edge_collector",
    "gateway_collector",
    "unknown",
}
FLEET_STATES = {"active", "degraded", "stale", "offline", "unknown"}
VERSION_STATES = {"current", "compatible", "outdated", "incompatible", "unknown"}
FLEET_SAFETY_FLAGS = {
    **RISK_DASHBOARD_SAFETY_FLAGS,
    "fleet_visibility_model_only": True,
    "cloud_sync_enabled": False,
    "remote_control_enabled": False,
    "fleet_database_written": False,
}


class FleetVisibilityError(ValueError):
    """Raised when fleet visibility inputs are malformed."""


@dataclass(frozen=True)
class FleetNodeRecord:
    fleet_node_id: str
    node_reference: str
    node_label: str
    node_role: str
    site_reference: str = "site-default"
    group_references: list[str] = field(default_factory=list)
    runtime_state: str = "unknown"
    health_state: str = "unknown"
    version_state: str = "unknown"
    last_checkin: str = ""
    telemetry_freshness: str = "unknown"
    collector_status: str = "unknown"
    observed_asset_count: int = 0
    observed_flow_count: int = 0
    risk_state: str = "unknown"
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "visual_fleet_node",
            "record_version": FLEET_RECORD_VERSION,
            "fleet_node_id": sanitize_reference(self.fleet_node_id),
            "node_reference": sanitize_reference(self.node_reference),
            "node_label": sanitize_summary(self.node_label),
            "node_role": normalize_node_role(self.node_role),
            "site_reference": sanitize_reference(self.site_reference),
            "group_references": sanitize_references(self.group_references),
            "runtime_state": normalize_fleet_state(self.runtime_state),
            "health_state": normalize_fleet_state(self.health_state),
            "version_state": normalize_version_state(self.version_state),
            "last_checkin": str(self.last_checkin or ""),
            "telemetry_freshness": normalize_fleet_state(self.telemetry_freshness),
            "collector_status": normalize_fleet_state(self.collector_status),
            "observed_asset_count": max(0, int(self.observed_asset_count or 0)),
            "observed_flow_count": max(0, int(self.observed_flow_count or 0)),
            "risk_state": normalize_risk_state(self.risk_state),
            "source_mode": mode,
            "data_source": mode,
            "preview_only": True,
            "destructive_action": False,
            "advisory_notes": [sanitize_summary(note) for note in self.advisory_notes],
            **FLEET_SAFETY_FLAGS,
        }


@dataclass(frozen=True)
class FleetGroupSummary:
    summary_id: str
    summary_type: str
    site_reference: str = ""
    group_reference: str = ""
    node_count: int = 0
    active_count: int = 0
    degraded_count: int = 0
    stale_count: int = 0
    offline_count: int = 0
    highest_risk_state: str = "unknown"
    health_summary: dict[str, Any] = field(default_factory=dict)
    source_modes: list[str] = field(default_factory=list)
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "visual_fleet_group_summary",
            "record_version": FLEET_RECORD_VERSION,
            "summary_id": sanitize_reference(self.summary_id),
            "summary_type": _safe_token(self.summary_type),
            "site_reference": sanitize_reference(self.site_reference),
            "group_reference": sanitize_reference(self.group_reference),
            "node_count": max(0, int(self.node_count or 0)),
            "active_count": max(0, int(self.active_count or 0)),
            "degraded_count": max(0, int(self.degraded_count or 0)),
            "stale_count": max(0, int(self.stale_count or 0)),
            "offline_count": max(0, int(self.offline_count or 0)),
            "highest_risk_state": normalize_risk_state(self.highest_risk_state),
            "health_summary": dict(self.health_summary),
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "export_safe": True,
            **FLEET_SAFETY_FLAGS,
        }


def make_fleet_node_record(
    *,
    node_reference: Any,
    node_label: Any = "",
    node_role: Any = "unknown",
    site_reference: Any = "site-default",
    group_references: list[Any] | None = None,
    runtime_state: Any = "unknown",
    health_state: Any = "unknown",
    version_state: Any = "unknown",
    last_checkin: Any = "",
    telemetry_freshness: Any = "unknown",
    collector_status: Any = "unknown",
    observed_asset_count: Any = 0,
    observed_flow_count: Any = 0,
    risk_state: Any = "unknown",
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> FleetNodeRecord:
    node_ref = sanitize_reference(node_reference)
    mode = normalize_source_mode(source_mode)
    fleet_node_id = "fleet-node-" + _digest(
        {
            "node_reference": node_ref,
            "node_role": normalize_node_role(node_role),
            "site_reference": sanitize_reference(site_reference),
            "source_mode": mode,
        }
    )[:16]
    return FleetNodeRecord(
        fleet_node_id=fleet_node_id,
        node_reference=node_ref,
        node_label=sanitize_summary(node_label or f"{normalize_node_role(node_role)} node"),
        node_role=normalize_node_role(node_role),
        site_reference=sanitize_reference(site_reference) or "site-default",
        group_references=sanitize_references(group_references or []),
        runtime_state=normalize_fleet_state(runtime_state),
        health_state=normalize_fleet_state(health_state),
        version_state=normalize_version_state(version_state),
        last_checkin=str(last_checkin or ""),
        telemetry_freshness=normalize_fleet_state(telemetry_freshness),
        collector_status=normalize_fleet_state(collector_status),
        observed_asset_count=_safe_int(observed_asset_count),
        observed_flow_count=_safe_int(observed_flow_count),
        risk_state=normalize_risk_state(risk_state),
        source_mode=mode,
        preview_only=True,
        destructive_action=False,
        advisory_notes=[sanitize_summary(note) for note in advisory_notes or ["visual fleet node is advisory-only"]],
    )


def make_fleet_group_summary(
    *,
    summary_type: str,
    site_reference: Any = "",
    group_reference: Any = "",
    nodes: list[FleetNodeRecord] | None = None,
) -> FleetGroupSummary:
    rows = [node for node in nodes or [] if isinstance(node, FleetNodeRecord)]
    site_ref = sanitize_reference(site_reference)
    group_ref = sanitize_reference(group_reference)
    state_counts = {
        "active": sum(1 for node in rows if node.runtime_state == "active" and node.health_state == "active"),
        "degraded": sum(1 for node in rows if "degraded" in {node.runtime_state, node.health_state, node.collector_status}),
        "stale": sum(1 for node in rows if "stale" in {node.runtime_state, node.health_state, node.telemetry_freshness}),
        "offline": sum(1 for node in rows if "offline" in {node.runtime_state, node.health_state, node.collector_status}),
    }
    summary_id = "fleet-summary-" + _digest(
        {
            "summary_type": summary_type,
            "site_reference": site_ref,
            "group_reference": group_ref,
            "nodes": [node.fleet_node_id for node in rows],
        }
    )[:16]
    return FleetGroupSummary(
        summary_id=summary_id,
        summary_type=summary_type,
        site_reference=site_ref,
        group_reference=group_ref,
        node_count=len(rows),
        active_count=state_counts["active"],
        degraded_count=state_counts["degraded"],
        stale_count=state_counts["stale"],
        offline_count=state_counts["offline"],
        highest_risk_state=highest_risk_state([node.risk_state for node in rows]),
        health_summary={
            "active": state_counts["active"],
            "degraded": state_counts["degraded"],
            "stale": state_counts["stale"],
            "offline": state_counts["offline"],
            "unknown": sum(1 for node in rows if node.runtime_state == "unknown" or node.health_state == "unknown"),
        },
        source_modes=sorted({node.source_mode for node in rows}) or ["unknown"],
        export_safe=True,
    )


def normalize_node_role(value: Any) -> str:
    role = _safe_token(value)
    return role if role in FLEET_NODE_ROLES else "unknown"


def normalize_fleet_state(value: Any) -> str:
    state = _safe_token(value)
    if state in {"healthy", "ready", "ok", "online", "fresh", "current"}:
        return "active"
    return state if state in FLEET_STATES else "unknown"


def normalize_version_state(value: Any) -> str:
    state = _safe_token(value)
    if state in {"ready", "active", "fresh"}:
        return "current"
    return state if state in VERSION_STATES else "unknown"


def highest_risk_state(values: list[Any]) -> str:
    order = {"critical": 5, "high": 4, "elevated": 3, "degraded": 2, "nominal": 1, "empty": 0, "unknown": 0}
    normalized = [normalize_risk_state(value) for value in values]
    if not normalized:
        return "unknown"
    return max(normalized, key=lambda item: order.get(item, 0))


def deterministic_fleet_json(record: FleetNodeRecord | FleetGroupSummary | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (FleetNodeRecord, FleetGroupSummary)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _safe_token(value: Any) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    safe = "".join(char for char in token if char.isalnum() or char == "_")
    return safe[:64] or "unknown"


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
