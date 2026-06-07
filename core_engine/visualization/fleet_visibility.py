from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable

from core_engine.visualization.fleet_models import (
    FLEET_RECORD_VERSION,
    FLEET_SAFETY_FLAGS,
    FleetGroupSummary,
    FleetNodeRecord,
    FleetVisibilityError,
    highest_risk_state,
    make_fleet_group_summary,
    make_fleet_node_record,
    normalize_fleet_state,
    normalize_node_role,
    normalize_version_state,
)
from core_engine.visualization.risk_dashboard import normalize_risk_state
from core_engine.visualization.timeline_models import sanitize_reference, sanitize_references
from core_engine.visualization.topology_models import normalize_source_mode, now_timestamp


DEFAULT_MAX_FLEET_NODES = 256


@dataclass(frozen=True)
class FleetVisibilityPanel:
    fleet_panel_id: str
    generated_at: str
    node_count: int
    site_count: int
    group_count: int
    active_count: int
    degraded_count: int
    stale_count: int
    offline_count: int
    highest_risk_state: str
    nodes: list[FleetNodeRecord] = field(default_factory=list)
    site_summaries: list[FleetGroupSummary] = field(default_factory=list)
    group_summaries: list[FleetGroupSummary] = field(default_factory=list)
    empty_state: bool = False
    degraded_state: bool = False
    bounded: bool = True
    max_nodes: int = DEFAULT_MAX_FLEET_NODES
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        node_rows = [node.to_dict() for node in self.nodes]
        site_rows = [summary.to_dict() for summary in self.site_summaries]
        group_rows = [summary.to_dict() for summary in self.group_summaries]
        return {
            "record_type": "visual_fleet_visibility_panel",
            "record_version": FLEET_RECORD_VERSION,
            "fleet_panel_id": sanitize_reference(self.fleet_panel_id),
            "generated_at": str(self.generated_at or ""),
            "node_count": max(0, int(self.node_count or 0)),
            "site_count": max(0, int(self.site_count or 0)),
            "group_count": max(0, int(self.group_count or 0)),
            "active_count": max(0, int(self.active_count or 0)),
            "degraded_count": max(0, int(self.degraded_count or 0)),
            "stale_count": max(0, int(self.stale_count or 0)),
            "offline_count": max(0, int(self.offline_count or 0)),
            "highest_risk_state": normalize_risk_state(self.highest_risk_state),
            "nodes": node_rows,
            "site_summaries": site_rows,
            "group_summaries": group_rows,
            "empty_state": bool(self.empty_state),
            "degraded_state": bool(self.degraded_state),
            "bounded": True,
            "max_nodes": max(0, int(self.max_nodes or 0)),
            "export_safe": True,
            "preview_only": True,
            "destructive_action": False,
            **FLEET_SAFETY_FLAGS,
        }


def build_fleet_visibility_panel(
    *,
    runtime_node_summaries: Iterable[dict[str, Any]] | None = None,
    federation_summaries: Iterable[dict[str, Any]] | None = None,
    deployment_summaries: Iterable[dict[str, Any]] | None = None,
    cluster_health_summaries: Iterable[dict[str, Any]] | None = None,
    topology_summaries: Iterable[dict[str, Any]] | None = None,
    asset_inventory: dict[str, Any] | None = None,
    risk_dashboard: dict[str, Any] | None = None,
    generated_at: str | None = None,
    max_nodes: int = DEFAULT_MAX_FLEET_NODES,
) -> FleetVisibilityPanel:
    _validate_iterable("runtime_node_summaries", runtime_node_summaries)
    _validate_iterable("federation_summaries", federation_summaries)
    _validate_iterable("deployment_summaries", deployment_summaries)
    _validate_iterable("cluster_health_summaries", cluster_health_summaries)
    _validate_iterable("topology_summaries", topology_summaries)
    timestamp = generated_at or now_timestamp()
    seed_rows = []
    seed_rows.extend(_dict_rows(runtime_node_summaries))
    seed_rows.extend(_seeds_from_federation(_dict_rows(federation_summaries)))
    seed_rows.extend(_seeds_from_deployment(_dict_rows(deployment_summaries)))
    seed_rows.extend(_seeds_from_cluster_health(_dict_rows(cluster_health_summaries)))
    seed_rows.extend(_seeds_from_topology(_dict_rows(topology_summaries)))
    if not seed_rows:
        return empty_fleet_visibility_panel(generated_at=timestamp, max_nodes=max_nodes)
    asset_count = _asset_count(asset_inventory)
    flow_count = _flow_count_from_risk(risk_dashboard)
    risk_state = _risk_state_from_dashboard(risk_dashboard)
    nodes = [
        fleet_node_from_summary(
            row,
            generated_at=timestamp,
            default_asset_count=asset_count,
            default_flow_count=flow_count,
            default_risk_state=risk_state,
        )
        for row in seed_rows
        if isinstance(row, dict)
    ]
    deduped = deduplicate_fleet_nodes(nodes)
    bounded = deduped[: max(0, int(max_nodes))]
    return summarize_fleet_visibility(bounded, generated_at=timestamp, max_nodes=max_nodes)


def fleet_node_from_summary(
    row: dict[str, Any],
    *,
    generated_at: str | None = None,
    default_asset_count: int = 0,
    default_flow_count: int = 0,
    default_risk_state: str = "unknown",
) -> FleetNodeRecord:
    if not isinstance(row, dict):
        raise FleetVisibilityError("node summary must be an object")
    node_reference = row.get("node_reference") or row.get("node_id") or row.get("node_name") or row.get("collector_id") or "node-unknown"
    role = _role_from_row(row)
    runtime_state = _state_from_runtime(row)
    health_state = _state_from_health(row)
    freshness = _freshness_from_row(row)
    collector_status = _collector_status_from_row(row)
    version_state = _version_state_from_row(row)
    return make_fleet_node_record(
        node_reference=node_reference,
        node_label=row.get("node_label") or row.get("display_name") or f"{role} node",
        node_role=role,
        site_reference=row.get("site_reference") or row.get("site_id") or "site-default",
        group_references=_group_references(row),
        runtime_state=runtime_state,
        health_state=health_state,
        version_state=version_state,
        last_checkin=row.get("last_checkin") or row.get("last_seen") or row.get("timestamp") or generated_at or "",
        telemetry_freshness=freshness,
        collector_status=collector_status,
        observed_asset_count=row.get("observed_asset_count") or row.get("asset_count") or default_asset_count,
        observed_flow_count=row.get("observed_flow_count") or row.get("flow_count") or default_flow_count,
        risk_state=row.get("risk_state") or default_risk_state,
        source_mode=row.get("source_mode") or row.get("data_source") or "unknown",
        advisory_notes=row.get("advisory_notes") or ["fleet visibility record uses sanitized metadata only"],
    )


def summarize_fleet_visibility(
    nodes: Iterable[FleetNodeRecord],
    *,
    generated_at: str | None = None,
    max_nodes: int = DEFAULT_MAX_FLEET_NODES,
) -> FleetVisibilityPanel:
    rows = sorted([node for node in nodes or [] if isinstance(node, FleetNodeRecord)], key=lambda item: item.fleet_node_id)
    site_summaries = _site_summaries(rows)
    group_summaries = _group_summaries(rows)
    timestamp = generated_at or now_timestamp()
    return FleetVisibilityPanel(
        fleet_panel_id="fleet-panel-" + _digest({"generated_at": timestamp, "nodes": [node.fleet_node_id for node in rows], "max_nodes": max_nodes})[:16],
        generated_at=timestamp,
        node_count=len(rows),
        site_count=len(site_summaries),
        group_count=len(group_summaries),
        active_count=sum(1 for node in rows if node.runtime_state == "active" and node.health_state == "active"),
        degraded_count=sum(1 for node in rows if "degraded" in {node.runtime_state, node.health_state, node.collector_status}),
        stale_count=sum(1 for node in rows if "stale" in {node.runtime_state, node.health_state, node.telemetry_freshness}),
        offline_count=sum(1 for node in rows if "offline" in {node.runtime_state, node.health_state, node.collector_status}),
        highest_risk_state=highest_risk_state([node.risk_state for node in rows]),
        nodes=rows,
        site_summaries=site_summaries,
        group_summaries=group_summaries,
        empty_state=len(rows) == 0,
        degraded_state=any(node.health_state in {"degraded", "stale", "offline"} or node.runtime_state in {"degraded", "stale", "offline"} for node in rows),
        bounded=True,
        max_nodes=max_nodes,
        export_safe=True,
    )


def empty_fleet_visibility_panel(*, generated_at: str | None = None, max_nodes: int = DEFAULT_MAX_FLEET_NODES) -> FleetVisibilityPanel:
    return summarize_fleet_visibility([], generated_at=generated_at or now_timestamp(), max_nodes=max_nodes)


def deduplicate_fleet_nodes(nodes: Iterable[FleetNodeRecord]) -> list[FleetNodeRecord]:
    grouped: dict[str, FleetNodeRecord] = {}
    for node in nodes or []:
        if not isinstance(node, FleetNodeRecord):
            continue
        existing = grouped.get(node.node_reference)
        if existing is None:
            grouped[node.node_reference] = node
            continue
        grouped[node.node_reference] = _merge_fleet_nodes(existing, node)
    return sorted(grouped.values(), key=lambda item: item.fleet_node_id)


def deterministic_fleet_visibility_json(record: FleetVisibilityPanel | FleetNodeRecord | FleetGroupSummary | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (FleetVisibilityPanel, FleetNodeRecord, FleetGroupSummary)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _merge_fleet_nodes(left: FleetNodeRecord, right: FleetNodeRecord) -> FleetNodeRecord:
    return make_fleet_node_record(
        node_reference=left.node_reference,
        node_label=left.node_label,
        node_role=left.node_role if left.node_role != "unknown" else right.node_role,
        site_reference=left.site_reference or right.site_reference,
        group_references=sorted(set(left.group_references + right.group_references)),
        runtime_state=_preferred_state(left.runtime_state, right.runtime_state),
        health_state=_preferred_state(left.health_state, right.health_state),
        version_state=left.version_state if left.version_state != "unknown" else right.version_state,
        last_checkin=max(left.last_checkin, right.last_checkin),
        telemetry_freshness=_preferred_state(left.telemetry_freshness, right.telemetry_freshness),
        collector_status=_preferred_state(left.collector_status, right.collector_status),
        observed_asset_count=max(left.observed_asset_count, right.observed_asset_count),
        observed_flow_count=max(left.observed_flow_count, right.observed_flow_count),
        risk_state=highest_risk_state([left.risk_state, right.risk_state]),
        source_mode=left.source_mode if left.source_mode != "unknown" else right.source_mode,
        advisory_notes=sorted(set(left.advisory_notes + right.advisory_notes)),
    )


def _site_summaries(nodes: list[FleetNodeRecord]) -> list[FleetGroupSummary]:
    grouped: dict[str, list[FleetNodeRecord]] = defaultdict(list)
    for node in nodes:
        grouped[node.site_reference or "site-default"].append(node)
    return [
        make_fleet_group_summary(summary_type="site", site_reference=site_ref, nodes=rows)
        for site_ref, rows in sorted(grouped.items())
    ]


def _group_summaries(nodes: list[FleetNodeRecord]) -> list[FleetGroupSummary]:
    grouped: dict[str, list[FleetNodeRecord]] = defaultdict(list)
    for node in nodes:
        groups = node.group_references or ["group-default"]
        for group_ref in groups:
            grouped[group_ref].append(node)
    return [
        make_fleet_group_summary(summary_type="group", group_reference=group_ref, nodes=rows)
        for group_ref, rows in sorted(grouped.items())
    ]


def _role_from_row(row: dict[str, Any]) -> str:
    role = row.get("node_role") or row.get("role") or row.get("node_class") or "unknown"
    normalized = normalize_node_role(role)
    if normalized != "unknown":
        return normalized
    text = " ".join(str(row.get(key) or "").lower() for key in ("collector_type", "deployment_mode", "runtime_role"))
    if "gateway" in text:
        return "gateway_collector"
    if "edge" in text:
        return "edge_collector"
    if "worker" in text:
        return "worker"
    if "master" in text:
        return "master"
    if "orchestrator" in text:
        return "orchestrator"
    return "unknown"


def _state_from_runtime(row: dict[str, Any]) -> str:
    return normalize_fleet_state(row.get("runtime_state") or row.get("state") or row.get("status"))


def _state_from_health(row: dict[str, Any]) -> str:
    return normalize_fleet_state(row.get("health_state") or row.get("runtime_health") or row.get("collector_health") or row.get("state"))


def _freshness_from_row(row: dict[str, Any]) -> str:
    explicit = normalize_fleet_state(row.get("telemetry_freshness") or row.get("freshness_state"))
    if explicit != "unknown":
        return explicit
    age = _safe_float(row.get("telemetry_age_seconds") or row.get("checkin_age_seconds"))
    if age <= 0:
        return "unknown"
    if age <= 120:
        return "active"
    if age <= 900:
        return "stale"
    return "offline"


def _collector_status_from_row(row: dict[str, Any]) -> str:
    return normalize_fleet_state(row.get("collector_status") or row.get("collector_state") or row.get("health_state") or row.get("state"))


def _version_state_from_row(row: dict[str, Any]) -> str:
    return normalize_version_state(row.get("version_state") or row.get("compatibility_state") or row.get("deployment_state"))


def _group_references(row: dict[str, Any]) -> list[str]:
    values = row.get("group_references") or row.get("groups") or row.get("group_reference") or row.get("group_id") or ["group-default"]
    if isinstance(values, list):
        return sanitize_references(values)
    return sanitize_references([values])


def _seeds_from_federation(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seeds = []
    for row in rows:
        for peer in row.get("peers") or row.get("nodes") or []:
            if isinstance(peer, dict):
                seeds.append({**peer, "source_mode": peer.get("source_mode") or row.get("source_mode")})
    return seeds


def _seeds_from_deployment(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "node_reference": row.get("node_reference") or row.get("manifest_id") or row.get("deployment_id"),
            "node_role": row.get("node_role") or row.get("deployment_mode") or "unknown",
            "deployment_state": row.get("deployment_state") or row.get("readiness_state"),
            "version_state": row.get("version_state") or row.get("compatibility_state"),
            "site_reference": row.get("site_reference"),
            "group_references": row.get("group_references"),
            "source_mode": row.get("source_mode") or row.get("data_source"),
        }
        for row in rows
    ]


def _seeds_from_cluster_health(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "node_reference": row.get("node_reference") or row.get("node_id") or row.get("cluster_node_id"),
            "node_role": row.get("node_role") or row.get("role"),
            "health_state": row.get("health_state") or row.get("cluster_state"),
            "runtime_state": row.get("runtime_state") or row.get("state"),
            "last_checkin": row.get("last_checkin") or row.get("timestamp"),
            "source_mode": row.get("source_mode") or row.get("data_source"),
        }
        for row in rows
    ]


def _seeds_from_topology(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seeds = []
    for graph in rows:
        for node in graph.get("nodes") or []:
            if isinstance(node, dict):
                seeds.append(
                    {
                        "node_reference": node.get("node_id"),
                        "node_label": node.get("label"),
                        "node_role": node.get("role_hint") or node.get("node_class"),
                        "runtime_state": "active",
                        "health_state": "active",
                        "source_mode": node.get("source_mode") or node.get("data_source"),
                    }
                )
    return seeds


def _asset_count(inventory: dict[str, Any] | None) -> int:
    if not isinstance(inventory, dict):
        return 0
    try:
        return max(0, int(inventory.get("asset_count") or len(inventory.get("assets") or [])))
    except (TypeError, ValueError):
        return 0


def _flow_count_from_risk(risk_dashboard: dict[str, Any] | None) -> int:
    if not isinstance(risk_dashboard, dict):
        return 0
    cards = risk_dashboard.get("cards") or []
    if not isinstance(cards, list):
        return 0
    flow_refs = set()
    for card in cards:
        if isinstance(card, dict):
            flow_refs.update(sanitize_references(card.get("related_flow_references") or []))
    return len(flow_refs)


def _risk_state_from_dashboard(risk_dashboard: dict[str, Any] | None) -> str:
    if not isinstance(risk_dashboard, dict):
        return "unknown"
    return normalize_risk_state(risk_dashboard.get("risk_state") or "unknown")


def _preferred_state(left: str, right: str) -> str:
    order = {"offline": 5, "stale": 4, "degraded": 3, "active": 2, "unknown": 0}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _dict_rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _validate_iterable(name: str, values: Any) -> None:
    if values is None:
        return
    try:
        iter(values)
    except TypeError as exc:
        raise FleetVisibilityError(f"{name} must be iterable") from exc
    if isinstance(values, (str, bytes)):
        raise FleetVisibilityError(f"{name} must be iterable")


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
