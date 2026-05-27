from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.telemetry.flows import summarize_flows
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS
from core_engine.telemetry.dns_behavior import build_dns_destination_operator_panel
from core_engine.telemetry.service_fingerprints import build_service_fingerprint_operator_panel


LIVE_TELEMETRY_VIEW_RECORD_VERSION = 1
DEFAULT_UPDATE_INTERVAL_SECONDS = 5
MIN_UPDATE_INTERVAL_SECONDS = 1
MAX_UPDATE_INTERVAL_SECONDS = 60
DEFAULT_STALE_AFTER_SECONDS = 300

LIVE_TELEMETRY_VIEW_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "read_only": True,
    "dashboard_safe": True,
    "raw_payload_rendered": False,
    "packet_replay_enabled": False,
    "automatic_blocking": False,
    "tui_replaced": False,
    "parallel_dashboard_schema_created": False,
}


def build_live_telemetry_operator_summary(
    *,
    interface_inventory: dict[str, Any] | None = None,
    packet_window: dict[str, Any] | None = None,
    flows: Iterable[dict[str, Any]] | None = None,
    flow_summary: dict[str, Any] | None = None,
    protocol_report: dict[str, Any] | None = None,
    live_topology: dict[str, Any] | None = None,
    behavior_baseline_report: dict[str, Any] | None = None,
    temporal_anomaly_report: dict[str, Any] | None = None,
    service_fingerprint_report: dict[str, Any] | None = None,
    dns_destination_behavior_report: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    federation_diagnostics: dict[str, Any] | None = None,
    operator_visibility: dict[str, Any] | None = None,
    resource_usage: dict[str, Any] | None = None,
    requested_update_interval_seconds: int = DEFAULT_UPDATE_INTERVAL_SECONDS,
    min_update_interval_seconds: int = MIN_UPDATE_INTERVAL_SECONDS,
    max_update_interval_seconds: int = MAX_UPDATE_INTERVAL_SECONDS,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
    last_updated_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    flow_rows = _rows(flows)
    effective_flow_summary = dict(flow_summary or summarize_flows(flow_rows, generated_at=timestamp))
    panels = {
        "interfaces": build_interface_telemetry_summary(interface_inventory, generated_at=timestamp),
        "packet_rate": build_packet_rate_summary(packet_window, generated_at=timestamp),
        "flow_rate": build_flow_rate_summary(flows=flow_rows, flow_summary=effective_flow_summary, generated_at=timestamp),
        "live_topology": build_live_topology_rendering_summary(live_topology, generated_at=timestamp),
        "protocol_distribution": build_protocol_distribution_summary(protocol_report, generated_at=timestamp),
        "resource_usage": build_resource_usage_telemetry_summary(resource_usage=resource_usage, runtime_health=runtime_health, generated_at=timestamp),
        "federation_rollup": build_federation_aware_telemetry_rollup(
            live_topology=live_topology,
            federation_diagnostics=federation_diagnostics,
            operator_visibility=operator_visibility,
            generated_at=timestamp,
        ),
    }
    if behavior_baseline_report is not None:
        panels["behavior_baselines"] = build_behavior_baseline_operator_panel(behavior_baseline_report, generated_at=timestamp)
    if temporal_anomaly_report is not None:
        panels["temporal_anomalies"] = build_temporal_anomaly_operator_panel(temporal_anomaly_report, generated_at=timestamp)
    if service_fingerprint_report is not None:
        panels["service_fingerprints"] = build_service_fingerprint_operator_panel(service_fingerprint_report, generated_at=timestamp)
    if dns_destination_behavior_report is not None:
        panels["dns_destination_behavior"] = build_dns_destination_operator_panel(dns_destination_behavior_report, generated_at=timestamp)
    update_controls = build_bounded_update_interval_controls(
        requested_update_interval_seconds=requested_update_interval_seconds,
        min_update_interval_seconds=min_update_interval_seconds,
        max_update_interval_seconds=max_update_interval_seconds,
        stale_after_seconds=stale_after_seconds,
        generated_at=timestamp,
    )
    stale_state = build_stale_telemetry_state_model(
        last_updated_at=last_updated_at or _latest_generated_at(
            interface_inventory,
            packet_window,
            effective_flow_summary,
            protocol_report,
            live_topology,
            behavior_baseline_report,
            temporal_anomaly_report,
            service_fingerprint_report,
            dns_destination_behavior_report,
            runtime_health,
            federation_diagnostics,
            operator_visibility,
        ),
        generated_at=timestamp,
        stale_after_seconds=stale_after_seconds,
    )
    health = build_telemetry_health_status_summary(panels=panels, stale_state=stale_state, update_controls=update_controls, generated_at=timestamp)
    summary = summarize_live_telemetry_panels(panels=panels, health=health, stale_state=stale_state, generated_at=timestamp)
    empty_state = build_empty_live_telemetry_model(generated_at=timestamp) if summary["empty_state"] else None
    api = build_live_telemetry_api_response(
        panels=panels,
        summary=summary,
        health=health,
        update_controls=update_controls,
        empty_state=empty_state,
        stale_state=stale_state,
        generated_at=timestamp,
    )
    return {
        "record_type": "live_telemetry_operator_summary",
        "record_version": LIVE_TELEMETRY_VIEW_RECORD_VERSION,
        "generated_at": timestamp,
        "status": health["status"],
        "panels": panels,
        "summary": summary,
        "health_summary": health,
        "update_controls": update_controls,
        "empty_state": empty_state,
        "stale_state": stale_state,
        "api_status": api,
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_interface_telemetry_summary(interface_inventory: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not interface_inventory:
        return _empty_panel("interfaces", generated_at=timestamp)
    summary = interface_inventory.get("summary") if isinstance(interface_inventory.get("summary"), dict) else {}
    dashboard = interface_inventory.get("dashboard_status") if isinstance(interface_inventory.get("dashboard_status"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "interface_telemetry_dashboard_summary",
        "panel": "interfaces",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "interface_count": int(metrics.get("interface_count") or summary.get("interface_count") or 0),
            "operator_selectable_count": int(metrics.get("operator_selectable_count") or summary.get("operator_selectable_count") or 0),
            "ipv4_interface_count": int(summary.get("ipv4_interface_count") or 0),
            "ipv6_interface_count": int(summary.get("ipv6_interface_count") or 0),
            "loopback_count": int(summary.get("loopback_count") or 0),
        },
        "rows": [
            {
                "interface_name": row.get("interface_name"),
                "classification": row.get("classification"),
                "operator_selectable": row.get("operator_selectable"),
                "address_family_summary": row.get("address_family_summary"),
            }
            for row in sorted(_rows(interface_inventory.get("interfaces")), key=lambda item: str(item.get("interface_name") or ""))
        ],
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_packet_rate_summary(packet_window: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not packet_window:
        return _empty_panel("packet_rate", generated_at=timestamp)
    summary = packet_window.get("summary") if isinstance(packet_window.get("summary"), dict) else {}
    rate = summary.get("packet_rate_summary") if isinstance(summary.get("packet_rate_summary"), dict) else {}
    return {
        "record_type": "packet_rate_dashboard_summary",
        "panel": "packet_rate",
        "status": str((packet_window.get("dashboard_status") or {}).get("status") if isinstance(packet_window.get("dashboard_status"), dict) else "ok"),
        "generated_at": timestamp,
        "metrics": {
            "metadata_record_count": int(summary.get("metadata_record_count") or 0),
            "accepted_count": int(summary.get("accepted_count") or 0),
            "duplicate_count": int(summary.get("duplicate_count") or 0),
            "stale_count": int(summary.get("stale_count") or 0),
            "malformed_count": int(summary.get("malformed_count") or 0),
            "unsupported_count": int(summary.get("unsupported_count") or 0),
            "truncated_count": int(summary.get("truncated_count") or 0),
            "packets_per_second": float(rate.get("packets_per_second") or 0.0),
            "accepted_packets_per_second": float(rate.get("accepted_packets_per_second") or 0.0),
        },
        "transport_summary": dict(summary.get("transport_summary") or {}),
        "interface_summary": dict(summary.get("interface_summary") or {}),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_flow_rate_summary(
    *,
    flows: Iterable[dict[str, Any]] | None = None,
    flow_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = _rows(flows)
    summary = dict(flow_summary or summarize_flows(rows, generated_at=timestamp))
    duration = _flow_duration_seconds(rows)
    flow_count = int(summary.get("flow_count") or len(rows))
    return {
        "record_type": "flow_rate_dashboard_summary",
        "panel": "flow_rate",
        "status": "ok" if int(summary.get("malformed_flow_count") or 0) == 0 else "review_required",
        "generated_at": timestamp,
        "metrics": {
            "flow_count": flow_count,
            "complete_flow_count": int(summary.get("complete_flow_count") or 0),
            "partial_flow_count": int(summary.get("partial_flow_count") or 0),
            "malformed_flow_count": int(summary.get("malformed_flow_count") or 0),
            "packet_count": int(summary.get("packet_count") or 0),
            "byte_count": int(summary.get("byte_count") or 0),
            "duration_seconds": duration,
            "flows_per_second": round(flow_count / duration, 2) if duration > 0 else 0.0,
        },
        "by_transport": dict(summary.get("by_transport") or {}),
        "by_service": dict(summary.get("by_service") or {}),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_live_topology_rendering_summary(live_topology: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not live_topology:
        return _empty_panel("live_topology", generated_at=timestamp)
    dashboard = live_topology.get("dashboard_status") if isinstance(live_topology.get("dashboard_status"), dict) else {}
    graph = live_topology.get("graph") if isinstance(live_topology.get("graph"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "live_topology_rendering_summary",
        "panel": "live_topology",
        "status": str(dashboard.get("status") or live_topology.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "node_count": int(metrics.get("node_count") or graph.get("node_count") or 0),
            "edge_count": int(metrics.get("edge_count") or graph.get("edge_count") or 0),
            "added_edge_count": int(metrics.get("added_edge_count") or 0),
            "protocol_anomaly_count": int(metrics.get("protocol_anomaly_count") or 0),
            "federation_aware": bool(metrics.get("federation_aware") or (live_topology.get("cluster_federation_summary") or {}).get("federation_aware")),
        },
        "nodes": list(dashboard.get("nodes") or []),
        "edges": list(dashboard.get("edges") or []),
        "warnings": list(dashboard.get("warnings") or []),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_protocol_distribution_summary(protocol_report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not protocol_report:
        return _empty_panel("protocol_distribution", generated_at=timestamp)
    summary = protocol_report.get("summary") if isinstance(protocol_report.get("summary"), dict) else {}
    dashboard = protocol_report.get("dashboard_status") if isinstance(protocol_report.get("dashboard_status"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "protocol_distribution_dashboard_summary",
        "panel": "protocol_distribution",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "record_count": int(metrics.get("record_count") or summary.get("record_count") or 0),
            "anomaly_count": int(metrics.get("anomaly_count") or summary.get("anomaly_count") or 0),
            "highest_confidence": float(metrics.get("highest_confidence") or summary.get("highest_confidence") or 0.0),
            "truncated_field_count": int(summary.get("truncated_field_count") or 0),
        },
        "by_protocol": dict(summary.get("by_protocol") or {}),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_behavior_baseline_operator_panel(behavior_baseline_report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not behavior_baseline_report:
        return _empty_panel("behavior_baselines", generated_at=timestamp)
    dashboard = behavior_baseline_report.get("dashboard_status") if isinstance(behavior_baseline_report.get("dashboard_status"), dict) else {}
    summary = behavior_baseline_report.get("summary") if isinstance(behavior_baseline_report.get("summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "behavior_baseline_operator_panel",
        "panel": "behavior_baselines",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "baseline_entry_count": int(metrics.get("baseline_entry_count") or summary.get("baseline_entry_count") or 0),
            "stable_behavior_count": int(metrics.get("stable_behavior_count") or summary.get("stable_behavior_count") or 0),
            "novel_behavior_count": int(metrics.get("novel_behavior_count") or summary.get("novel_behavior_count") or 0),
            "decaying_inactive_count": int(metrics.get("decaying_inactive_count") or summary.get("decaying_inactive_count") or 0),
            "average_confidence": float(metrics.get("average_confidence") or summary.get("average_confidence") or 0.0),
        },
        "by_category": dict(summary.get("by_category") or {}),
        "by_behavior_state": dict(summary.get("by_behavior_state") or {}),
        "rows": list(dashboard.get("rows") or []),
        "recommended_review": bool(dashboard.get("recommended_review")),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_temporal_anomaly_operator_panel(temporal_anomaly_report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not temporal_anomaly_report:
        return _empty_panel("temporal_anomalies", generated_at=timestamp)
    dashboard = temporal_anomaly_report.get("dashboard_status") if isinstance(temporal_anomaly_report.get("dashboard_status"), dict) else {}
    summary = temporal_anomaly_report.get("summary") if isinstance(temporal_anomaly_report.get("summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "temporal_anomaly_operator_panel",
        "panel": "temporal_anomalies",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "anomaly_count": int(metrics.get("anomaly_count") or summary.get("anomaly_count") or 0),
            "burst_count": int(metrics.get("burst_count") or summary.get("burst_count") or 0),
            "rare_service_timing_count": int(metrics.get("rare_service_timing_count") or summary.get("rare_service_timing_count") or 0),
            "volume_drift_count": int(metrics.get("volume_drift_count") or summary.get("volume_drift_count") or 0),
            "novel_behavior_count": int(metrics.get("novel_behavior_count") or summary.get("novel_behavior_count") or 0),
            "average_confidence": float(metrics.get("average_confidence") or summary.get("average_confidence") or 0.0),
        },
        "by_label": dict(summary.get("by_label") or {}),
        "by_window": dict(summary.get("by_window") or {}),
        "rows": list(dashboard.get("rows") or []),
        "recommended_review": bool(dashboard.get("recommended_review")),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_resource_usage_telemetry_summary(
    *,
    resource_usage: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    usage = resource_usage if isinstance(resource_usage, dict) else {}
    checks = _rows((runtime_health or {}).get("checks"))
    warning_count = sum(1 for check in checks if str(check.get("status") or "") not in {"ok", "not_configured"})
    return {
        "record_type": "resource_usage_telemetry_summary",
        "panel": "resource_usage",
        "status": str(usage.get("status") or ("review_required" if warning_count else "ok")),
        "generated_at": timestamp,
        "metrics": {
            "cpu_percent": float(usage.get("cpu_percent") or 0.0),
            "memory_mb": int(usage.get("memory_mb") or 0),
            "storage_mb": int(usage.get("storage_mb") or 0),
            "warning_count": int(usage.get("warning_count") or warning_count),
            "health_check_count": len(checks),
        },
        "warnings": list(usage.get("warnings") or []),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_federation_aware_telemetry_rollup(
    *,
    live_topology: dict[str, Any] | None = None,
    federation_diagnostics: dict[str, Any] | None = None,
    operator_visibility: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    cluster = live_topology.get("cluster_federation_summary") if isinstance((live_topology or {}).get("cluster_federation_summary"), dict) else {}
    diagnostics_summary = federation_diagnostics.get("summary") if isinstance((federation_diagnostics or {}).get("summary"), dict) else {}
    visibility_summary = operator_visibility.get("summary") if isinstance((operator_visibility or {}).get("summary"), dict) else {}
    node_count = int(cluster.get("source_node_ids") and len(cluster.get("source_node_ids")) or visibility_summary.get("node_count") or diagnostics_summary.get("trusted_peer_count") or 0)
    readiness = int(diagnostics_summary.get("readiness_score") or (federation_diagnostics or {}).get("readiness_score") or 0)
    return {
        "record_type": "federation_aware_telemetry_rollup",
        "panel": "federation_rollup",
        "status": str((federation_diagnostics or {}).get("status") or ("ok" if readiness >= 80 or not federation_diagnostics else "review_required")),
        "generated_at": timestamp,
        "metrics": {
            "source_node_count": node_count,
            "federation_aware": bool(cluster.get("federation_aware") or node_count > 1 or federation_diagnostics),
            "readiness_score": readiness,
            "rejected_update_count": int(diagnostics_summary.get("rejected_update_count") or 0),
            "duplicate_event_count": int(diagnostics_summary.get("duplicate_event_count") or 0),
        },
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_bounded_update_interval_controls(
    *,
    requested_update_interval_seconds: int,
    min_update_interval_seconds: int = MIN_UPDATE_INTERVAL_SECONDS,
    max_update_interval_seconds: int = MAX_UPDATE_INTERVAL_SECONDS,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    minimum = max(1, int(min_update_interval_seconds))
    maximum = max(minimum, int(max_update_interval_seconds))
    requested = int(requested_update_interval_seconds)
    effective = min(max(requested, minimum), maximum)
    return {
        "record_type": "bounded_telemetry_update_interval_controls",
        "generated_at": generated_at or _now(),
        "requested_update_interval_seconds": requested,
        "effective_update_interval_seconds": effective,
        "min_update_interval_seconds": minimum,
        "max_update_interval_seconds": maximum,
        "stale_after_seconds": int(stale_after_seconds),
        "bounded": requested == effective,
        "update_loop_started": False,
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_stale_telemetry_state_model(
    *,
    last_updated_at: str | None,
    generated_at: str | None = None,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    age = _age_seconds(last_updated_at, timestamp)
    stale = bool(age is not None and age > int(stale_after_seconds))
    return {
        "record_type": "stale_live_telemetry_state_model",
        "generated_at": timestamp,
        "last_updated_at": last_updated_at,
        "age_seconds": age,
        "stale_after_seconds": int(stale_after_seconds),
        "stale": stale,
        "status": "stale" if stale else "current" if last_updated_at else "empty",
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_empty_live_telemetry_model(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "empty_live_telemetry_model",
        "generated_at": generated_at or _now(),
        "status": "empty",
        "message": "No live telemetry summaries are available.",
        "panels": [],
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_telemetry_health_status_summary(
    *,
    panels: dict[str, dict[str, Any]],
    stale_state: dict[str, Any],
    update_controls: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    panel_statuses = {name: str(panel.get("status") or "unknown") for name, panel in panels.items()}
    warning_count = sum(1 for status in panel_statuses.values() if status in {"review_required", "degraded", "error", "stale"})
    if stale_state.get("stale"):
        warning_count += 1
    if not update_controls.get("bounded"):
        warning_count += 1
    return {
        "record_type": "live_telemetry_health_status_summary",
        "generated_at": generated_at or _now(),
        "status": "review_required" if warning_count else "ok",
        "panel_statuses": dict(sorted(panel_statuses.items())),
        "warning_count": warning_count,
        "stale": bool(stale_state.get("stale")),
        "update_interval_bounded": bool(update_controls.get("bounded")),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def summarize_live_telemetry_panels(
    *,
    panels: dict[str, dict[str, Any]],
    health: dict[str, Any],
    stale_state: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    metrics = {name: panel.get("metrics") if isinstance(panel.get("metrics"), dict) else {} for name, panel in panels.items()}
    packet_count = int(metrics.get("packet_rate", {}).get("metadata_record_count") or 0)
    flow_count = int(metrics.get("flow_rate", {}).get("flow_count") or 0)
    interface_count = int(metrics.get("interfaces", {}).get("interface_count") or 0)
    topology_node_count = int(metrics.get("live_topology", {}).get("node_count") or 0)
    protocol_count = int(metrics.get("protocol_distribution", {}).get("record_count") or 0)
    behavior_count = int(metrics.get("behavior_baselines", {}).get("baseline_entry_count") or 0)
    anomaly_count = int(metrics.get("temporal_anomalies", {}).get("anomaly_count") or 0)
    fingerprint_count = int(metrics.get("service_fingerprints", {}).get("profile_count") or 0)
    dns_destination_count = int(metrics.get("dns_destination_behavior", {}).get("destination_count") or 0)
    return {
        "record_type": "live_telemetry_dashboard_summary",
        "generated_at": generated_at or _now(),
        "status": str(health.get("status") or "unknown"),
        "interface_count": interface_count,
        "packet_count": packet_count,
        "flow_count": flow_count,
        "topology_node_count": topology_node_count,
        "topology_edge_count": int(metrics.get("live_topology", {}).get("edge_count") or 0),
        "protocol_record_count": protocol_count,
        "behavior_baseline_count": behavior_count,
        "temporal_anomaly_count": anomaly_count,
        "service_fingerprint_count": fingerprint_count,
        "dns_destination_behavior_count": dns_destination_count,
        "federation_aware": bool(metrics.get("federation_rollup", {}).get("federation_aware")),
        "empty_state": not any((interface_count, packet_count, flow_count, topology_node_count, protocol_count, behavior_count, anomaly_count, fingerprint_count, dns_destination_count)),
        "stale": bool(stale_state.get("stale")),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def build_live_telemetry_api_response(
    *,
    panels: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    health: dict[str, Any],
    update_controls: dict[str, Any],
    empty_state: dict[str, Any] | None,
    stale_state: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "live_telemetry_api",
        "generated_at": generated_at or _now(),
        "status": str(health.get("status") or "unknown"),
        "count": len(panels),
        "summary": dict(summary),
        "panels": panels,
        "health_summary": dict(health),
        "update_controls": dict(update_controls),
        "empty_state": empty_state,
        "stale_state": dict(stale_state),
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def deterministic_live_telemetry_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _empty_panel(panel: str, *, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": f"{panel}_empty_dashboard_summary",
        "panel": panel,
        "status": "empty",
        "generated_at": generated_at,
        "metrics": {},
        "rows": [],
        **LIVE_TELEMETRY_VIEW_SAFETY_FLAGS,
    }


def _flow_duration_seconds(rows: list[dict[str, Any]]) -> int:
    values = []
    for row in rows:
        values.extend([str(row.get("first_seen") or ""), str(row.get("last_seen") or "")])
    parsed = [_parse_time(value) for value in values if value]
    parsed = [value for value in parsed if value is not None]
    if len(parsed) < 2:
        return 0
    return max(1, int((max(parsed) - min(parsed)).total_seconds()))


def _latest_generated_at(*records: Any) -> str | None:
    values = [str(record.get("generated_at") or "") for record in records if isinstance(record, dict) and record.get("generated_at")]
    return max(values) if values else None


def _age_seconds(start: str | None, end: str) -> int | None:
    if not start:
        return None
    start_dt = _parse_time(start)
    end_dt = _parse_time(end)
    if not start_dt or not end_dt:
        return None
    return max(0, int((end_dt - start_dt).total_seconds()))


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _rows(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()
