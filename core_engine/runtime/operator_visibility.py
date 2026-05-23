from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.runtime.distributed_state import SAFETY_FLAGS


OPERATOR_VISIBILITY_RECORD_VERSION = 1
VISIBILITY_SAFETY_FLAGS = {
    **SAFETY_FLAGS,
    "read_only": True,
    "api_compatible": True,
    "public_exposure_enabled": False,
    "cloud_sync_enabled": False,
    "remote_control_enabled": False,
}


def build_operator_visibility_summary(
    *,
    distributed_state: dict[str, Any] | None = None,
    federated_topology: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    distributed_review: dict[str, Any] | None = None,
    coordinated_export: dict[str, Any] | None = None,
    service_readiness_by_node: dict[str, dict[str, Any]] | Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build read-only trusted-node visibility models for future local operator views."""
    timestamp = generated_at or _now()
    node_summaries = build_trusted_node_visibility_summaries(
        distributed_state=distributed_state,
        cluster_health=cluster_health,
        service_readiness_by_node=service_readiness_by_node,
        generated_at=timestamp,
    )
    panels = {
        "cluster_runtime": build_cluster_runtime_status_panel(cluster_health, generated_at=timestamp),
        "federated_topology": build_federated_topology_status_panel(federated_topology, generated_at=timestamp),
        "distributed_review": build_distributed_review_status_panel(distributed_review, generated_at=timestamp),
        "coordinated_export": build_coordinated_export_status_panel(coordinated_export, generated_at=timestamp),
        "service_readiness": build_service_readiness_status_panel(service_readiness_by_node, generated_at=timestamp),
    }
    stale_nodes = build_stale_node_rendering_models(
        distributed_state=distributed_state,
        cluster_health=cluster_health,
        generated_at=timestamp,
    )
    summary = summarize_operator_visibility(
        node_summaries=node_summaries,
        panels=panels,
        stale_nodes=stale_nodes,
    )
    empty_state = build_empty_state_visibility_model(generated_at=timestamp) if summary["empty_state"] else None
    return {
        "record_type": "trusted_operator_visibility_summary",
        "record_version": OPERATOR_VISIBILITY_RECORD_VERSION,
        "visibility_id": _stable_id("operator-visibility", timestamp, summary),
        "generated_at": timestamp,
        "node_summaries": node_summaries,
        "panels": panels,
        "stale_nodes": stale_nodes,
        "empty_state": empty_state,
        "api": build_operator_visibility_api_response(
            node_summaries=node_summaries,
            panels=panels,
            summary=summary,
            generated_at=timestamp,
        ),
        "summary": summary,
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_trusted_node_visibility_summaries(
    *,
    distributed_state: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    service_readiness_by_node: dict[str, dict[str, Any]] | Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    states = _rows((distributed_state or {}).get("nodes"))
    health_rollups = {str(row.get("node_id") or ""): row for row in _rows((cluster_health or {}).get("node_rollups"))}
    service_by_node = _service_readiness_map(service_readiness_by_node)
    node_ids = sorted(
        {
            *[str(row.get("node_id") or "") for row in states],
            *[node_id for node_id in health_rollups if node_id],
            *[node_id for node_id in service_by_node if node_id],
        }
    )
    summaries = []
    for node_id in node_ids:
        if not node_id:
            continue
        state = next((row for row in states if str(row.get("node_id") or "") == node_id), {})
        health = health_rollups.get(node_id, {})
        service = service_by_node.get(node_id, {})
        summaries.append(
            {
                "node_id": node_id,
                "node_label": str(state.get("node_label") or health.get("node_label") or service.get("node_label") or node_id),
                "role": str(state.get("role") or health.get("role") or service.get("role") or "worker"),
                "sync_status": str(state.get("sync_status") or health.get("sync_status") or "unknown"),
                "runtime_health": str(health.get("classification") or health.get("health_status") or "unknown"),
                "service_readiness": str(service.get("status") or "unknown"),
                "last_seen_at": str(state.get("last_seen_at") or health.get("last_seen_at") or ""),
                "source_refs": sorted(set(_string_rows(state.get("source_refs")) + _string_rows(health.get("source_refs")))),
                "generated_at": timestamp,
                **VISIBILITY_SAFETY_FLAGS,
            }
        )
    return summaries


def build_cluster_runtime_status_panel(cluster_health: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not cluster_health:
        return _empty_panel("cluster_runtime", generated_at=timestamp)
    dashboard_panel = cluster_health.get("dashboard_panel") if isinstance(cluster_health.get("dashboard_panel"), dict) else {}
    summary = cluster_health.get("summary") if isinstance(cluster_health.get("summary"), dict) else {}
    metrics = dashboard_panel.get("metrics") if isinstance(dashboard_panel.get("metrics"), dict) else {}
    return {
        "panel": "cluster_runtime",
        "status": str(cluster_health.get("status") or dashboard_panel.get("status") or "unknown"),
        "metrics": {
            "node_count": int(metrics.get("node_count") or summary.get("node_count") or 0),
            "degraded_node_count": int(metrics.get("degraded_node_count") or summary.get("degraded_node_count") or 0),
            "stale_node_count": int(metrics.get("stale_node_count") or summary.get("stale_node_count") or 0),
            "unavailable_node_count": int(metrics.get("unavailable_node_count") or summary.get("unavailable_node_count") or 0),
            "resource_warning_count": int(metrics.get("resource_warning_count") or summary.get("resource_warning_count") or 0),
        },
        "recommended_review": bool(summary.get("administrator_review_required") or dashboard_panel.get("recommended_review")),
        "generated_at": timestamp,
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_federated_topology_status_panel(federated_topology: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not federated_topology:
        return _empty_panel("federated_topology", generated_at=timestamp)
    dashboard = federated_topology.get("dashboard_summary") if isinstance(federated_topology.get("dashboard_summary"), dict) else {}
    summary = federated_topology.get("summary") if isinstance(federated_topology.get("summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "panel": "federated_topology",
        "status": str(dashboard.get("status") or summary.get("status") or "unknown"),
        "metrics": {
            "source_node_count": int(metrics.get("source_node_count") or summary.get("source_node_count") or 0),
            "asset_count": int(metrics.get("asset_count") or summary.get("asset_count") or 0),
            "service_count": int(metrics.get("service_count") or summary.get("service_count") or 0),
            "topology_edge_count": int(metrics.get("topology_edge_count") or summary.get("topology_edge_count") or 0),
            "finding_count": int(metrics.get("finding_count") or summary.get("finding_count") or 0),
            "conflict_count": int(metrics.get("conflict_count") or summary.get("conflict_count") or 0),
        },
        "recommended_review": bool(dashboard.get("recommended_review") or summary.get("recommended_review")),
        "generated_at": timestamp,
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_distributed_review_status_panel(distributed_review: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not distributed_review:
        return _empty_panel("distributed_review", generated_at=timestamp)
    dashboard = distributed_review.get("dashboard_panel") if isinstance(distributed_review.get("dashboard_panel"), dict) else {}
    summary = distributed_review.get("summary") if isinstance(distributed_review.get("summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "panel": "distributed_review",
        "status": str(dashboard.get("status") or ("review_required" if summary.get("administrator_review_required") else "ok")),
        "metrics": {
            "node_count": int(metrics.get("node_count") or summary.get("node_count") or 0),
            "review_count": int(metrics.get("review_count") or summary.get("review_count") or 0),
            "duplicate_review_count": int(metrics.get("duplicate_review_count") or summary.get("duplicate_review_count") or 0),
            "repeated_category_count": int(metrics.get("repeated_category_count") or summary.get("repeated_category_count") or 0),
            "recommended_review_count": int(metrics.get("recommended_review_count") or summary.get("recommended_review_count") or 0),
        },
        "recommended_review": bool(summary.get("administrator_review_required")),
        "generated_at": timestamp,
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_coordinated_export_status_panel(coordinated_export: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not coordinated_export:
        return _empty_panel("coordinated_export", generated_at=timestamp)
    summary = coordinated_export.get("summary") if isinstance(coordinated_export.get("summary"), dict) else {}
    manifest = coordinated_export.get("manifest") if isinstance(coordinated_export.get("manifest"), dict) else {}
    counts = manifest.get("record_counts") if isinstance(manifest.get("record_counts"), dict) else {}
    totals = counts.get("totals") if isinstance(counts.get("totals"), dict) else {}
    return {
        "panel": "coordinated_export",
        "status": str(summary.get("status") or "unknown"),
        "metrics": {
            "node_count": int(summary.get("node_count") or counts.get("node_count") or 0),
            "missing_node_count": int(summary.get("missing_node_count") or manifest.get("missing_node_count") or 0),
            "conflict_count": int(summary.get("conflict_count") or manifest.get("conflict_count") or 0),
            "review_count": int(totals.get("reviews") or 0),
            "health_count": int(totals.get("health") or 0),
        },
        "recommended_review": bool(summary.get("administrator_review_required")),
        "archive_requested": bool((coordinated_export.get("archive_plan") or {}).get("archive_requested")),
        "generated_at": timestamp,
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_service_readiness_status_panel(
    service_readiness_by_node: dict[str, dict[str, Any]] | Iterable[dict[str, Any]] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    service_map = _service_readiness_map(service_readiness_by_node)
    nodes = []
    by_status: dict[str, int] = {}
    for node_id, readiness in sorted(service_map.items()):
        summary = readiness.get("summary") if isinstance(readiness.get("summary"), dict) else {}
        status = str(readiness.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        nodes.append(
            {
                "node_id": node_id,
                "status": status,
                "readiness_id": str(readiness.get("readiness_id") or ""),
                "preview_count": int(summary.get("preview_count") or 0),
                "manual_operator_review_required": bool(summary.get("manual_operator_review_required", status != "ready")),
                **VISIBILITY_SAFETY_FLAGS,
            }
        )
    return {
        "panel": "service_readiness",
        "status": "empty" if not nodes else ("review_required" if any(node["status"] != "ready" for node in nodes) else "ready"),
        "metrics": {
            "node_count": len(nodes),
            "ready_count": by_status.get("ready", 0),
            "review_required_count": by_status.get("review_required", 0),
            "blocked_count": by_status.get("blocked", 0),
        },
        "nodes": nodes,
        "by_status": dict(sorted(by_status.items())),
        "generated_at": timestamp,
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_stale_node_rendering_models(
    *,
    distributed_state: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    stale = []
    for state in _rows((distributed_state or {}).get("nodes")):
        if str(state.get("sync_status") or "") == "stale":
            stale.append(
                {
                    "node_id": str(state.get("node_id") or ""),
                    "role": str(state.get("role") or "worker"),
                    "reason": "stale_node_state",
                    "last_seen_at": str(state.get("last_seen_at") or ""),
                    "render_status": "stale",
                    "generated_at": timestamp,
                    **VISIBILITY_SAFETY_FLAGS,
                }
            )
    for rollup in _rows((cluster_health or {}).get("node_rollups")):
        if str(rollup.get("classification") or "") == "stale" and str(rollup.get("node_id") or "") not in {row["node_id"] for row in stale}:
            stale.append(
                {
                    "node_id": str(rollup.get("node_id") or ""),
                    "role": str(rollup.get("role") or "worker"),
                    "reason": "stale_cluster_health",
                    "last_seen_at": str(rollup.get("last_seen_at") or ""),
                    "render_status": "stale",
                    "generated_at": timestamp,
                    **VISIBILITY_SAFETY_FLAGS,
                }
            )
    return sorted(stale, key=lambda item: item["node_id"])


def build_empty_state_visibility_model(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "status": "empty",
        "message": "No trusted-node visibility records are available.",
        "panels": ["cluster_runtime", "federated_topology", "distributed_review", "coordinated_export", "service_readiness"],
        "generated_at": generated_at or _now(),
        **VISIBILITY_SAFETY_FLAGS,
    }


def build_operator_visibility_api_response(
    *,
    node_summaries: list[dict[str, Any]],
    panels: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "status": "ok",
        "generated_at": generated_at or _now(),
        "count": len(node_summaries),
        "items": node_summaries,
        "panels": panels,
        "summary": summary,
        **VISIBILITY_SAFETY_FLAGS,
    }


def summarize_operator_visibility(
    *,
    node_summaries: list[dict[str, Any]],
    panels: dict[str, dict[str, Any]],
    stale_nodes: list[dict[str, Any]],
) -> dict[str, Any]:
    active_counts = [
        _panel_metric_total(panel)
        for panel in panels.values()
    ]
    review_required = any(str(panel.get("status") or "") in {"review_required", "degraded"} or bool(panel.get("recommended_review")) for panel in panels.values())
    return {
        "node_count": len(node_summaries),
        "panel_count": len(panels),
        "stale_node_count": len(stale_nodes),
        "empty_state": not node_summaries and not any(active_counts),
        "review_required": review_required,
        **VISIBILITY_SAFETY_FLAGS,
    }


def _empty_panel(name: str, *, generated_at: str) -> dict[str, Any]:
    return {
        "panel": name,
        "status": "empty",
        "metrics": {},
        "recommended_review": False,
        "generated_at": generated_at,
        **VISIBILITY_SAFETY_FLAGS,
    }


def _service_readiness_map(value: dict[str, dict[str, Any]] | Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    if isinstance(value, dict):
        return {
            str(node_id): {**dict(readiness), "node_id": str(node_id)}
            for node_id, readiness in value.items()
            if isinstance(readiness, dict)
        }
    result: dict[str, dict[str, Any]] = {}
    for row in _rows(value):
        node_id = str(row.get("node_id") or row.get("source_node_id") or "")
        if node_id:
            result[node_id] = row
    return result


def _panel_metric_total(panel: dict[str, Any]) -> int:
    metrics = panel.get("metrics") if isinstance(panel.get("metrics"), dict) else {}
    return sum(int(value or 0) for value in metrics.values() if isinstance(value, int))


def _string_rows(value: Any) -> list[str]:
    return [str(item) for item in value or [] if str(item).strip()]


def _rows(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
