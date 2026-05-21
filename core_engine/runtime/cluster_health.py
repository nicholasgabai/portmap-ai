from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.events import LocalEvent, event_to_dict
from core_engine.runtime.distributed_state import SAFETY_FLAGS, normalize_node_runtime_state, summarize_role_counts
from core_engine.runtime.health import DEFAULT_RESOURCE_BUDGETS, RASPBERRY_PI_RESOURCE_BUDGETS, summarize_health_checks


CLUSTER_HEALTH_RECORD_VERSION = 1
CLUSTER_COMPONENTS = (
    "scheduler",
    "storage",
    "event_queue",
    "review_queue",
    "export_readiness",
    "service_readiness",
    "runtime_sessions",
)


def build_cluster_runtime_health(
    node_reports: Iterable[dict[str, Any]],
    *,
    expected_nodes: Iterable[str] | None = None,
    generated_at: str | None = None,
    stale_after_seconds: float | None = None,
    resource_budgets: dict[str, int] | None = None,
    edge_device: bool = False,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    budgets = _resource_budgets(resource_budgets, edge_device=edge_device)
    node_rollups, malformed = normalize_node_health_rollups(
        node_reports,
        generated_at=timestamp,
        stale_after_seconds=stale_after_seconds,
        resource_budgets=budgets,
    )
    missing = _missing_rollups(node_rollups, expected_nodes=expected_nodes, generated_at=timestamp)
    all_rollups = sorted([*node_rollups, *missing, *malformed], key=lambda item: str(item["node_id"]))
    availability = summarize_cluster_availability(all_rollups)
    component_rollups = summarize_cluster_component_health(all_rollups)
    resource_warnings = summarize_cluster_resource_warnings(all_rollups, resource_budgets=budgets)
    summary = summarize_cluster_health(all_rollups, component_rollups=component_rollups, resource_warnings=resource_warnings)
    status = _cluster_status(summary)
    health_event = build_cluster_health_event(
        status=status,
        summary=summary,
        generated_at=timestamp,
        node_count=len(all_rollups),
    )
    dashboard_panel = build_cluster_health_dashboard_panel(
        status=status,
        availability=availability,
        component_rollups=component_rollups,
        resource_warnings=resource_warnings,
        summary=summary,
    )
    return {
        "record_type": "cluster_runtime_health",
        "record_version": CLUSTER_HEALTH_RECORD_VERSION,
        "cluster_health_id": _stable_id("cluster-health", timestamp, summary),
        "status": status,
        "generated_at": timestamp,
        "node_rollups": all_rollups,
        "availability": availability,
        "component_rollups": component_rollups,
        "resource_budget_warnings": resource_warnings,
        "summary": summary,
        "health_event": health_event,
        "dashboard_panel": dashboard_panel,
        "resource_budgets": budgets,
        **SAFETY_FLAGS,
    }


def normalize_node_health_rollups(
    node_reports: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    stale_after_seconds: float | None = None,
    resource_budgets: dict[str, int] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    timestamp = generated_at or _now()
    budgets = _resource_budgets(resource_budgets, edge_device=False)
    rollups: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for index, report in enumerate(node_reports):
        try:
            state = normalize_node_runtime_state(
                report,
                generated_at=timestamp,
                stale_after_seconds=stale_after_seconds,
            )
            rollups.append(build_node_health_rollup(state, generated_at=timestamp, resource_budgets=budgets))
        except Exception as exc:
            malformed.append(_malformed_rollup(index=index, error=str(exc), generated_at=timestamp))
    return rollups, malformed


def build_node_health_rollup(
    node_state: dict[str, Any],
    *,
    generated_at: str | None = None,
    resource_budgets: dict[str, int] | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    budgets = _resource_budgets(resource_budgets, edge_device=False)
    health = dict(node_state.get("health_summary") or {})
    checks = _health_checks(health)
    check_summary = summarize_health_checks(checks)
    component_status = _component_statuses(checks)
    resource_warnings = _resource_warnings_for_node(node_state, component_status=component_status, resource_budgets=budgets)
    classification = classify_node_health(
        sync_status=str(node_state.get("sync_status") or "current"),
        health_status=str(health.get("status") or ""),
        check_summary=check_summary,
        malformed=False,
    )
    return {
        "node_id": str(node_state.get("node_id") or ""),
        "node_label": str(node_state.get("node_label") or node_state.get("node_id") or ""),
        "role": str(node_state.get("role") or "worker"),
        "classification": classification,
        "sync_status": str(node_state.get("sync_status") or "current"),
        "health_status": str(health.get("status") or "unknown"),
        "last_seen_at": str(node_state.get("last_seen_at") or ""),
        "generated_at": timestamp,
        "component_status": component_status,
        "check_summary": check_summary,
        "resource_warnings": resource_warnings,
        "source_refs": list(node_state.get("source_refs") or []),
        "session_reference": dict(node_state.get("session_reference") or {}),
        "profile_reference": dict(node_state.get("profile_reference") or {}),
        "health_reference": dict(node_state.get("health_reference") or {}),
        "checkpoint_reference": dict(node_state.get("checkpoint_reference") or {}),
        **SAFETY_FLAGS,
    }


def classify_node_health(
    *,
    sync_status: str,
    health_status: str,
    check_summary: dict[str, Any] | None = None,
    malformed: bool = False,
) -> str:
    if malformed:
        return "malformed"
    if sync_status == "missing":
        return "unavailable"
    if sync_status == "stale":
        return "stale"
    if sync_status == "conflicting":
        return "degraded"
    summary = dict(check_summary or {})
    if int(summary.get("critical_count") or 0) or int(summary.get("high_count") or 0):
        return "degraded"
    if int(summary.get("degraded_count") or 0):
        return "degraded"
    if health_status == "degraded":
        return "degraded"
    if health_status in {"unavailable", "missing"}:
        return "unavailable"
    return "healthy"


def summarize_cluster_availability(node_rollups: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(node_rollups)
    by_classification: dict[str, int] = {}
    by_role: dict[str, dict[str, int]] = {}
    for row in rows:
        classification = str(row.get("classification") or "unknown")
        role = str(row.get("role") or "worker")
        by_classification[classification] = by_classification.get(classification, 0) + 1
        by_role.setdefault(role, {})
        by_role[role][classification] = by_role[role].get(classification, 0) + 1
    role_counts = summarize_role_counts([{"role": row.get("role"), "sync_status": row.get("sync_status")} for row in rows])
    return {
        "node_count": len(rows),
        "healthy_node_count": by_classification.get("healthy", 0),
        "degraded_node_count": by_classification.get("degraded", 0),
        "stale_node_count": by_classification.get("stale", 0),
        "unavailable_node_count": by_classification.get("unavailable", 0),
        "malformed_node_count": by_classification.get("malformed", 0),
        "by_classification": dict(sorted(by_classification.items())),
        "by_role": {role: dict(sorted(counts.items())) for role, counts in sorted(by_role.items())},
        "roles": role_counts,
        **SAFETY_FLAGS,
    }


def summarize_cluster_component_health(node_rollups: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(node_rollups)
    result: dict[str, dict[str, Any]] = {}
    for component in CLUSTER_COMPONENTS:
        counts: dict[str, int] = {}
        for row in rows:
            status = str((row.get("component_status") or {}).get(component) or "unavailable")
            counts[status] = counts.get(status, 0) + 1
        result[component] = {
            "component": component,
            "node_count": len(rows),
            "by_status": dict(sorted(counts.items())),
            "degraded_count": counts.get("degraded", 0),
            "unavailable_count": counts.get("unavailable", 0),
            **SAFETY_FLAGS,
        }
    return result


def summarize_cluster_resource_warnings(
    node_rollups: Iterable[dict[str, Any]],
    *,
    resource_budgets: dict[str, int] | None = None,
) -> dict[str, Any]:
    rows = list(node_rollups)
    warnings = [warning for row in rows for warning in row.get("resource_warnings") or []]
    by_type: dict[str, int] = {}
    for warning in warnings:
        warning_type = str(warning.get("warning_type") or "resource_budget")
        by_type[warning_type] = by_type.get(warning_type, 0) + 1
    return {
        "warning_count": len(warnings),
        "by_type": dict(sorted(by_type.items())),
        "warnings": sorted(warnings, key=lambda item: (str(item.get("node_id") or ""), str(item.get("warning_type") or ""))),
        "resource_budgets": _resource_budgets(resource_budgets, edge_device=False),
        **SAFETY_FLAGS,
    }


def summarize_cluster_health(
    node_rollups: Iterable[dict[str, Any]],
    *,
    component_rollups: dict[str, Any] | None = None,
    resource_warnings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = list(node_rollups)
    availability = summarize_cluster_availability(rows)
    components = dict(component_rollups or summarize_cluster_component_health(rows))
    warnings = dict(resource_warnings or summarize_cluster_resource_warnings(rows))
    return {
        "node_count": len(rows),
        "healthy_node_count": availability["healthy_node_count"],
        "degraded_node_count": availability["degraded_node_count"],
        "stale_node_count": availability["stale_node_count"],
        "unavailable_node_count": availability["unavailable_node_count"],
        "malformed_node_count": availability["malformed_node_count"],
        "component_count": len(components),
        "resource_warning_count": int(warnings.get("warning_count") or 0),
        "administrator_review_required": any(
            availability[key] > 0
            for key in ("degraded_node_count", "stale_node_count", "unavailable_node_count", "malformed_node_count")
        )
        or int(warnings.get("warning_count") or 0) > 0,
        **SAFETY_FLAGS,
    }


def build_cluster_health_event(
    *,
    status: str,
    summary: dict[str, Any],
    generated_at: str | None = None,
    node_count: int = 0,
) -> dict[str, Any]:
    severity = "medium" if status == "degraded" else "info"
    if int(summary.get("unavailable_node_count") or 0) or int(summary.get("malformed_node_count") or 0):
        severity = "high"
    event = LocalEvent(
        event_type="runtime_health",
        severity=severity,
        source="runtime.cluster_health",
        timestamp=generated_at or _now(),
        message=f"Cluster runtime health status: {status}",
        metadata={
            "health_scope": "cluster",
            "summary": dict(summary),
            "node_count": int(node_count),
        },
    )
    return event_to_dict(event)


def build_cluster_health_dashboard_panel(
    *,
    status: str,
    availability: dict[str, Any],
    component_rollups: dict[str, Any],
    resource_warnings: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "panel": "cluster_runtime_health",
        "status": status,
        "metrics": {
            "node_count": summary["node_count"],
            "healthy_node_count": summary["healthy_node_count"],
            "degraded_node_count": summary["degraded_node_count"],
            "stale_node_count": summary["stale_node_count"],
            "unavailable_node_count": summary["unavailable_node_count"],
            "resource_warning_count": summary["resource_warning_count"],
        },
        "availability": availability,
        "component_rollups": component_rollups,
        "resource_warnings": resource_warnings,
        "recommended_review": summary["administrator_review_required"],
        **SAFETY_FLAGS,
    }


def _health_checks(health_summary: dict[str, Any]) -> list[dict[str, Any]]:
    checks = health_summary.get("checks")
    return [check for check in checks or [] if isinstance(check, dict)]


def _component_statuses(checks: list[dict[str, Any]]) -> dict[str, str]:
    statuses = {component: "unavailable" for component in CLUSTER_COMPONENTS}
    aliases = {
        "review_queue": "review_queue",
        "export_readiness": "export_readiness",
        "runtime_sessions": "runtime_sessions",
        "event_queue": "event_queue",
        "scheduler": "scheduler",
        "storage": "storage",
        "service_readiness": "service_readiness",
    }
    for check in checks:
        name = aliases.get(str(check.get("name") or ""))
        if name:
            statuses[name] = str(check.get("status") or "unknown")
    return statuses


def _resource_warnings_for_node(
    node_state: dict[str, Any],
    *,
    component_status: dict[str, str],
    resource_budgets: dict[str, int],
) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    node_id = str(node_state.get("node_id") or "unknown")
    health = dict(node_state.get("health_summary") or {})
    checks = _health_checks(health)
    details_by_name = {str(check.get("name") or ""): dict(check.get("details") or {}) for check in checks}
    queue_depth = int(details_by_name.get("event_queue", {}).get("queue_depth") or 0)
    if queue_depth >= int(resource_budgets["event_queue_warning_depth"]):
        warnings.append(_resource_warning(node_id, "event_queue_depth", queue_depth, resource_budgets["event_queue_warning_depth"]))
    storage_records = int(details_by_name.get("storage", {}).get("record_count") or 0)
    if storage_records >= int(resource_budgets["storage_warning_records"]):
        warnings.append(_resource_warning(node_id, "storage_records", storage_records, resource_budgets["storage_warning_records"]))
    review_count = int(details_by_name.get("review_queue", {}).get("review_count") or 0)
    if review_count >= int(resource_budgets["review_warning_count"]):
        warnings.append(_resource_warning(node_id, "review_count", review_count, resource_budgets["review_warning_count"]))
    for component, status in component_status.items():
        if status == "degraded":
            warnings.append(_resource_warning(node_id, f"{component}_degraded", 1, 1, severity="medium"))
    return warnings


def _resource_warning(node_id: str, warning_type: str, value: int, threshold: int, *, severity: str = "medium") -> dict[str, Any]:
    return {
        "node_id": node_id,
        "warning_type": warning_type,
        "value": int(value),
        "threshold": int(threshold),
        "severity": severity,
        "recommended_review": True,
        **SAFETY_FLAGS,
    }


def _malformed_rollup(*, index: int, error: str, generated_at: str) -> dict[str, Any]:
    return {
        "node_id": f"malformed-node-{index}",
        "node_label": f"malformed-node-{index}",
        "role": "unknown",
        "classification": "malformed",
        "sync_status": "conflicting",
        "health_status": "malformed",
        "last_seen_at": "",
        "generated_at": generated_at,
        "component_status": {component: "unavailable" for component in CLUSTER_COMPONENTS},
        "check_summary": summarize_health_checks([]),
        "resource_warnings": [
            {
                "node_id": f"malformed-node-{index}",
                "warning_type": "malformed_node_health",
                "value": 1,
                "threshold": 1,
                "severity": "high",
                "summary": error,
                "recommended_review": True,
                **SAFETY_FLAGS,
            }
        ],
        "source_refs": [],
        "session_reference": {},
        "profile_reference": {},
        "health_reference": {},
        "checkpoint_reference": {},
        **SAFETY_FLAGS,
    }


def _missing_rollups(
    node_rollups: list[dict[str, Any]],
    *,
    expected_nodes: Iterable[str] | None,
    generated_at: str,
) -> list[dict[str, Any]]:
    present = {str(row.get("node_id") or "") for row in node_rollups}
    missing: list[dict[str, Any]] = []
    for node_id in sorted(str(item) for item in expected_nodes or [] if str(item).strip()):
        if node_id in present:
            continue
        missing.append(
            {
                "node_id": node_id,
                "node_label": node_id,
                "role": "unknown",
                "classification": "unavailable",
                "sync_status": "missing",
                "health_status": "missing",
                "last_seen_at": "",
                "generated_at": generated_at,
                "component_status": {component: "unavailable" for component in CLUSTER_COMPONENTS},
                "check_summary": summarize_health_checks([]),
                "resource_warnings": [],
                "source_refs": [f"expected-node:{node_id}"],
                "session_reference": {},
                "profile_reference": {},
                "health_reference": {},
                "checkpoint_reference": {},
                **SAFETY_FLAGS,
            }
        )
    return missing


def _cluster_status(summary: dict[str, Any]) -> str:
    if any(int(summary.get(key) or 0) for key in ("degraded_node_count", "stale_node_count", "unavailable_node_count", "malformed_node_count")):
        return "degraded"
    if int(summary.get("resource_warning_count") or 0):
        return "degraded"
    return "ok"


def _resource_budgets(overrides: dict[str, int] | None, *, edge_device: bool) -> dict[str, int]:
    budgets = dict(RASPBERRY_PI_RESOURCE_BUDGETS if edge_device else DEFAULT_RESOURCE_BUDGETS)
    for key, value in dict(overrides or {}).items():
        if key in budgets and isinstance(value, int) and value > 0:
            budgets[key] = value
    return budgets


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
