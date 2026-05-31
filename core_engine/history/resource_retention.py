from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.history.baseline_decay import BASELINE_DECAY_SAFETY_FLAGS
from core_engine.history.retention_policies import (
    RETENTION_POLICY_SAFETY_FLAGS,
    build_retention_policy_record,
)
from core_engine.history.snapshot_store import summarize_snapshot_store
from core_engine.history.timeline_replay import TIMELINE_REPLAY_SAFETY_FLAGS
from core_engine.history.topology_evolution import TOPOLOGY_EVOLUTION_SAFETY_FLAGS
from core_engine.platform.runtime_detection import PLATFORM_RUNTIME_SAFETY_FLAGS


RESOURCE_RETENTION_RECORD_VERSION = 1

RESOURCE_RETENTION_SAFETY_FLAGS = {
    **RETENTION_POLICY_SAFETY_FLAGS,
    **TIMELINE_REPLAY_SAFETY_FLAGS,
    **BASELINE_DECAY_SAFETY_FLAGS,
    **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    **PLATFORM_RUNTIME_SAFETY_FLAGS,
    "resource_aware_retention": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "resource_conscious": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "delete_preview_only": True,
    "deletion_preview_only": True,
    "automatic_deletion": False,
    "delete_performed": False,
    "path_modified": False,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_logs_stored": False,
    "raw_browsing_history_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


RETENTION_CATEGORIES = (
    "snapshots",
    "replay",
    "topology_history",
    "behavioral_baselines",
)


def build_storage_budget_summary(
    storage_summary: dict[str, Any] | None = None,
    *,
    policy: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    thresholds = _thresholds(policy)
    if storage_summary is not None and not isinstance(storage_summary, dict):
        return _malformed_budget("storage", generated_at=timestamp)
    source = storage_summary or {}
    free_mb = _number(_first_present(source, "free_mb", "available_mb", "free_storage_mb", "available_storage_mb"))
    total_mb = _number(_first_present(source, "total_mb", "total_storage_mb"))
    used_mb = _number(_first_present(source, "used_mb", "used_storage_mb"))
    status, warnings = _budget_status(
        free_mb,
        minimum=float(thresholds["min_free_storage_mb"]),
        critical=float(thresholds["critical_free_storage_mb"]),
        resource="storage",
    )
    percent_free = round((free_mb / total_mb) * 100.0, 3) if free_mb is not None and total_mb and total_mb > 0 else None
    return {
        "record_type": "historical_storage_budget_summary",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": timestamp,
        "status": status,
        "free_mb": free_mb,
        "available_mb": free_mb,
        "total_mb": total_mb,
        "used_mb": used_mb,
        "percent_free": percent_free,
        "min_free_storage_mb": int(thresholds["min_free_storage_mb"]),
        "critical_free_storage_mb": int(thresholds["critical_free_storage_mb"]),
        "warnings": warnings,
        "operator_summary": _budget_operator_summary("storage", status),
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_memory_budget_summary(
    memory_summary: dict[str, Any] | None = None,
    *,
    policy: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    thresholds = _thresholds(policy)
    if memory_summary is not None and not isinstance(memory_summary, dict):
        return _malformed_budget("memory", generated_at=timestamp)
    source = memory_summary or {}
    free_mb = _number(_first_present(source, "free_mb", "available_mb", "free_memory_mb", "available_memory_mb"))
    total_mb = _number(_first_present(source, "total_mb", "total_memory_mb"))
    used_mb = _number(_first_present(source, "used_mb", "used_memory_mb"))
    status, warnings = _budget_status(
        free_mb,
        minimum=float(thresholds["min_free_memory_mb"]),
        critical=float(thresholds["critical_free_memory_mb"]),
        resource="memory",
    )
    percent_free = round((free_mb / total_mb) * 100.0, 3) if free_mb is not None and total_mb and total_mb > 0 else None
    return {
        "record_type": "historical_memory_budget_summary",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": timestamp,
        "status": status,
        "free_mb": free_mb,
        "available_mb": free_mb,
        "total_mb": total_mb,
        "used_mb": used_mb,
        "percent_free": percent_free,
        "min_free_memory_mb": int(thresholds["min_free_memory_mb"]),
        "critical_free_memory_mb": int(thresholds["critical_free_memory_mb"]),
        "warnings": warnings,
        "operator_summary": _budget_operator_summary("memory", status),
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_adaptive_retention_windows(
    *,
    policy: dict[str, Any] | None = None,
    storage_budget: dict[str, Any] | None = None,
    memory_budget: dict[str, Any] | None = None,
    platform_record: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    policy_record = policy or build_retention_policy_record(generated_at=timestamp)
    limits = dict(policy_record.get("category_limits") or {})
    factor = _resource_factor(storage_budget=storage_budget, memory_budget=memory_budget, platform_record=platform_record, policy=policy_record)
    adapted = {category: max(1, int(int(limits.get(category) or 1) * factor)) for category in RETENTION_CATEGORIES}
    state = _degradation_state(storage_budget=storage_budget, memory_budget=memory_budget, factor=factor)
    return {
        "record_type": "adaptive_historical_retention_windows",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": timestamp,
        "status": state,
        "policy_id": str(policy_record.get("policy_id") or ""),
        "profile_label": str(policy_record.get("profile_label") or "default"),
        "platform_family": _platform_family(platform_record),
        "resource_factor": round(factor, 3),
        "base_category_limits": {category: int(limits.get(category) or 0) for category in RETENTION_CATEGORIES},
        "adapted_category_limits": adapted,
        "low_resource_degradation_state": state,
        "warnings": _retention_warnings(storage_budget=storage_budget, memory_budget=memory_budget, platform_record=platform_record, factor=factor),
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_retention_recommendations(
    *,
    snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    historical_replay_report: dict[str, Any] | None = None,
    topology_evolution_report: dict[str, Any] | None = None,
    baseline_decay_report: dict[str, Any] | None = None,
    adaptive_windows: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    limits = dict((adaptive_windows or {}).get("adapted_category_limits") or {})
    counts = {
        "snapshots": _snapshot_count(snapshots),
        "replay": _replay_count(historical_replay_report),
        "topology_history": _topology_count(topology_evolution_report),
        "behavioral_baselines": _baseline_count(baseline_decay_report),
    }
    recommendations = []
    for category in RETENTION_CATEGORIES:
        recommended_max = int(limits.get(category) or counts[category] or 1)
        current_count = int(counts[category])
        over_limit = current_count > recommended_max
        record = {
            "record_type": "historical_retention_recommendation",
            "record_version": RESOURCE_RETENTION_RECORD_VERSION,
            "generated_at": timestamp,
            "category": category,
            "current_count": current_count,
            "recommended_max_records": recommended_max,
            "over_recommended_limit": over_limit,
            "recommendation_state": "degraded" if over_limit else "supported",
            "operator_action": "review_future_rotation" if over_limit else "retain_current_window",
            "action_preview": _action_preview(category, recommended_max, over_limit),
            "delete_performed": False,
            "automatic_deletion": False,
            "deletion_preview_only": True,
            **RESOURCE_RETENTION_SAFETY_FLAGS,
        }
        record["recommendation_id"] = "historical-retention-" + _digest({"category": category, "count": current_count, "max": recommended_max})[:16]
        recommendations.append(record)
    return recommendations


def build_resource_aware_retention_report(
    *,
    snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    historical_replay_report: dict[str, Any] | None = None,
    topology_evolution_report: dict[str, Any] | None = None,
    baseline_decay_report: dict[str, Any] | None = None,
    retention_policy: dict[str, Any] | None = None,
    storage_summary: dict[str, Any] | None = None,
    memory_summary: dict[str, Any] | None = None,
    platform_record: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    policy = retention_policy or build_retention_policy_record(generated_at=timestamp)
    storage_budget = build_storage_budget_summary(storage_summary, policy=policy, generated_at=timestamp)
    memory_budget = build_memory_budget_summary(memory_summary, policy=policy, generated_at=timestamp)
    adaptive = build_adaptive_retention_windows(
        policy=policy,
        storage_budget=storage_budget,
        memory_budget=memory_budget,
        platform_record=platform_record,
        generated_at=timestamp,
    )
    recommendations = build_retention_recommendations(
        snapshots=snapshots,
        historical_replay_report=historical_replay_report,
        topology_evolution_report=topology_evolution_report,
        baseline_decay_report=baseline_decay_report,
        adaptive_windows=adaptive,
        generated_at=timestamp,
    )
    summary = build_retention_summary(
        policy=policy,
        storage_budget=storage_budget,
        memory_budget=memory_budget,
        adaptive_windows=adaptive,
        recommendations=recommendations,
        generated_at=timestamp,
    )
    export = build_resource_retention_export_summary(summary=summary, recommendations=recommendations, generated_at=timestamp)
    dashboard = build_resource_retention_dashboard_record(summary=summary, recommendations=recommendations, generated_at=timestamp)
    api = build_resource_retention_api_response(
        summary=summary,
        storage_budget=storage_budget,
        memory_budget=memory_budget,
        adaptive_windows=adaptive,
        recommendations=recommendations,
        dashboard=dashboard,
        export=export,
        generated_at=timestamp,
    )
    return {
        "record_type": "resource_aware_historical_retention_report",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "report_id": "resource-retention-" + _digest({"generated_at": timestamp, "summary": summary})[:16],
        "generated_at": timestamp,
        "retention_policy": policy,
        "storage_budget": storage_budget,
        "memory_budget": memory_budget,
        "adaptive_windows": adaptive,
        "recommendations": recommendations,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_retention_summary(
    *,
    policy: dict[str, Any],
    storage_budget: dict[str, Any],
    memory_budget: dict[str, Any],
    adaptive_windows: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(recommendations)
    over_limit = sum(1 for row in rows if row.get("over_recommended_limit"))
    statuses = [str(storage_budget.get("status") or "unknown"), str(memory_budget.get("status") or "unknown"), str(adaptive_windows.get("status") or "unknown")]
    aggregate = _aggregate_status(statuses, over_limit=over_limit)
    return {
        "record_type": "resource_aware_historical_retention_summary",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": aggregate,
        "profile_label": str(policy.get("profile_label") or "default"),
        "storage_status": str(storage_budget.get("status") or "unknown"),
        "memory_status": str(memory_budget.get("status") or "unknown"),
        "low_resource_degradation_state": str(adaptive_windows.get("low_resource_degradation_state") or aggregate),
        "recommendation_count": len(rows),
        "over_limit_recommendation_count": over_limit,
        "resource_factor": float(adaptive_windows.get("resource_factor") or 0.0),
        "adapted_category_limits": dict(adaptive_windows.get("adapted_category_limits") or {}),
        "operator_summary": _summary_text(aggregate, over_limit),
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_resource_retention_dashboard_record(
    *,
    summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(recommendations)
    return {
        "record_type": "resource_aware_retention_dashboard",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "panel": "resource_aware_historical_retention",
        "generated_at": generated_at or _now(),
        "status": str(summary.get("status") or "unknown"),
        "metrics": {
            "recommendation_count": int(summary.get("recommendation_count") or 0),
            "over_limit_recommendation_count": int(summary.get("over_limit_recommendation_count") or 0),
            "resource_factor": float(summary.get("resource_factor") or 0.0),
        },
        "rows": [
            {
                "category": row.get("category"),
                "current_count": row.get("current_count"),
                "recommended_max_records": row.get("recommended_max_records"),
                "recommendation_state": row.get("recommendation_state"),
                "operator_action": row.get("operator_action"),
            }
            for row in sorted(rows, key=lambda item: str(item.get("category") or ""))
        ],
        "recommended_review": int(summary.get("over_limit_recommendation_count") or 0) > 0 or str(summary.get("status")) == "degraded",
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_resource_retention_api_response(
    *,
    summary: dict[str, Any],
    storage_budget: dict[str, Any],
    memory_budget: dict[str, Any],
    adaptive_windows: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    export: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "resource_aware_retention_api",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "storage_budget": dict(storage_budget),
        "memory_budget": dict(memory_budget),
        "adaptive_windows": dict(adaptive_windows),
        "recommendations": _rows(recommendations),
        "dashboard_status": dict(dashboard),
        "export_summary": dict(export),
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def build_resource_retention_export_summary(
    *,
    summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(recommendations)
    payload = {
        "record_type": "resource_aware_retention_export_summary",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "recommendations": len(rows),
            "over_limit": int(summary.get("over_limit_recommendation_count") or 0),
        },
        "status": str(summary.get("status") or "unknown"),
        "category_limits": dict(summary.get("adapted_category_limits") or {}),
        "digest": "",
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }
    payload["digest"] = digest_payload(
        {
            "record_counts": payload["record_counts"],
            "status": payload["status"],
            "category_limits": payload["category_limits"],
        }
    )
    return payload


def deterministic_resource_retention_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _snapshot_count(snapshots: Iterable[dict[str, Any]] | dict[str, Any] | None) -> int:
    if snapshots is None:
        return 0
    if isinstance(snapshots, dict):
        if isinstance(snapshots.get("summary"), dict):
            return int((snapshots["summary"]).get("snapshot_count") or 0)
        if isinstance(snapshots.get("snapshots"), list):
            return len(snapshots["snapshots"])
        return 1 if snapshots.get("record_type") == "historical_snapshot" else 0
    return int(summarize_snapshot_store(_rows(snapshots)).get("snapshot_count") or 0)


def _replay_count(report: dict[str, Any] | None) -> int:
    if not isinstance(report, dict):
        return 0
    if isinstance(report.get("timeline_events"), list):
        return len(report["timeline_events"])
    return int((report.get("snapshot_sequence") or {}).get("snapshot_count") or 0)


def _topology_count(report: dict[str, Any] | None) -> int:
    if not isinstance(report, dict):
        return 0
    if isinstance(report.get("relationships"), list):
        return len(report["relationships"])
    return int((report.get("relationship_summary") or {}).get("relationship_count") or 0)


def _baseline_count(report: dict[str, Any] | None) -> int:
    if not isinstance(report, dict):
        return 0
    if isinstance(report.get("records"), list):
        return len(report["records"])
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    return int(summary.get("record_count") or summary.get("baseline_entry_count") or 0)


def _thresholds(policy: dict[str, Any] | None) -> dict[str, int]:
    source = (policy or {}).get("budget_thresholds") if isinstance((policy or {}).get("budget_thresholds"), dict) else {}
    return {
        "min_free_storage_mb": int(source.get("min_free_storage_mb") or 512),
        "critical_free_storage_mb": int(source.get("critical_free_storage_mb") or 128),
        "min_free_memory_mb": int(source.get("min_free_memory_mb") or 256),
        "critical_free_memory_mb": int(source.get("critical_free_memory_mb") or 128),
    }


def _budget_status(value: float | None, *, minimum: float, critical: float, resource: str) -> tuple[str, list[str]]:
    if value is None:
        return "unknown", [f"{resource}_budget_unknown"]
    if value < critical:
        return "degraded", [f"{resource}_below_critical_threshold"]
    if value < minimum:
        return "degraded", [f"{resource}_below_recommended_threshold"]
    return "supported", []


def _malformed_budget(resource: str, *, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": f"historical_{resource}_budget_summary",
        "record_version": RESOURCE_RETENTION_RECORD_VERSION,
        "generated_at": generated_at,
        "status": "unavailable",
        "free_mb": None,
        "available_mb": None,
        "total_mb": None,
        "used_mb": None,
        "percent_free": None,
        "warnings": [f"malformed_{resource}_budget"],
        "operator_summary": f"{resource.title()} budget input was malformed; retention recommendations use safe degraded defaults.",
        **RESOURCE_RETENTION_SAFETY_FLAGS,
    }


def _resource_factor(
    *,
    storage_budget: dict[str, Any] | None,
    memory_budget: dict[str, Any] | None,
    platform_record: dict[str, Any] | None,
    policy: dict[str, Any],
) -> float:
    factor = 0.75 if policy.get("edge_device_profile") or _platform_family(platform_record) == "raspberry-pi-linux-arm" else 1.0
    factor = min(factor, _budget_factor(storage_budget, "storage"))
    factor = min(factor, _budget_factor(memory_budget, "memory"))
    return max(0.25, factor)


def _budget_factor(budget: dict[str, Any] | None, resource: str) -> float:
    if not isinstance(budget, dict):
        return 0.75
    status = str(budget.get("status") or "unknown")
    if status == "supported":
        return 1.0
    if status == "unknown":
        return 0.75
    warnings = set(str(item) for item in budget.get("warnings", []) if item)
    if f"{resource}_below_critical_threshold" in warnings or f"malformed_{resource}_budget" in warnings:
        return 0.35
    return 0.55


def _degradation_state(*, storage_budget: dict[str, Any] | None, memory_budget: dict[str, Any] | None, factor: float) -> str:
    statuses = {str((storage_budget or {}).get("status") or "unknown"), str((memory_budget or {}).get("status") or "unknown")}
    if "unavailable" in statuses and factor <= 0.35:
        return "unavailable"
    if factor < 1.0 or "degraded" in statuses or "unavailable" in statuses:
        return "degraded"
    if "unknown" in statuses:
        return "unknown"
    return "supported"


def _aggregate_status(statuses: Iterable[str], *, over_limit: int) -> str:
    values = set(statuses)
    if "unavailable" in values:
        return "unavailable"
    if "degraded" in values or over_limit:
        return "degraded"
    if "unknown" in values:
        return "unknown"
    return "supported"


def _retention_warnings(
    *,
    storage_budget: dict[str, Any] | None,
    memory_budget: dict[str, Any] | None,
    platform_record: dict[str, Any] | None,
    factor: float,
) -> list[str]:
    warnings: set[str] = set()
    for budget in (storage_budget, memory_budget):
        if isinstance(budget, dict):
            warnings.update(str(item) for item in budget.get("warnings", []) if item)
    if _platform_family(platform_record) == "raspberry-pi-linux-arm":
        warnings.add("raspberry_pi_edge_retention_profile_recommended")
    if factor < 1.0:
        warnings.add("retention_windows_reduced_for_resource_budget")
    return sorted(warnings)


def _platform_family(platform_record: dict[str, Any] | None) -> str:
    if not isinstance(platform_record, dict):
        return "unknown"
    return str(platform_record.get("platform_family") or (platform_record.get("os") or {}).get("family") or "unknown")


def _action_preview(category: str, recommended_max: int, over_limit: bool) -> str:
    if over_limit:
        return f"Preview retaining newest {recommended_max} metadata records for {category}; no deletion is performed automatically."
    return f"Current {category} metadata is within the recommended bounded retention window."


def _budget_operator_summary(resource: str, status: str) -> str:
    if status == "supported":
        return f"{resource.title()} budget supports the configured metadata retention window."
    if status == "degraded":
        return f"{resource.title()} budget is low; reduce historical metadata retention windows."
    if status == "unavailable":
        return f"{resource.title()} budget could not be read from the provided summary."
    return f"{resource.title()} budget is unknown; use conservative retention windows."


def _summary_text(status: str, over_limit: int) -> str:
    if status == "supported" and not over_limit:
        return "Historical metadata retention is within the configured local resource budget."
    if status == "unavailable":
        return "Historical retention uses unavailable-resource safeguards and requires operator review."
    return "Historical retention should use reduced preview windows until local resource budget improves."


def _first_present(source: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in source:
            return source[key]
    return None


def _number(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return round(float(value), 3)
    except (TypeError, ValueError):
        return None


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _digest(payload: Any) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
