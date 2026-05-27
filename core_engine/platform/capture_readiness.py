from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.platform.capture_backends import (
    CAPTURE_BACKEND_SAFETY_FLAGS,
    build_capture_backend_summary,
)
from core_engine.platform.runtime_detection import build_platform_runtime_record
from core_engine.telemetry.capture_sessions import build_passive_capture_session_plan
from core_engine.telemetry.interfaces import enumerate_local_interfaces


CAPTURE_READINESS_RECORD_VERSION = 1

CAPTURE_READINESS_SAFETY_FLAGS = {
    **CAPTURE_BACKEND_SAFETY_FLAGS,
    "passive_capture_only": True,
    "packet_payload_storage_prohibited": True,
    "payload_retention": "disabled",
    "packets_captured": 0,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "capture_started": False,
    "capture_loop_started": False,
    "promiscuous_mode_enabled": False,
    "interface_mode_changed": False,
    "provider_install_attempted": False,
    "admin_elevation_requested": False,
}


def build_cross_platform_capture_readiness_report(
    *,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    is_admin: bool | None = None,
    interfaces: dict[str, Iterable[dict[str, Any]]] | None = None,
    interface_inventory: dict[str, Any] | None = None,
    selected_interfaces: Iterable[str] | None = None,
    backend_statuses: dict[str, str] | None = None,
    span_readiness: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    edge_device: bool | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a dry-run packet capture readiness report without starting capture."""
    timestamp = generated_at or _now()
    platform_payload = platform_record or build_platform_runtime_record(
        platform_info=platform_info,
        is_admin=is_admin,
        generated_at=timestamp,
    )
    platform_family = str(platform_payload.get("platform_family") or "unknown")
    edge = bool(edge_device) if edge_device is not None else platform_family == "raspberry-pi-linux-arm"
    inventory = interface_inventory or enumerate_local_interfaces(interfaces=interfaces, generated_at=timestamp)
    backends = build_capture_backend_summary(
        platform_record=platform_payload,
        backend_statuses=backend_statuses,
        generated_at=timestamp,
    )
    capture_plan = build_passive_capture_session_plan(
        selected_interfaces=selected_interfaces,
        interface_inventory=inventory,
        edge_device=edge,
        generated_at=timestamp,
    )
    permission = build_capture_permission_requirement_summary(platform_payload, generated_at=timestamp)
    passive_warnings = build_passive_capture_safety_warnings(
        platform_record=platform_payload,
        capture_plan=capture_plan,
        backends=backends,
        span_readiness=span_readiness,
        runtime_health=runtime_health,
        gateway_validation=gateway_validation,
        generated_at=timestamp,
    )
    summary = summarize_capture_readiness(
        platform_record=platform_payload,
        inventory=inventory,
        capture_plan=capture_plan,
        backends=backends,
        permission=permission,
        passive_warnings=passive_warnings,
        generated_at=timestamp,
    )
    dashboard = build_capture_readiness_dashboard_record(
        summary=summary,
        capture_plan=capture_plan,
        backends=backends,
        permission=permission,
        passive_warnings=passive_warnings,
        generated_at=timestamp,
    )
    api = build_capture_readiness_api_response(
        summary=summary,
        platform_record=platform_payload,
        inventory=inventory,
        capture_plan=capture_plan,
        backends=backends,
        permission=permission,
        passive_warnings=passive_warnings,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    return {
        "record_type": "cross_platform_capture_readiness_report",
        "record_version": CAPTURE_READINESS_RECORD_VERSION,
        "report_id": "capture-readiness-" + _digest({"generated_at": timestamp, "platform": platform_family, "summary": summary})[:16],
        "generated_at": timestamp,
        "platform": platform_payload,
        "interface_inventory": inventory,
        "capture_plan": capture_plan,
        "backend_readiness": backends,
        "permission_requirements": permission,
        "passive_capture_warnings": passive_warnings,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **CAPTURE_READINESS_SAFETY_FLAGS,
    }


def build_capture_permission_requirement_summary(
    platform_record: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str(platform_record.get("platform_family") or "unknown")
    permissions = platform_record.get("permissions") if isinstance(platform_record.get("permissions"), dict) else {}
    elevated = bool(permissions.get("elevated"))
    requires_manual_permission = platform_family in {"macos", "linux", "raspberry-pi-linux-arm", "windows"}
    status = "supported" if requires_manual_permission and elevated else "degraded" if requires_manual_permission else "unknown"
    warnings = []
    if requires_manual_permission and not elevated:
        warnings.append("manual_capture_permission_review_required")
    if platform_family == "windows":
        warnings.append("npcap_or_equivalent_not_assumed")
    if platform_family == "unknown":
        warnings.append("platform_family_unknown")
    return {
        "record_type": "capture_permission_requirement_summary",
        "record_version": CAPTURE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "platform_family": platform_family,
        "status": status,
        "currently_elevated": elevated,
        "requires_manual_permission_for_future_capture": requires_manual_permission,
        "admin_or_root_required_for_future_capture": requires_manual_permission,
        "elevation_requested": False,
        "permission_change_attempted": False,
        "warnings": sorted(set(warnings)),
        **CAPTURE_READINESS_SAFETY_FLAGS,
    }


def build_passive_capture_safety_warnings(
    *,
    platform_record: dict[str, Any],
    capture_plan: dict[str, Any],
    backends: dict[str, Any],
    span_readiness: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    warnings = {
        "packet_payload_storage_prohibited",
        "capture_loop_disabled",
        "interface_mode_changes_disabled",
        "promiscuous_mode_disabled",
        "provider_install_disabled",
    }
    backend_summary = backends.get("summary") if isinstance(backends.get("summary"), dict) else {}
    warnings.update(backend_summary.get("warnings") or [])
    capture_summary = capture_plan.get("summary") if isinstance(capture_plan.get("summary"), dict) else {}
    validation = capture_plan.get("validation") if isinstance(capture_plan.get("validation"), dict) else {}
    warnings.update(capture_summary.get("warnings") or [])
    warnings.update(validation.get("warnings") or [])
    for source_name, record in {
        "span_readiness": span_readiness,
        "runtime_health": runtime_health,
        "gateway_validation": gateway_validation,
    }.items():
        status = _nested_status(record)
        if status in {"degraded", "review_required", "unsafe", "unknown"}:
            warnings.add(f"{source_name}_{status}")
    if str(platform_record.get("platform_family") or "unknown") == "raspberry-pi-linux-arm":
        warnings.add("edge_device_resource_review_required")
    return {
        "record_type": "passive_capture_safety_warnings",
        "record_version": CAPTURE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "warning_count": len(warnings),
        "warnings": sorted(warnings),
        **CAPTURE_READINESS_SAFETY_FLAGS,
    }


def summarize_capture_readiness(
    *,
    platform_record: dict[str, Any],
    inventory: dict[str, Any],
    capture_plan: dict[str, Any],
    backends: dict[str, Any],
    permission: dict[str, Any],
    passive_warnings: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    backend_status = str((backends.get("summary") or {}).get("status") or "unknown")
    permission_status = str(permission.get("status") or "unknown")
    platform_family = str(platform_record.get("platform_family") or "unknown")
    interface_count = int((inventory.get("summary") or {}).get("interface_count") or 0)
    selected_count = int((capture_plan.get("summary") or {}).get("selected_interface_count") or 0)
    if platform_family == "unknown":
        status = "unknown"
    elif backend_status == "supported" and permission_status == "supported" and interface_count:
        status = "supported"
    elif backend_status in {"degraded", "supported"} or permission_status == "degraded" or interface_count:
        status = "degraded"
    else:
        status = "unavailable"
    warnings = sorted(set(list((backends.get("summary") or {}).get("warnings") or []) + list(permission.get("warnings") or []) + list(passive_warnings.get("warnings") or [])))
    return {
        "record_type": "capture_readiness_summary",
        "record_version": CAPTURE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "platform_family": platform_family,
        "backend_status": backend_status,
        "permission_status": permission_status,
        "interface_count": interface_count,
        "selected_interface_count": selected_count,
        "warning_count": len(warnings),
        "warnings": warnings,
        "operator_summary": _operator_summary(status, platform_family),
        **CAPTURE_READINESS_SAFETY_FLAGS,
    }


def build_capture_readiness_dashboard_record(
    *,
    summary: dict[str, Any],
    capture_plan: dict[str, Any],
    backends: dict[str, Any],
    permission: dict[str, Any],
    passive_warnings: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    backend_rows = [
        {
            "backend_name": row.get("backend_name"),
            "status": row.get("status"),
            "provider_label": row.get("provider_label"),
        }
        for row in backends.get("backends") or []
        if isinstance(row, dict)
    ]
    return {
        "record_type": "capture_readiness_dashboard",
        "panel": "cross_platform_packet_capture_readiness",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "interface_count": int(summary.get("interface_count") or 0),
            "selected_interface_count": int(summary.get("selected_interface_count") or 0),
            "backend_count": int((backends.get("summary") or {}).get("backend_count") or 0),
            "warning_count": int(summary.get("warning_count") or 0),
            "packets_captured": 0,
        },
        "backend_rows": sorted(backend_rows, key=lambda item: str(item.get("backend_name") or "")),
        "permission_status": str(permission.get("status") or "unknown"),
        "capture_plan_status": str((capture_plan.get("dashboard_status") or {}).get("status") or "unknown"),
        "warnings": list(passive_warnings.get("warnings") or []),
        "recommended_review": str(summary.get("status") or "") != "supported",
        **CAPTURE_READINESS_SAFETY_FLAGS,
    }


def build_capture_readiness_api_response(
    *,
    summary: dict[str, Any],
    platform_record: dict[str, Any],
    inventory: dict[str, Any],
    capture_plan: dict[str, Any],
    backends: dict[str, Any],
    permission: dict[str, Any],
    passive_warnings: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "capture_readiness_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "platform": dict(platform_record),
        "interface_inventory": dict(inventory),
        "capture_plan": dict(capture_plan),
        "backend_readiness": dict(backends),
        "permission_requirements": dict(permission),
        "passive_capture_warnings": dict(passive_warnings),
        "dashboard": dict(dashboard),
        **CAPTURE_READINESS_SAFETY_FLAGS,
    }


def deterministic_capture_readiness_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _nested_status(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict):
        return "unknown"
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    dashboard = record.get("dashboard_status") if isinstance(record.get("dashboard_status"), dict) else {}
    return str(record.get("status") or summary.get("status") or dashboard.get("status") or "unknown")


def _operator_summary(status: str, platform_family: str) -> str:
    if status == "supported":
        return f"{platform_family} packet capture readiness is supported for dry-run metadata planning."
    if status == "degraded":
        return f"{platform_family} packet capture readiness requires operator review before any future capture."
    if status == "unavailable":
        return "Packet capture readiness is unavailable for the provided platform and interface records."
    return "Packet capture readiness is unknown and requires operator review."


def _digest(payload: Any) -> str:
    return sha256(deterministic_capture_readiness_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "CAPTURE_READINESS_RECORD_VERSION",
    "CAPTURE_READINESS_SAFETY_FLAGS",
    "build_capture_permission_requirement_summary",
    "build_capture_readiness_api_response",
    "build_capture_readiness_dashboard_record",
    "build_cross_platform_capture_readiness_report",
    "build_passive_capture_safety_warnings",
    "deterministic_capture_readiness_json",
    "summarize_capture_readiness",
]
