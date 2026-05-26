from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.gateway.mirror_profiles import (
    SPAN_READINESS_RECORD_VERSION,
    SPAN_READINESS_SAFETY_FLAGS,
    build_interface_capability_summary,
    build_packet_loss_risk_summary,
    build_passive_capture_requirement_summary,
    build_privilege_requirement_summary,
    build_span_mirror_profile,
    build_span_resource_budget_check,
    build_telemetry_scaling_summary,
    normalize_span_mirror_profile,
)
from core_engine.telemetry.capture_sessions import build_passive_capture_session_plan
from core_engine.telemetry.interfaces import enumerate_local_interfaces


class SpanReadinessError(ValueError):
    """Raised when SPAN/mirror-port readiness inputs are malformed."""


def build_span_readiness_report(
    *,
    profile: dict[str, Any] | None = None,
    interface_inventory: dict[str, Any] | None = None,
    interfaces: dict[str, Any] | None = None,
    interface_name: str | None = None,
    expected_traffic_mbps: float | None = None,
    expected_packet_rate: int | None = None,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a dry-run SPAN/mirror-port readiness report without changing interface state."""
    timestamp = generated_at or _now()
    profile_record = _profile_record(
        profile=profile,
        interface_name=interface_name,
        expected_traffic_mbps=expected_traffic_mbps,
        expected_packet_rate=expected_packet_rate,
        edge_device=edge_device,
        generated_at=timestamp,
    )
    inventory = interface_inventory or enumerate_local_interfaces(interfaces=interfaces, generated_at=timestamp)
    selected_interface = _find_interface(inventory, str(profile_record.get("interface_name") or ""))
    capability = build_interface_capability_summary(selected_interface, generated_at=timestamp)
    resource_budget = build_span_resource_budget_check(profile_record, selected_interface_count=1 if selected_interface else 0, generated_at=timestamp)
    privilege = build_privilege_requirement_summary(profile_record, generated_at=timestamp)
    packet_loss = build_packet_loss_risk_summary(profile_record, resource_budget, generated_at=timestamp)
    scaling = build_telemetry_scaling_summary(profile_record, resource_budget, generated_at=timestamp)
    capture_plan = build_passive_capture_session_plan(
        selected_interfaces=[str(profile_record.get("interface_name") or "")],
        interface_inventory=inventory,
        edge_device=bool(profile_record.get("edge_device")),
        generated_at=timestamp,
    )
    checklist = build_operator_readiness_checklist(
        capability=capability,
        resource_budget=resource_budget,
        privilege=privilege,
        packet_loss=packet_loss,
        capture_plan=capture_plan,
        generated_at=timestamp,
    )
    summary = summarize_span_readiness(
        profile=profile_record,
        capability=capability,
        resource_budget=resource_budget,
        packet_loss=packet_loss,
        checklist=checklist,
        generated_at=timestamp,
    )
    dashboard = build_span_readiness_dashboard_record(summary=summary, checklist=checklist, generated_at=timestamp)
    api = build_span_readiness_api_response(
        summary=summary,
        profile=profile_record,
        capability=capability,
        resource_budget=resource_budget,
        packet_loss=packet_loss,
        scaling=scaling,
        checklist=checklist,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    return {
        "record_type": "span_readiness_report",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "report_id": "span-readiness-report-" + _digest({"generated_at": timestamp, "profile": profile_record.get("profile_ref"), "summary": summary})[:16],
        "generated_at": timestamp,
        "profile": profile_record,
        "interface_capability": capability,
        "passive_capture_requirements": build_passive_capture_requirement_summary(profile_record, generated_at=timestamp),
        "resource_budget": resource_budget,
        "privilege_requirements": privilege,
        "packet_loss_risk": packet_loss,
        "telemetry_scaling": scaling,
        "capture_plan": capture_plan,
        "operator_checklist": checklist,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def summarize_span_readiness(
    *,
    profile: dict[str, Any],
    capability: dict[str, Any],
    resource_budget: dict[str, Any],
    packet_loss: dict[str, Any],
    checklist: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    warnings = sorted(
        set(
            list(capability.get("warnings") or [])
            + list(resource_budget.get("warnings") or [])
            + list(packet_loss.get("warnings") or [])
        )
    )
    blocked_count = int(checklist.get("blocked_count") or 0)
    review_count = int(checklist.get("review_count") or 0)
    risk = str(packet_loss.get("risk_level") or "unknown")
    if blocked_count:
        status = "unsafe"
    elif review_count or warnings or risk in {"medium", "high"}:
        status = "review_required"
    else:
        status = "ready"
    return {
        "record_type": "span_readiness_summary",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "interface_name": str(profile.get("interface_name") or ""),
        "edge_device": bool(profile.get("edge_device")),
        "expected_traffic_mbps": float(profile.get("expected_traffic_mbps") or 0.0),
        "expected_packet_rate": int(profile.get("expected_packet_rate") or 0),
        "packet_loss_risk": risk,
        "check_count": int(checklist.get("check_count") or 0),
        "passed_count": int(checklist.get("passed_count") or 0),
        "review_count": review_count,
        "blocked_count": blocked_count,
        "warnings": warnings,
        "operator_summary": _operator_summary(status, str(profile.get("interface_name") or "")),
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_operator_readiness_checklist(
    *,
    capability: dict[str, Any],
    resource_budget: dict[str, Any],
    privilege: dict[str, Any],
    packet_loss: dict[str, Any],
    capture_plan: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    checks = [
        _check_item(
            "interface_selected",
            "Interface exists and is operator selectable.",
            "pass" if capability.get("operator_selectable") else "block",
            capability.get("warnings") or [],
        ),
        _check_item(
            "passive_capture_mode",
            "Readiness is passive, metadata-only, and dry-run.",
            "pass",
            [],
        ),
        _check_item(
            "resource_budget",
            "Expected mirrored traffic fits local resource budget.",
            "pass" if resource_budget.get("status") == "within_budget" else "review",
            resource_budget.get("warnings") or [],
        ),
        _check_item(
            "operator_permissions",
            "OS-level capture permissions are reviewed manually by the operator.",
            "review" if privilege.get("requires_manual_os_permission") else "pass",
            ["manual_permission_review_required"] if privilege.get("requires_manual_os_permission") else [],
        ),
        _check_item(
            "packet_loss_risk",
            "Expected traffic volume has acceptable packet-loss risk.",
            "review" if packet_loss.get("risk_level") in {"medium", "high"} else "pass",
            [f"packet_loss_risk:{packet_loss.get('risk_level')}"],
        ),
        _check_item(
            "capture_loop_disabled",
            "No live SPAN capture loop is started by readiness checks.",
            "pass" if not capture_plan.get("capture_loop_started") else "block",
            [],
        ),
    ]
    return {
        "record_type": "span_operator_readiness_checklist",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "checks": checks,
        "check_count": len(checks),
        "passed_count": sum(1 for item in checks if item["status"] == "pass"),
        "review_count": sum(1 for item in checks if item["status"] == "review"),
        "blocked_count": sum(1 for item in checks if item["status"] == "block"),
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_span_readiness_dashboard_record(
    *,
    summary: dict[str, Any],
    checklist: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "span_readiness_dashboard",
        "panel": "span_mirror_readiness",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "check_count": int(summary.get("check_count") or 0),
            "passed_count": int(summary.get("passed_count") or 0),
            "review_count": int(summary.get("review_count") or 0),
            "blocked_count": int(summary.get("blocked_count") or 0),
            "expected_packet_rate": int(summary.get("expected_packet_rate") or 0),
            "expected_traffic_mbps": float(summary.get("expected_traffic_mbps") or 0.0),
        },
        "rows": [
            {
                "check_id": item.get("check_id"),
                "status": item.get("status"),
                "label": item.get("label"),
            }
            for item in checklist.get("checks") or []
            if isinstance(item, dict)
        ],
        "recommended_review": str(summary.get("status")) != "ready",
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_span_readiness_api_response(
    *,
    summary: dict[str, Any],
    profile: dict[str, Any],
    capability: dict[str, Any],
    resource_budget: dict[str, Any],
    packet_loss: dict[str, Any],
    scaling: dict[str, Any],
    checklist: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "span_readiness_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "profile": dict(profile),
        "interface_capability": dict(capability),
        "resource_budget": dict(resource_budget),
        "packet_loss_risk": dict(packet_loss),
        "telemetry_scaling": dict(scaling),
        "operator_checklist": dict(checklist),
        "dashboard": dict(dashboard),
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def deterministic_span_readiness_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _profile_record(
    *,
    profile: dict[str, Any] | None,
    interface_name: str | None,
    expected_traffic_mbps: float | None,
    expected_packet_rate: int | None,
    edge_device: bool,
    generated_at: str,
) -> dict[str, Any]:
    if profile is not None:
        merged = dict(profile)
        if interface_name is not None:
            merged["interface_name"] = interface_name
        if expected_traffic_mbps is not None:
            merged["expected_traffic_mbps"] = expected_traffic_mbps
        if expected_packet_rate is not None:
            merged["expected_packet_rate"] = expected_packet_rate
        if edge_device:
            merged["edge_device"] = True
        return normalize_span_mirror_profile(merged, generated_at=generated_at)
    if not interface_name:
        raise SpanReadinessError("interface_name is required when profile is not provided")
    return build_span_mirror_profile(
        interface_name=interface_name,
        expected_traffic_mbps=expected_traffic_mbps or 0.0,
        expected_packet_rate=expected_packet_rate or 0,
        edge_device=edge_device,
        generated_at=generated_at,
    )


def _find_interface(inventory: dict[str, Any], interface_name: str) -> dict[str, Any] | None:
    for row in inventory.get("interfaces") or []:
        if isinstance(row, dict) and str(row.get("interface_name") or "") == interface_name:
            return dict(row)
    return None


def _check_item(check_id: str, label: str, status: str, warnings: list[Any]) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "label": label,
        "status": status,
        "warnings": sorted(str(item) for item in warnings),
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def _operator_summary(status: str, interface_name: str) -> str:
    if status == "ready":
        return f"SPAN readiness for {interface_name} is dry-run ready; no interface changes were made."
    if status == "unsafe":
        return f"SPAN readiness for {interface_name} is blocked until interface selection is corrected."
    return f"SPAN readiness for {interface_name} requires operator review before any future live capture."


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "SpanReadinessError",
    "build_operator_readiness_checklist",
    "build_span_readiness_api_response",
    "build_span_readiness_dashboard_record",
    "build_span_readiness_report",
    "deterministic_span_readiness_json",
    "summarize_span_readiness",
]
