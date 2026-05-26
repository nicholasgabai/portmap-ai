from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.gateway.router_logs import GATEWAY_LOG_SAFETY_FLAGS
from core_engine.runtime.health import DEFAULT_RESOURCE_BUDGETS, RASPBERRY_PI_RESOURCE_BUDGETS
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


SPAN_READINESS_RECORD_VERSION = 1
DEFAULT_EXPECTED_TRAFFIC_MBPS = 25.0
DEFAULT_EXPECTED_PACKET_RATE = 2500
EDGE_TRAFFIC_WARNING_MBPS = 75.0
EDGE_PACKET_RATE_WARNING = 7500
DEFAULT_TRAFFIC_WARNING_MBPS = 250.0
DEFAULT_PACKET_RATE_WARNING = 25000

SPAN_READINESS_SAFETY_FLAGS = {
    **GATEWAY_LOG_SAFETY_FLAGS,
    **TELEMETRY_SAFETY_FLAGS,
    "span_readiness_only": True,
    "passive_capture_required": True,
    "promiscuous_mode_enabled": False,
    "interface_mode_changed": False,
    "capture_loop_started": False,
    "switch_settings_modified": False,
    "router_settings_modified": False,
    "service_started": False,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
}


class SpanMirrorProfileError(ValueError):
    """Raised when a SPAN/mirror-port readiness profile is malformed."""


def build_span_mirror_profile(
    *,
    profile_id: str = "span-profile-placeholder",
    interface_name: str,
    profile_name: str = "SPAN Mirror Readiness",
    expected_traffic_mbps: float = DEFAULT_EXPECTED_TRAFFIC_MBPS,
    expected_packet_rate: int = DEFAULT_EXPECTED_PACKET_RATE,
    edge_device: bool = False,
    operator_notes: str = "",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not str(interface_name or "").strip():
        raise SpanMirrorProfileError("interface_name is required")
    profile = {
        "record_type": "span_mirror_profile",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "profile_id": str(profile_id or "span-profile-placeholder"),
        "profile_name": str(profile_name or "SPAN Mirror Readiness"),
        "interface_name": str(interface_name),
        "expected_traffic_mbps": max(0.0, float(expected_traffic_mbps or 0.0)),
        "expected_packet_rate": max(0, int(expected_packet_rate or 0)),
        "edge_device": bool(edge_device),
        "operator_notes": _sanitize_operator_notes(operator_notes),
        "generated_at": timestamp,
        "source_refs": [f"span-profile:{profile_id or 'placeholder'}", f"interface:{interface_name}"],
        **SPAN_READINESS_SAFETY_FLAGS,
    }
    profile["profile_ref"] = "span-profile-" + _digest(profile)[:16]
    profile["passive_capture_requirements"] = build_passive_capture_requirement_summary(profile, generated_at=timestamp)
    profile["expected_traffic"] = build_expected_traffic_volume_summary(profile, generated_at=timestamp)
    profile["privilege_requirements"] = build_privilege_requirement_summary(profile, generated_at=timestamp)
    return profile


def normalize_span_mirror_profile(payload: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SpanMirrorProfileError("profile payload must be an object")
    return build_span_mirror_profile(
        profile_id=str(payload.get("profile_id") or payload.get("profile_ref") or "span-profile-placeholder"),
        interface_name=str(payload.get("interface_name") or ""),
        profile_name=str(payload.get("profile_name") or "SPAN Mirror Readiness"),
        expected_traffic_mbps=float(payload.get("expected_traffic_mbps") or DEFAULT_EXPECTED_TRAFFIC_MBPS),
        expected_packet_rate=int(payload.get("expected_packet_rate") or DEFAULT_EXPECTED_PACKET_RATE),
        edge_device=bool(payload.get("edge_device")),
        operator_notes=str(payload.get("operator_notes") or ""),
        generated_at=generated_at or str(payload.get("generated_at") or _now()),
    )


def build_passive_capture_requirement_summary(profile: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "span_passive_capture_requirements",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "interface_name": str(profile.get("interface_name") or ""),
        "requirements": [
            "operator_selects_interface",
            "mirror_source_configured_outside_portmap",
            "metadata_only_capture",
            "bounded_ingestion_window",
            "no_inline_packet_modification",
            "no_automatic_blocking",
        ],
        "capture_mode": "passive-metadata-only",
        "payload_retention": "disabled",
        "dry_run_only": True,
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_interface_capability_summary(interface: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    row = dict(interface or {})
    interface_name = str(row.get("interface_name") or "")
    missing = not interface_name
    loopback = bool(row.get("loopback"))
    link_local = bool(row.get("link_local_only"))
    operator_selectable = bool(row.get("operator_selectable", not missing))
    warnings: list[str] = []
    if missing:
        warnings.append("interface_not_found")
    if loopback:
        warnings.append("loopback_interface_not_suitable_for_span")
    if link_local:
        warnings.append("link_local_only_interface_requires_review")
    if not operator_selectable:
        warnings.append("interface_not_operator_selectable")
    return {
        "record_type": "span_interface_capability_summary",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "interface_name": interface_name,
        "interface_id": str(row.get("interface_id") or ""),
        "classification": str(row.get("classification") or ("missing" if missing else "unknown")),
        "operator_selectable": operator_selectable and not missing,
        "broadcast_capable": bool(row.get("broadcast_capable")),
        "multicast_capable": bool(row.get("multicast_capable")),
        "loopback": loopback,
        "link_local_only": link_local,
        "address_family_summary": dict(row.get("address_family_summary") or {}),
        "status": "ok" if not warnings else "review_required",
        "warnings": warnings,
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_expected_traffic_volume_summary(profile: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    edge_device = bool(profile.get("edge_device"))
    expected_mbps = max(0.0, float(profile.get("expected_traffic_mbps") or 0.0))
    expected_pps = max(0, int(profile.get("expected_packet_rate") or 0))
    mbps_limit = EDGE_TRAFFIC_WARNING_MBPS if edge_device else DEFAULT_TRAFFIC_WARNING_MBPS
    pps_limit = EDGE_PACKET_RATE_WARNING if edge_device else DEFAULT_PACKET_RATE_WARNING
    warnings: list[str] = []
    if expected_mbps > mbps_limit:
        warnings.append("expected_traffic_mbps_exceeds_budget")
    if expected_pps > pps_limit:
        warnings.append("expected_packet_rate_exceeds_budget")
    return {
        "record_type": "span_expected_traffic_volume",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "edge_device": edge_device,
        "expected_traffic_mbps": expected_mbps,
        "expected_packet_rate": expected_pps,
        "warning_traffic_mbps": mbps_limit,
        "warning_packet_rate": pps_limit,
        "status": "within_budget" if not warnings else "review_required",
        "warnings": warnings,
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_span_resource_budget_check(
    profile: dict[str, Any],
    *,
    selected_interface_count: int = 1,
    generated_at: str | None = None,
) -> dict[str, Any]:
    edge_device = bool(profile.get("edge_device"))
    budgets = RASPBERRY_PI_RESOURCE_BUDGETS if edge_device else DEFAULT_RESOURCE_BUDGETS
    traffic = build_expected_traffic_volume_summary(profile, generated_at=generated_at)
    warnings = list(traffic.get("warnings") or [])
    selected_limit = 1 if edge_device else 2
    if int(selected_interface_count) > selected_limit:
        warnings.append("selected_interface_count_exceeds_span_budget")
    return {
        "record_type": "span_resource_budget_check",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "edge_device": edge_device,
        "selected_interface_count": int(selected_interface_count),
        "max_selected_interfaces": selected_limit,
        "event_queue_warning_depth": int(budgets["event_queue_warning_depth"]),
        "expected_traffic": traffic,
        "status": "within_budget" if not warnings else "review_required",
        "warnings": sorted(set(warnings)),
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_privilege_requirement_summary(profile: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "span_privilege_requirement_summary",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "interface_name": str(profile.get("interface_name") or ""),
        "requires_operator_review": True,
        "requires_manual_os_permission": True,
        "privilege_escalation_attempted": False,
        "automatic_permission_change": False,
        "operator_summary": "SPAN capture may require OS-level packet capture permissions; PortMap-AI records the requirement only.",
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_packet_loss_risk_summary(
    profile: dict[str, Any],
    resource_budget: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    expected_mbps = max(0.0, float(profile.get("expected_traffic_mbps") or 0.0))
    expected_pps = max(0, int(profile.get("expected_packet_rate") or 0))
    edge_device = bool(profile.get("edge_device"))
    score = 0
    if expected_mbps > (EDGE_TRAFFIC_WARNING_MBPS if edge_device else DEFAULT_TRAFFIC_WARNING_MBPS):
        score += 2
    if expected_pps > (EDGE_PACKET_RATE_WARNING if edge_device else DEFAULT_PACKET_RATE_WARNING):
        score += 2
    if resource_budget.get("status") != "within_budget":
        score += 1
    risk_level = "high" if score >= 3 else "medium" if score else "low"
    return {
        "record_type": "span_packet_loss_risk_summary",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "risk_level": risk_level,
        "risk_score": score,
        "expected_traffic_mbps": expected_mbps,
        "expected_packet_rate": expected_pps,
        "warnings": list(resource_budget.get("warnings") or []),
        "operator_summary": _packet_loss_operator_summary(risk_level),
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def build_telemetry_scaling_summary(
    profile: dict[str, Any],
    resource_budget: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    edge_device = bool(profile.get("edge_device"))
    expected_pps = max(0, int(profile.get("expected_packet_rate") or 0))
    update_interval_seconds = 10 if edge_device else 5
    max_records_per_window = 500 if edge_device else 2000
    if expected_pps > (EDGE_PACKET_RATE_WARNING if edge_device else DEFAULT_PACKET_RATE_WARNING):
        max_records_per_window = max(100, max_records_per_window // 2)
    return {
        "record_type": "span_telemetry_scaling_summary",
        "record_version": SPAN_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "edge_device": edge_device,
        "recommended_update_interval_seconds": update_interval_seconds,
        "recommended_max_records_per_window": max_records_per_window,
        "resource_status": str(resource_budget.get("status") or "unknown"),
        "dashboard_safe": True,
        "api_compatible": True,
        **SPAN_READINESS_SAFETY_FLAGS,
    }


def deterministic_mirror_profile_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _packet_loss_operator_summary(risk_level: str) -> str:
    if risk_level == "high":
        return "High packet-loss risk for passive mirror-port telemetry; reduce expected volume or use a stronger capture host."
    if risk_level == "medium":
        return "Moderate packet-loss risk; operator should review traffic volume and resource budgets before live capture."
    return "Low packet-loss risk in dry-run readiness records."


def _sanitize_operator_notes(value: str) -> str:
    text = str(value or "")
    blocked = ("/" + "Users/", "/" + "home/", "BEGIN ", "PRIVATE KEY", "token" + "=", "password" + "=")
    if any(marker.lower() in text.lower() for marker in blocked):
        return "redacted"
    return text[:160]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "DEFAULT_EXPECTED_PACKET_RATE",
    "DEFAULT_EXPECTED_TRAFFIC_MBPS",
    "EDGE_PACKET_RATE_WARNING",
    "EDGE_TRAFFIC_WARNING_MBPS",
    "SPAN_READINESS_RECORD_VERSION",
    "SPAN_READINESS_SAFETY_FLAGS",
    "SpanMirrorProfileError",
    "build_expected_traffic_volume_summary",
    "build_interface_capability_summary",
    "build_packet_loss_risk_summary",
    "build_passive_capture_requirement_summary",
    "build_privilege_requirement_summary",
    "build_span_mirror_profile",
    "build_span_resource_budget_check",
    "build_telemetry_scaling_summary",
    "deterministic_mirror_profile_json",
    "normalize_span_mirror_profile",
]
