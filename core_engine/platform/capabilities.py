from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


CAPABILITY_STATUSES = frozenset({"supported", "degraded", "unavailable", "unknown"})

PLATFORM_CAPABILITY_SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "administrator_controlled": True,
    "advisory": True,
    "dry_run": True,
    "preview_only": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "automatic_changes": False,
    "firewall_rules_changed": False,
    "service_installed": False,
    "service_started": False,
    "packet_capture_enabled": False,
    "capture_mode_changed": False,
    "privilege_escalation_attempted": False,
    "dashboard_safe": True,
    "api_compatible": True,
}


def build_platform_capability_summary(
    *,
    platform_record: dict[str, Any] | None = None,
    runtime_profile: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    telemetry_readiness: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build dry-run platform capability placeholders from local runtime summaries."""
    timestamp = generated_at or _now()
    platform_payload = dict(platform_record or {})
    capabilities = [
        build_packet_capture_capability(platform_payload, telemetry_readiness=telemetry_readiness, generated_at=timestamp),
        build_firewall_provider_capability(platform_payload, gateway_validation=gateway_validation, generated_at=timestamp),
        build_service_mode_capability(platform_payload, runtime_profile=runtime_profile, service_mode=service_mode, generated_at=timestamp),
        build_path_export_capability(platform_payload, runtime_profile=runtime_profile, runtime_health=runtime_health, generated_at=timestamp),
    ]
    summary = summarize_platform_capabilities(capabilities, generated_at=timestamp)
    dashboard = build_platform_capability_dashboard_record(summary=summary, capabilities=capabilities, generated_at=timestamp)
    api = build_platform_capability_api_response(summary=summary, capabilities=capabilities, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "platform_capability_summary",
        "record_version": 1,
        "capability_summary_id": "platform-capabilities-" + _digest(
            {
                "generated_at": timestamp,
                "platform_family": platform_payload.get("platform_family"),
                "capabilities": [row.get("capability") for row in capabilities],
            }
        )[:16],
        "generated_at": timestamp,
        "platform_family": str(platform_payload.get("platform_family") or "unknown"),
        "capabilities": sorted(capabilities, key=lambda item: str(item.get("capability") or "")),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    }


def build_packet_capture_capability(
    platform_record: dict[str, Any] | None = None,
    *,
    telemetry_readiness: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    readiness_status = _nested_status(telemetry_readiness)
    status = "unknown"
    warnings: list[str] = ["packet_capture_not_enabled_by_runtime_detection"]
    summary = "Packet capture readiness is a dry-run placeholder."
    if platform_family in {"macos", "linux", "raspberry-pi-linux-arm", "windows"}:
        status = "degraded"
        warnings.append("operator_permission_review_required")
        summary = "Packet capture support requires a later dry-run readiness check and manual operator approval."
    if readiness_status in {"ready", "supported", "ok"}:
        status = "supported"
        warnings = ["packet_capture_still_disabled"]
        summary = "Packet capture readiness records are available, but capture remains disabled here."
    elif readiness_status in {"review_required", "degraded"}:
        status = "degraded"
        warnings.append("telemetry_readiness_requires_review")
    elif platform_family == "unknown":
        status = "unknown"
        warnings.append("platform_family_unknown")
    return build_capability_status_record(
        "packet_capture",
        status,
        summary,
        details={
            "provider_placeholders": _capture_provider_placeholders(platform_family),
            "telemetry_readiness_status": readiness_status,
            "capture_enabled": False,
            "mode_changes_performed": False,
        },
        warnings=warnings,
        generated_at=generated_at,
    )


def build_firewall_provider_capability(
    platform_record: dict[str, Any] | None = None,
    *,
    gateway_validation: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    gateway_status = _nested_status(gateway_validation)
    provider_map = {
        "macos": ["pf"],
        "linux": ["nftables", "ufw", "iptables"],
        "raspberry-pi-linux-arm": ["nftables", "ufw", "iptables"],
        "windows": ["windows-defender-firewall"],
    }
    providers = provider_map.get(platform_family, [])
    status = "degraded" if providers else "unknown"
    warnings = ["firewall_preview_only", "automatic_blocking_disabled"]
    if gateway_status in {"supported", "ok", "ready"}:
        status = "supported"
    elif gateway_status in {"unsafe"}:
        status = "degraded"
        warnings.append("gateway_validation_unsafe")
    elif not providers:
        warnings.append("platform_family_unknown")
    return build_capability_status_record(
        "firewall_provider",
        status,
        "Firewall provider readiness is preview-only; no rules are changed.",
        details={
            "provider_placeholders": providers,
            "gateway_validation_status": gateway_status,
            "rules_changed": False,
            "automatic_blocking": False,
        },
        warnings=warnings,
        generated_at=generated_at,
    )


def build_service_mode_capability(
    platform_record: dict[str, Any] | None = None,
    *,
    runtime_profile: dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    service_status = _nested_status(service_mode)
    platforms = {
        "macos": ["launch-agent-preview"],
        "linux": ["systemd-preview"],
        "raspberry-pi-linux-arm": ["systemd-preview"],
        "windows": ["windows-service-preview"],
    }.get(platform_family, [])
    runtime_mode = str((runtime_profile or {}).get("runtime_mode") or "")
    status = "degraded" if platforms else "unknown"
    if service_status in {"ok", "ready", "compatible", "supported"}:
        status = "supported"
    warnings = ["service_mode_preview_only", "manual_install_required"]
    if runtime_mode and runtime_mode != "dry-run":
        warnings.append("non_default_runtime_mode_requires_review")
    if not platforms:
        warnings.append("platform_family_unknown")
    return build_capability_status_record(
        "service_mode",
        status,
        "Service-mode capability is a dry-run preview and does not install or start services.",
        details={
            "service_preview_placeholders": platforms,
            "runtime_mode": runtime_mode or "unknown",
            "service_mode_status": service_status,
            "installation_performed": False,
            "service_started": False,
        },
        warnings=warnings,
        generated_at=generated_at,
    )


def build_path_export_capability(
    platform_record: dict[str, Any] | None = None,
    *,
    runtime_profile: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    health_status = _nested_status(runtime_health)
    export_config = dict((runtime_profile or {}).get("export") or {})
    placeholder = export_config.get("output_path") or _default_export_placeholder(platform_family)
    status = "supported" if platform_family in {"macos", "linux", "raspberry-pi-linux-arm", "windows"} else "unknown"
    warnings = ["operator_provided_export_path_required"]
    if health_status in {"degraded", "unsafe"}:
        status = "degraded"
        warnings.append("runtime_health_requires_review")
    if platform_family == "unknown":
        warnings.append("platform_family_unknown")
    return build_capability_status_record(
        "path_export",
        status,
        "Path and export capability uses sanitized placeholders and operator-provided local paths.",
        details={
            "export_path_placeholder": str(placeholder),
            "safe_log_path_placeholder": _default_log_placeholder(platform_family),
            "runtime_health_status": health_status,
            "external_export_delivery": False,
        },
        warnings=warnings,
        generated_at=generated_at,
    )


def build_capability_status_record(
    capability: str,
    status: str,
    summary: str,
    *,
    details: dict[str, Any] | None = None,
    warnings: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    normalized = _status(status)
    timestamp = generated_at or _now()
    record = {
        "record_type": "platform_capability_status",
        "record_version": 1,
        "capability": str(capability),
        "status": normalized,
        "summary": str(summary),
        "details": _sorted_dict(details or {}),
        "warnings": sorted(set(str(item) for item in warnings or [] if str(item))),
        "generated_at": timestamp,
        **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    }
    record["capability_id"] = "platform-capability-" + _digest(record)[:16]
    return record


def summarize_platform_capabilities(capabilities: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in capabilities or [] if isinstance(row, dict)]
    counts = {status: sum(1 for row in rows if row.get("status") == status) for status in sorted(CAPABILITY_STATUSES)}
    if counts["unavailable"]:
        status = "degraded"
    elif counts["degraded"]:
        status = "degraded"
    elif counts["supported"] and counts["unknown"] == 0:
        status = "supported"
    elif counts["unknown"]:
        status = "unknown"
    else:
        status = "unavailable"
    warnings = sorted({warning for row in rows for warning in list(row.get("warnings") or [])})
    return {
        "record_type": "platform_capabilities_rollup",
        "record_version": 1,
        "generated_at": generated_at or _now(),
        "status": status,
        "capability_count": len(rows),
        "supported_count": counts["supported"],
        "degraded_count": counts["degraded"],
        "unavailable_count": counts["unavailable"],
        "unknown_count": counts["unknown"],
        "capabilities_by_status": counts,
        "warnings": warnings,
        **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    }


def build_platform_capability_dashboard_record(
    *,
    summary: dict[str, Any],
    capabilities: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [
        {
            "capability": str(row.get("capability") or ""),
            "status": str(row.get("status") or "unknown"),
            "summary": str(row.get("summary") or ""),
            "warning_count": len(row.get("warnings") or []),
        }
        for row in capabilities or []
        if isinstance(row, dict)
    ]
    return {
        "record_type": "platform_capabilities_dashboard",
        "panel": "platform_capabilities",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "capability_count": int(summary.get("capability_count") or 0),
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unknown_count": int(summary.get("unknown_count") or 0),
        },
        "rows": sorted(rows, key=lambda item: item["capability"]),
        "recommended_review": str(summary.get("status") or "") != "supported",
        **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    }


def build_platform_capability_api_response(
    *,
    summary: dict[str, Any],
    capabilities: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "platform_capabilities_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "capabilities": sorted([dict(row) for row in capabilities or [] if isinstance(row, dict)], key=lambda item: str(item.get("capability") or "")),
        "dashboard": dict(dashboard),
        **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    }


def deterministic_platform_capability_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _capture_provider_placeholders(platform_family: str) -> list[str]:
    if platform_family == "macos":
        return ["bpf", "libpcap", "scapy"]
    if platform_family in {"linux", "raspberry-pi-linux-arm"}:
        return ["libpcap", "scapy"]
    if platform_family == "windows":
        return ["npcap", "winpcap", "scapy"]
    return []


def _default_export_placeholder(platform_family: str) -> str:
    if platform_family == "windows":
        return "<portmap-export-dir>\\bundle.json"
    return "<portmap-export-dir>/bundle.json"


def _default_log_placeholder(platform_family: str) -> str:
    if platform_family == "windows":
        return "<portmap-log-dir>\\portmap.log"
    return "<portmap-log-dir>/portmap.log"


def _nested_status(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict):
        return "unknown"
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    dashboard = record.get("dashboard_status") if isinstance(record.get("dashboard_status"), dict) else {}
    api = record.get("api_status") if isinstance(record.get("api_status"), dict) else {}
    return str(record.get("status") or summary.get("status") or dashboard.get("status") or api.get("status") or "unknown")


def _status(value: str) -> str:
    status = str(value or "unknown")
    return status if status in CAPABILITY_STATUSES else "unknown"


def _sorted_dict(payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(payload):
        value = payload[key]
        if isinstance(value, dict):
            result[str(key)] = _sorted_dict(value)
        elif isinstance(value, list):
            result[str(key)] = [_sorted_dict(item) if isinstance(item, dict) else item for item in value]
        else:
            result[str(key)] = value
    return result


def _digest(payload: Any) -> str:
    return sha256(deterministic_platform_capability_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "CAPABILITY_STATUSES",
    "PLATFORM_CAPABILITY_SAFETY_FLAGS",
    "build_capability_status_record",
    "build_firewall_provider_capability",
    "build_packet_capture_capability",
    "build_path_export_capability",
    "build_platform_capability_api_response",
    "build_platform_capability_dashboard_record",
    "build_platform_capability_summary",
    "build_service_mode_capability",
    "deterministic_platform_capability_json",
    "summarize_platform_capabilities",
]
