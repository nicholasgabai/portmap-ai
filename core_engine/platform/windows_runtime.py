from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.platform.capabilities import PLATFORM_CAPABILITY_SAFETY_FLAGS
from core_engine.platform.runtime_detection import (
    PLATFORM_RUNTIME_SAFETY_FLAGS,
    build_permission_summary,
    build_platform_runtime_record,
    build_runtime_compatibility_report,
)
from core_engine.platform.windows_paths import (
    WINDOWS_PATH_SAFETY_FLAGS,
    build_windows_path_summary,
)
from core_engine.runtime.profiles import (
    RuntimeProfile,
    default_runtime_profile,
    merge_runtime_profiles,
    runtime_profile_to_dict,
    summarize_runtime_profile,
)


WINDOWS_RUNTIME_SAFETY_FLAGS = {
    **PLATFORM_RUNTIME_SAFETY_FLAGS,
    **WINDOWS_PATH_SAFETY_FLAGS,
    "windows_service_installed": False,
    "windows_service_started": False,
    "windows_service_stopped": False,
    "windows_firewall_modified": False,
    "registry_keys_written": False,
    "npcap_assumed_installed": False,
}


def build_windows_runtime_compatibility_report(
    *,
    platform_info: dict[str, Any] | None = None,
    is_admin: bool | None = None,
    runtime_profile: RuntimeProfile | dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    process_service_attribution: dict[str, Any] | None = None,
    log_path: str | None = None,
    export_path: str | None = None,
    cache_path: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build Windows runtime compatibility records without changing the host."""
    timestamp = generated_at or _now()
    platform_payload = platform_info or {
        "system": "Windows",
        "release": "windows-release-placeholder",
        "machine": "AMD64",
        "python_version": "3.11.5",
    }
    platform_record = build_platform_runtime_record(platform_info=platform_payload, is_admin=is_admin, generated_at=timestamp)
    profile = runtime_profile_to_dict(runtime_profile) if runtime_profile is not None else build_windows_runtime_profile_defaults(generated_at=timestamp)
    path_summary = build_windows_path_summary(
        log_path=log_path,
        export_path=export_path or str((profile.get("export") or {}).get("output_path") or ""),
        cache_path=cache_path,
        data_path=str((profile.get("storage") or {}).get("data_path") or ""),
        database_path=str((profile.get("storage") or {}).get("database_path") or ""),
        generated_at=timestamp,
    )
    permission = build_windows_permission_summary(is_admin=is_admin, generated_at=timestamp)
    process_socket = build_windows_process_socket_visibility_summary(
        process_service_attribution=process_service_attribution,
        generated_at=timestamp,
    )
    service_preview = build_windows_service_mode_preview(profile=profile, service_mode=service_mode, generated_at=timestamp)
    platform_compatibility = build_runtime_compatibility_report(
        platform_info=platform_payload,
        is_admin=is_admin,
        runtime_profile=profile,
        runtime_health=runtime_health,
        service_mode=service_preview,
        generated_at=timestamp,
    )
    summary = summarize_windows_runtime_compatibility(
        platform_record=platform_record,
        path_summary=path_summary,
        permission=permission,
        process_socket=process_socket,
        service_preview=service_preview,
        generated_at=timestamp,
    )
    dashboard = build_windows_runtime_dashboard_record(
        summary=summary,
        platform_record=platform_record,
        path_summary=path_summary,
        process_socket=process_socket,
        service_preview=service_preview,
        generated_at=timestamp,
    )
    api = build_windows_runtime_api_response(
        summary=summary,
        platform_record=platform_record,
        profile=profile,
        path_summary=path_summary,
        permission=permission,
        process_socket=process_socket,
        service_preview=service_preview,
        platform_compatibility=platform_compatibility,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    return {
        "record_type": "windows_runtime_compatibility_report",
        "record_version": 1,
        "report_id": "windows-runtime-" + _digest({"generated_at": timestamp, "platform": platform_record, "summary": summary})[:16],
        "generated_at": timestamp,
        "platform": platform_record,
        "runtime_profile": summarize_runtime_profile(profile),
        "windows_profile_defaults": profile,
        "paths": path_summary,
        "permissions": permission,
        "process_socket_visibility": process_socket,
        "service_mode_preview": service_preview,
        "platform_compatibility": platform_compatibility,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def build_windows_runtime_profile_defaults(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    base = default_runtime_profile(generated_at=timestamp)
    profile = merge_runtime_profiles(
        base,
        {
            "profile_id": "runtime-windows-preview",
            "name": "Windows Runtime Preview",
            "description": "Dry-run Windows compatibility profile with local placeholders.",
            "profile_type": "operator",
            "runtime_mode": "dry-run",
            "scheduler": {
                "enabled": False,
                "poll_interval_seconds": 10,
                "jobs": {
                    "health_check": {"enabled": True, "interval_seconds": 120},
                    "snapshot_refresh": {"enabled": False, "interval_seconds": 600},
                    "event_flush": {"enabled": False, "interval_seconds": 300},
                    "policy_review_refresh": {"enabled": False, "interval_seconds": 600},
                },
            },
            "storage": {
                "enabled": True,
                "backend": "sqlite",
                "database_path": "<windows-data-dir>\\portmap.db",
                "data_path": "<windows-data-dir>",
                "write_requires_explicit_flag": True,
            },
            "api": {
                "enabled": False,
                "bind_host": "127.0.0.1",
                "port": 8765,
                "read_only": True,
            },
            "dashboard": {
                "enabled": False,
                "provider": "local",
                "static_output_enabled": False,
            },
            "export": {
                "enabled": True,
                "create_archive": False,
                "output_path": "<windows-export-dir>\\bundle.json",
                "redaction_required": True,
            },
            "metadata": {
                "platform_family": "windows",
                "service_mode": "preview-only",
                "firewall_mode": "preview-only",
                "packet_capture": "readiness-only",
            },
            "created_at": timestamp,
            "updated_at": timestamp,
        },
    )
    return runtime_profile_to_dict(profile)


def build_windows_permission_summary(*, is_admin: bool | None = None, generated_at: str | None = None) -> dict[str, Any]:
    summary = build_permission_summary(system="Windows", is_admin=is_admin, generated_at=generated_at)
    return {
        **summary,
        "record_type": "windows_permission_summary",
        "windows_elevated": bool(summary.get("elevated")),
        "admin_required_for_preview": False,
        "admin_required_for_future_capture_or_service": True,
        "elevation_requested": False,
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def build_windows_process_socket_visibility_summary(
    *,
    process_service_attribution: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not process_service_attribution:
        status = "degraded"
        warnings = ["process_socket_visibility_fixture_not_provided", "permission_denied_safe_fallback_available"]
        metrics = {"attribution_count": 0, "socket_count": 0}
        source_refs: list[str] = []
    else:
        summary = process_service_attribution.get("summary") if isinstance(process_service_attribution.get("summary"), dict) else {}
        dashboard = process_service_attribution.get("dashboard_status") if isinstance(process_service_attribution.get("dashboard_status"), dict) else {}
        status = str(process_service_attribution.get("status") or dashboard.get("status") or "supported")
        if status in {"ok", "supported", "ready"}:
            status = "supported"
        elif status in {"permission_denied", "unsupported", "degraded"}:
            status = "degraded"
        else:
            status = "unknown"
        warnings = sorted(set(str(item) for item in summary.get("warnings") or [] if str(item)))
        metrics = {
            "attribution_count": int(summary.get("attribution_count") or summary.get("socket_count") or 0),
            "socket_count": int(summary.get("socket_count") or 0),
        }
        source_refs = [str(process_service_attribution.get("report_id") or process_service_attribution.get("inventory_id") or "")]
    return {
        "record_type": "windows_process_socket_visibility",
        "record_version": 1,
        "generated_at": timestamp,
        "status": status,
        "metrics": metrics,
        "source_refs": [item for item in source_refs if item],
        "fallback_behavior": {
            "permission_denied_safe": True,
            "unsupported_platform_safe": True,
            "process_metadata_minimized": True,
            "command_line_args_exposed": False,
        },
        "warnings": warnings,
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def build_windows_service_mode_preview(
    *,
    profile: RuntimeProfile | dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    profile_payload = runtime_profile_to_dict(profile) if profile is not None else build_windows_runtime_profile_defaults(generated_at=timestamp)
    service_status = _nested_status(service_mode)
    status = "supported" if service_status in {"ready", "ok", "supported", "compatible"} else "degraded"
    warnings = ["windows_service_preview_only", "manual_operator_install_required"]
    if service_status == "unknown":
        warnings.append("service_mode_record_not_provided")
    return {
        "record_type": "windows_service_mode_preview",
        "record_version": 1,
        "generated_at": timestamp,
        "status": status,
        "profile_id": str(profile_payload.get("profile_id") or ""),
        "preview_commands": [
            {
                "command_id": "windows-service-preview",
                "description": "Placeholder command text for manual operator review only.",
                "command": "<windows-service-command-preview>",
                "preview_only": True,
            }
        ],
        "service_mode_status": service_status,
        "warnings": warnings,
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def summarize_windows_runtime_compatibility(
    *,
    platform_record: dict[str, Any],
    path_summary: dict[str, Any],
    permission: dict[str, Any],
    process_socket: dict[str, Any],
    service_preview: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    component_statuses = {
        "platform": "supported" if platform_record.get("platform_family") == "windows" else "unavailable",
        "paths": str((path_summary.get("summary") or {}).get("status") or "unknown"),
        "permissions": str(permission.get("status") or "unknown"),
        "process_socket_visibility": str(process_socket.get("status") or "unknown"),
        "service_mode_preview": str(service_preview.get("status") or "unknown"),
    }
    if component_statuses["platform"] == "unavailable":
        status = "unavailable"
    elif any(value == "degraded" for value in component_statuses.values()):
        status = "degraded"
    elif any(value == "unknown" for value in component_statuses.values()):
        status = "unknown"
    else:
        status = "supported"
    warnings = sorted(
        set(
            list(platform_record.get("warnings") or [])
            + list((path_summary.get("summary") or {}).get("warnings") or [])
            + list(permission.get("warnings") or [])
            + list(process_socket.get("warnings") or [])
            + list(service_preview.get("warnings") or [])
        )
    )
    return {
        "record_type": "windows_runtime_compatibility_summary",
        "record_version": 1,
        "generated_at": generated_at or _now(),
        "status": status,
        "component_statuses": component_statuses,
        "supported_count": sum(1 for value in component_statuses.values() if value == "supported"),
        "degraded_count": sum(1 for value in component_statuses.values() if value == "degraded"),
        "unavailable_count": sum(1 for value in component_statuses.values() if value == "unavailable"),
        "unknown_count": sum(1 for value in component_statuses.values() if value == "unknown"),
        "warnings": warnings,
        "operator_summary": _operator_summary(status),
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def build_windows_runtime_dashboard_record(
    *,
    summary: dict[str, Any],
    platform_record: dict[str, Any],
    path_summary: dict[str, Any],
    process_socket: dict[str, Any],
    service_preview: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [
        {"component": "platform", "status": "supported" if platform_record.get("platform_family") == "windows" else "unavailable"},
        {"component": "paths", "status": (path_summary.get("summary") or {}).get("status")},
        {"component": "process_socket_visibility", "status": process_socket.get("status")},
        {"component": "service_mode_preview", "status": service_preview.get("status")},
    ]
    return {
        "record_type": "windows_runtime_dashboard",
        "panel": "windows_runtime_compatibility",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unknown_count": int(summary.get("unknown_count") or 0),
        },
        "rows": rows,
        "recommended_review": str(summary.get("status") or "") != "supported",
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def build_windows_runtime_api_response(
    *,
    summary: dict[str, Any],
    platform_record: dict[str, Any],
    profile: dict[str, Any],
    path_summary: dict[str, Any],
    permission: dict[str, Any],
    process_socket: dict[str, Any],
    service_preview: dict[str, Any],
    platform_compatibility: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "windows_runtime_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "platform": dict(platform_record),
        "runtime_profile": dict(profile),
        "paths": dict(path_summary),
        "permissions": dict(permission),
        "process_socket_visibility": dict(process_socket),
        "service_mode_preview": dict(service_preview),
        "platform_compatibility": dict(platform_compatibility),
        "dashboard": dict(dashboard),
        **WINDOWS_RUNTIME_SAFETY_FLAGS,
    }


def deterministic_windows_runtime_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _nested_status(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict):
        return "unknown"
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    dashboard = record.get("dashboard_status") if isinstance(record.get("dashboard_status"), dict) else {}
    return str(record.get("status") or summary.get("status") or dashboard.get("status") or "unknown")


def _operator_summary(status: str) -> str:
    if status == "supported":
        return "Windows runtime compatibility records are supported for dry-run use."
    if status == "degraded":
        return "Windows runtime compatibility is available with operator review for degraded capabilities."
    if status == "unavailable":
        return "Windows runtime compatibility is unavailable for the provided platform record."
    return "Windows runtime compatibility is unknown and requires operator review."


def _digest(payload: Any) -> str:
    return sha256(deterministic_windows_runtime_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "WINDOWS_RUNTIME_SAFETY_FLAGS",
    "build_windows_permission_summary",
    "build_windows_process_socket_visibility_summary",
    "build_windows_runtime_api_response",
    "build_windows_runtime_compatibility_report",
    "build_windows_runtime_dashboard_record",
    "build_windows_runtime_profile_defaults",
    "build_windows_service_mode_preview",
    "deterministic_windows_runtime_json",
    "summarize_windows_runtime_compatibility",
]
