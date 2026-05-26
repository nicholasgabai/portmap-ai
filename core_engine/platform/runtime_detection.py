from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine import platform_utils
from core_engine.platform.capabilities import (
    PLATFORM_CAPABILITY_SAFETY_FLAGS,
    build_platform_capability_summary,
)


PLATFORM_FAMILIES = frozenset({"macos", "linux", "raspberry-pi-linux-arm", "windows", "unknown"})

PLATFORM_RUNTIME_SAFETY_FLAGS = {
    **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    "host_identifier_included": False,
    "username_included": False,
    "ip_address_included": False,
    "mac_address_included": False,
    "elevation_requested": False,
}


def build_runtime_compatibility_report(
    *,
    platform_info: platform_utils.PlatformInfo | dict[str, Any] | None = None,
    os_release: str | None = None,
    is_admin: bool | None = None,
    runtime_profile: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    telemetry_readiness: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a dashboard/API-ready platform compatibility report without changing the host."""
    timestamp = generated_at or _now()
    platform_record = build_platform_runtime_record(
        platform_info=platform_info,
        os_release=os_release,
        is_admin=is_admin,
        generated_at=timestamp,
    )
    capabilities = build_platform_capability_summary(
        platform_record=platform_record,
        runtime_profile=runtime_profile,
        runtime_health=runtime_health,
        service_mode=service_mode,
        gateway_validation=gateway_validation,
        telemetry_readiness=telemetry_readiness,
        generated_at=timestamp,
    )
    summary = summarize_runtime_detection(platform_record=platform_record, capabilities=capabilities, generated_at=timestamp)
    dashboard = build_runtime_detection_dashboard_record(platform_record=platform_record, capabilities=capabilities, summary=summary, generated_at=timestamp)
    api = build_runtime_detection_api_response(platform_record=platform_record, capabilities=capabilities, summary=summary, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "runtime_compatibility_report",
        "record_version": 1,
        "report_id": "runtime-compatibility-" + _digest(
            {
                "generated_at": timestamp,
                "platform_family": platform_record["platform_family"],
                "architecture": platform_record["architecture"]["machine"],
                "capability_summary": capabilities["summary"],
            }
        )[:16],
        "generated_at": timestamp,
        "platform": platform_record,
        "capabilities": capabilities,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def build_platform_runtime_record(
    *,
    platform_info: platform_utils.PlatformInfo | dict[str, Any] | None = None,
    system: str | None = None,
    release: str | None = None,
    machine: str | None = None,
    python_version: str | None = None,
    os_release: str | None = None,
    is_admin: bool | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    info = _coerce_platform_info(platform_info, system=system, release=release, machine=machine, python_version=python_version)
    family = detect_platform_family(system=info.system, machine=info.machine, os_release=os_release)
    admin_summary = build_permission_summary(system=info.system, is_admin=is_admin, generated_at=timestamp)
    architecture = build_architecture_summary(machine=info.machine, platform_family=family)
    python_summary = build_python_runtime_summary(info.python_version)
    status = _platform_status(family)
    warnings = []
    if family == "unknown":
        warnings.append("platform_family_unknown")
    if not admin_summary["elevated"]:
        warnings.append("runtime_not_elevated")
    return {
        "record_type": "platform_runtime",
        "record_version": 1,
        "platform_family": family,
        "status": status,
        "generated_at": timestamp,
        "os": {
            "system": str(info.system or "Unknown"),
            "release": str(info.release or "unknown"),
            "family": family,
        },
        "architecture": architecture,
        "python": python_summary,
        "permissions": admin_summary,
        "environment_hints": build_environment_hints(os_release=os_release),
        "warnings": sorted(set(warnings)),
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def detect_platform_family(
    *,
    system: str | None = None,
    machine: str | None = None,
    os_release: str | None = None,
) -> str:
    normalized = str(system or platform.system() or "").strip().lower()
    arch = str(machine or platform.machine() or "").strip().lower()
    release_text = str(os_release or "").lower()
    if normalized == "darwin":
        return "macos"
    if normalized == "windows":
        return "windows"
    if normalized == "linux":
        if _is_arm_arch(arch) or "raspberry" in release_text or "raspbian" in release_text:
            return "raspberry-pi-linux-arm"
        return "linux"
    return "unknown"


def detect_admin_permission(system: str | None = None) -> dict[str, Any]:
    """Detect current elevated/admin state without requesting elevation."""
    normalized = str(system or platform.system() or "").strip().lower()
    elevated = False
    method = "unavailable"
    error = ""
    try:
        if normalized in {"darwin", "linux"} and hasattr(os, "geteuid"):
            elevated = os.geteuid() == 0
            method = "geteuid"
        elif normalized == "windows":
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            method = "windows-shell32"
        else:
            method = "unsupported-platform"
    except Exception as exc:  # pragma: no cover - platform-specific fallback
        elevated = False
        error = str(exc)
        method = "permission-check-failed"
    return {
        "elevated": bool(elevated),
        "method": method,
        "error": error,
        "elevation_requested": False,
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def build_permission_summary(
    *,
    system: str | None = None,
    is_admin: bool | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    detected = detect_admin_permission(system) if is_admin is None else {
        "elevated": bool(is_admin),
        "method": "fixture",
        "error": "",
        "elevation_requested": False,
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }
    status = "supported" if detected["elevated"] else "degraded"
    return {
        "record_type": "platform_permission_summary",
        "record_version": 1,
        "generated_at": generated_at or _now(),
        "status": status,
        "elevated": bool(detected["elevated"]),
        "admin_or_root": bool(detected["elevated"]),
        "detection_method": str(detected["method"]),
        "error": str(detected.get("error") or ""),
        "operator_summary": "Runtime is elevated." if detected["elevated"] else "Runtime is not elevated; privileged capabilities require manual operator review.",
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def build_architecture_summary(machine: str, *, platform_family: str) -> dict[str, Any]:
    normalized = str(machine or "unknown").lower()
    return {
        "machine": str(machine or "unknown"),
        "normalized": normalized,
        "is_arm": _is_arm_arch(normalized),
        "is_64_bit": "64" in normalized or sys.maxsize > 2**32,
        "platform_family": platform_family,
    }


def build_python_runtime_summary(version: str | None = None) -> dict[str, Any]:
    version_text = str(version or platform.python_version() or "unknown")
    parts = _version_tuple(version_text)
    return {
        "version": version_text,
        "major": parts[0],
        "minor": parts[1],
        "micro": parts[2],
        "supported": parts >= (3, 11, 0),
        "requires_python": ">=3.11",
    }


def build_environment_hints(*, os_release: str | None = None) -> dict[str, Any]:
    text = str(os_release or "")
    lowered = text.lower()
    return {
        "container_hint": any(marker in lowered for marker in ("container", "docker", "podman")),
        "virtualized_hint": any(marker in lowered for marker in ("virtual", "vmware", "hyper-v", "qemu", "parallels")),
        "source": "sanitized-os-release" if text else "not-provided",
    }


def summarize_runtime_detection(
    *,
    platform_record: dict[str, Any],
    capabilities: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    capability_summary = dict(capabilities.get("summary") or {})
    platform_status = str(platform_record.get("status") or "unknown")
    capability_status = str(capability_summary.get("status") or "unknown")
    if platform_status == "unavailable":
        status = "unavailable"
    elif "degraded" in {platform_status, capability_status}:
        status = "degraded"
    elif "unknown" in {platform_status, capability_status}:
        status = "unknown"
    else:
        status = "supported"
    warnings = sorted(set(list(platform_record.get("warnings") or []) + list(capability_summary.get("warnings") or [])))
    return {
        "record_type": "runtime_detection_summary",
        "record_version": 1,
        "generated_at": generated_at or _now(),
        "status": status,
        "platform_family": str(platform_record.get("platform_family") or "unknown"),
        "platform_status": platform_status,
        "capability_status": capability_status,
        "capability_count": int(capability_summary.get("capability_count") or 0),
        "supported_count": int(capability_summary.get("supported_count") or 0),
        "degraded_count": int(capability_summary.get("degraded_count") or 0),
        "unavailable_count": int(capability_summary.get("unavailable_count") or 0),
        "unknown_count": int(capability_summary.get("unknown_count") or 0),
        "elevated": bool((platform_record.get("permissions") or {}).get("elevated")),
        "warnings": warnings,
        "operator_summary": _operator_summary(status, str(platform_record.get("platform_family") or "unknown")),
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def build_runtime_detection_dashboard_record(
    *,
    platform_record: dict[str, Any],
    capabilities: dict[str, Any],
    summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "runtime_detection_dashboard",
        "panel": "cross_platform_runtime_detection",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "capability_count": int(summary.get("capability_count") or 0),
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unknown_count": int(summary.get("unknown_count") or 0),
        },
        "platform": {
            "family": str(platform_record.get("platform_family") or "unknown"),
            "system": str((platform_record.get("os") or {}).get("system") or "Unknown"),
            "architecture": str((platform_record.get("architecture") or {}).get("machine") or "unknown"),
            "python_version": str((platform_record.get("python") or {}).get("version") or "unknown"),
            "elevated": bool((platform_record.get("permissions") or {}).get("elevated")),
        },
        "capability_rows": [
            {
                "capability": row.get("capability"),
                "status": row.get("status"),
                "summary": row.get("summary"),
            }
            for row in capabilities.get("capabilities") or []
            if isinstance(row, dict)
        ],
        "recommended_review": str(summary.get("status") or "") != "supported",
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def build_runtime_detection_api_response(
    *,
    platform_record: dict[str, Any],
    capabilities: dict[str, Any],
    summary: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "runtime_detection_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "platform": dict(platform_record),
        "capabilities": dict(capabilities),
        "dashboard": dict(dashboard),
        **PLATFORM_RUNTIME_SAFETY_FLAGS,
    }


def deterministic_runtime_detection_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _coerce_platform_info(
    platform_info: platform_utils.PlatformInfo | dict[str, Any] | None,
    *,
    system: str | None = None,
    release: str | None = None,
    machine: str | None = None,
    python_version: str | None = None,
) -> platform_utils.PlatformInfo:
    if isinstance(platform_info, platform_utils.PlatformInfo):
        return platform_info
    if isinstance(platform_info, dict):
        return platform_utils.PlatformInfo(
            system=str(platform_info.get("system") or system or "Unknown"),
            release=str(platform_info.get("release") or release or "unknown"),
            machine=str(platform_info.get("machine") or machine or "unknown"),
            python_version=str(platform_info.get("python_version") or python_version or platform.python_version()),
        )
    if any(value is not None for value in (system, release, machine, python_version)):
        return platform_utils.PlatformInfo(
            system=str(system or "Unknown"),
            release=str(release or "unknown"),
            machine=str(machine or "unknown"),
            python_version=str(python_version or platform.python_version()),
        )
    return platform_utils.get_platform_info()


def _platform_status(family: str) -> str:
    if family in {"macos", "linux", "raspberry-pi-linux-arm", "windows"}:
        return "supported"
    return "unavailable"


def _is_arm_arch(machine: str) -> bool:
    return str(machine or "").lower().startswith(("arm", "aarch")) or str(machine or "").lower() in {"arm64", "aarch64"}


def _version_tuple(version: str) -> tuple[int, int, int]:
    parts: list[int] = []
    for item in str(version or "0.0.0").split(".")[:3]:
        try:
            parts.append(int("".join(ch for ch in item if ch.isdigit()) or 0))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])  # type: ignore[return-value]


def _operator_summary(status: str, platform_family: str) -> str:
    if status == "supported":
        return f"{platform_family} runtime compatibility records are supported for dry-run use."
    if status == "degraded":
        return f"{platform_family} runtime compatibility requires operator review before privileged workflows."
    if status == "unavailable":
        return "Runtime compatibility is unavailable for the detected platform family."
    return "Runtime compatibility is unknown and should be reviewed by the operator."


def _digest(payload: Any) -> str:
    return sha256(deterministic_runtime_detection_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "PLATFORM_FAMILIES",
    "PLATFORM_RUNTIME_SAFETY_FLAGS",
    "build_architecture_summary",
    "build_environment_hints",
    "build_permission_summary",
    "build_platform_runtime_record",
    "build_python_runtime_summary",
    "build_runtime_compatibility_report",
    "build_runtime_detection_api_response",
    "build_runtime_detection_dashboard_record",
    "detect_admin_permission",
    "detect_platform_family",
    "deterministic_runtime_detection_json",
    "summarize_runtime_detection",
]
