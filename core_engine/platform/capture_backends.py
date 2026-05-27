from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.platform.capabilities import CAPABILITY_STATUSES, PLATFORM_CAPABILITY_SAFETY_FLAGS


CAPTURE_BACKEND_RECORD_VERSION = 1

CAPTURE_BACKEND_SAFETY_FLAGS = {
    **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    "capture_readiness_only": True,
    "capture_loop_started": False,
    "promiscuous_mode_enabled": False,
    "interface_mode_changed": False,
    "provider_installed": False,
    "provider_install_attempted": False,
    "admin_elevation_requested": False,
    "raw_payload_stored": False,
    "payload_storage_allowed": False,
}


DEFAULT_BACKENDS_BY_PLATFORM = {
    "macos": ("bpf", "libpcap"),
    "linux": ("libpcap", "af_packet", "scapy"),
    "raspberry-pi-linux-arm": ("libpcap", "af_packet", "scapy"),
    "windows": ("npcap", "winpcap", "scapy"),
}


def build_capture_backend_summary(
    *,
    platform_record: dict[str, Any] | None = None,
    backend_statuses: dict[str, str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build platform capture backend readiness rows without probing or installing providers."""
    timestamp = generated_at or _now()
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    backends = [
        build_capture_backend_record(
            backend_name=name,
            platform_family=platform_family,
            status=(backend_statuses or {}).get(name),
            generated_at=timestamp,
        )
        for name in DEFAULT_BACKENDS_BY_PLATFORM.get(platform_family, ("unknown-capture-backend",))
    ]
    summary = summarize_capture_backends(backends, generated_at=timestamp)
    dashboard = build_capture_backend_dashboard_record(summary=summary, backends=backends, generated_at=timestamp)
    api = build_capture_backend_api_response(summary=summary, backends=backends, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "capture_backend_summary",
        "record_version": CAPTURE_BACKEND_RECORD_VERSION,
        "backend_summary_id": "capture-backends-" + _digest({"generated_at": timestamp, "platform_family": platform_family, "backends": backends})[:16],
        "generated_at": timestamp,
        "platform_family": platform_family,
        "backends": sorted(backends, key=lambda item: str(item.get("backend_name") or "")),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **CAPTURE_BACKEND_SAFETY_FLAGS,
    }


def build_capture_backend_record(
    *,
    backend_name: str,
    platform_family: str,
    status: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    normalized_name = str(backend_name or "unknown-capture-backend")
    default_status, warnings = _default_backend_status(normalized_name, platform_family)
    normalized_status = _status(status or default_status)
    details = _backend_details(normalized_name, platform_family)
    record = {
        "record_type": "capture_backend_readiness",
        "record_version": CAPTURE_BACKEND_RECORD_VERSION,
        "backend_name": normalized_name,
        "platform_family": str(platform_family or "unknown"),
        "status": normalized_status,
        "provider_label": details["provider_label"],
        "requires_manual_permission": details["requires_manual_permission"],
        "requires_admin_or_root_for_future_capture": details["requires_admin_or_root_for_future_capture"],
        "install_assumed": False,
        "install_attempted": False,
        "capture_enabled": False,
        "warnings": sorted(set(warnings + _status_warnings(normalized_status))),
        "generated_at": timestamp,
        **CAPTURE_BACKEND_SAFETY_FLAGS,
    }
    record["backend_id"] = "capture-backend-" + _digest(record)[:16]
    return record


def summarize_capture_backends(backends: list[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in backends or [] if isinstance(row, dict)]
    counts = {status: sum(1 for row in rows if row.get("status") == status) for status in sorted(CAPABILITY_STATUSES)}
    if counts["supported"]:
        status = "supported" if not counts["degraded"] and not counts["unavailable"] and not counts["unknown"] else "degraded"
    elif counts["degraded"]:
        status = "degraded"
    elif counts["unknown"]:
        status = "unknown"
    else:
        status = "unavailable"
    warnings = sorted({warning for row in rows for warning in row.get("warnings") or []})
    return {
        "record_type": "capture_backend_rollup",
        "record_version": CAPTURE_BACKEND_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "backend_count": len(rows),
        "supported_count": counts["supported"],
        "degraded_count": counts["degraded"],
        "unavailable_count": counts["unavailable"],
        "unknown_count": counts["unknown"],
        "backends_by_status": counts,
        "warnings": warnings,
        **CAPTURE_BACKEND_SAFETY_FLAGS,
    }


def build_capture_backend_dashboard_record(
    *,
    summary: dict[str, Any],
    backends: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "capture_backend_dashboard",
        "panel": "capture_backends",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "backend_count": int(summary.get("backend_count") or 0),
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unknown_count": int(summary.get("unknown_count") or 0),
        },
        "rows": [
            {
                "backend_name": row.get("backend_name"),
                "provider_label": row.get("provider_label"),
                "status": row.get("status"),
                "warning_count": len(row.get("warnings") or []),
            }
            for row in sorted(backends, key=lambda item: str(item.get("backend_name") or ""))
        ],
        "recommended_review": str(summary.get("status") or "") != "supported",
        **CAPTURE_BACKEND_SAFETY_FLAGS,
    }


def build_capture_backend_api_response(
    *,
    summary: dict[str, Any],
    backends: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "capture_backend_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "backends": sorted([dict(row) for row in backends], key=lambda item: str(item.get("backend_name") or "")),
        "dashboard": dict(dashboard),
        **CAPTURE_BACKEND_SAFETY_FLAGS,
    }


def deterministic_capture_backend_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _default_backend_status(backend_name: str, platform_family: str) -> tuple[str, list[str]]:
    if platform_family == "macos":
        return "degraded", ["manual_bpf_or_libpcap_permission_review_required"]
    if platform_family == "linux":
        return "degraded", ["manual_linux_capture_permission_review_required"]
    if platform_family == "raspberry-pi-linux-arm":
        return "degraded", ["manual_linux_capture_permission_review_required", "edge_device_resource_review_required"]
    if platform_family == "windows":
        if backend_name == "winpcap":
            return "unavailable", ["winpcap_legacy_backend_not_assumed"]
        if backend_name == "npcap":
            return "unknown", ["npcap_installation_not_assumed"]
        return "degraded", ["windows_capture_backend_requires_operator_review"]
    return "unknown", ["platform_family_unknown"]


def _backend_details(backend_name: str, platform_family: str) -> dict[str, Any]:
    labels = {
        "af_packet": "Linux AF_PACKET",
        "bpf": "macOS BPF",
        "libpcap": "libpcap",
        "npcap": "Npcap",
        "scapy": "Scapy",
        "winpcap": "WinPcap",
    }
    return {
        "provider_label": labels.get(backend_name, backend_name),
        "requires_manual_permission": platform_family in {"macos", "linux", "raspberry-pi-linux-arm", "windows"},
        "requires_admin_or_root_for_future_capture": platform_family in {"macos", "linux", "raspberry-pi-linux-arm", "windows"},
    }


def _status(value: str) -> str:
    return value if value in CAPABILITY_STATUSES else "unknown"


def _status_warnings(status: str) -> list[str]:
    if status == "supported":
        return ["capture_still_disabled"]
    if status == "degraded":
        return ["backend_requires_operator_review"]
    if status == "unavailable":
        return ["backend_unavailable"]
    return ["backend_state_unknown"]


def _digest(payload: Any) -> str:
    return sha256(deterministic_capture_backend_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "CAPTURE_BACKEND_RECORD_VERSION",
    "CAPTURE_BACKEND_SAFETY_FLAGS",
    "DEFAULT_BACKENDS_BY_PLATFORM",
    "build_capture_backend_api_response",
    "build_capture_backend_dashboard_record",
    "build_capture_backend_record",
    "build_capture_backend_summary",
    "deterministic_capture_backend_json",
    "summarize_capture_backends",
]
