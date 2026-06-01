from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.platform.runtime_detection import build_platform_runtime_record


SERVICE_PROVIDER_RECORD_VERSION = 1

SERVICE_PROVIDER_STATES = frozenset({"supported", "degraded", "unavailable", "unknown"})
SERVICE_PROVIDERS = frozenset(
    {
        "linux-systemd",
        "macos-launchd",
        "windows-service-control-manager",
        "foreground-process",
        "raspberry-pi-systemd-edge",
    }
)

SERVICE_PROVIDER_SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "administrator_controlled": True,
    "advisory": True,
    "advisory_first": True,
    "dry_run": True,
    "dry_run_only": True,
    "preview_only": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "credentials_stored": False,
    "automatic_changes": False,
    "destructive_action": False,
    "service_installed": False,
    "service_registered": False,
    "service_started": False,
    "service_stopped": False,
    "service_restarted": False,
    "service_uninstalled": False,
    "launch_agent_created": False,
    "systemd_unit_created": False,
    "windows_service_registered": False,
    "registry_changed": False,
    "system_directory_written": False,
    "firewall_rules_changed": False,
    "privilege_escalation_attempted": False,
    "admin_elevation_requested": False,
    "host_identifier_included": False,
    "username_included": False,
    "ip_address_included": False,
    "mac_address_included": False,
    "dashboard_safe": True,
    "api_compatible": True,
    "export_safe": True,
}


def build_service_provider_readiness(
    *,
    service_name: str = "portmap-runtime",
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    provider: str | None = None,
    install_path: str = "<portmap-install-dir>",
    is_admin: bool | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build provider readiness without installing or registering services."""
    timestamp = generated_at or _now()
    platform_payload = platform_record or build_platform_runtime_record(
        platform_info=platform_info,
        is_admin=is_admin,
        generated_at=timestamp,
    )
    platform_family = str(platform_payload.get("platform_family") or "unknown")
    provider_name = _provider(provider, platform_family)
    template = _provider_templates()[provider_name]
    permission = build_service_permission_summary(
        provider=provider_name,
        platform_record=platform_payload,
        generated_at=timestamp,
    )
    path_safety = build_install_path_safety_summary(
        provider=provider_name,
        install_path=install_path,
        generated_at=timestamp,
    )
    limitations = build_platform_limitations_summary(
        provider=provider_name,
        platform_family=platform_family,
        generated_at=timestamp,
    )
    state = _provider_state(
        provider=provider_name,
        platform_family=platform_family,
        permission_state=str(permission.get("state") or "unknown"),
        path_state=str(path_safety.get("state") or "unknown"),
    )
    warnings = sorted(
        set(template["warnings"])
        | set(permission.get("warnings") or [])
        | set(path_safety.get("warnings") or [])
        | set(limitations.get("warnings") or [])
    )
    return {
        "record_type": "service_provider_readiness",
        "record_version": SERVICE_PROVIDER_RECORD_VERSION,
        "provider_readiness_id": "service-provider-" + _digest(
            {
                "service_name": service_name,
                "provider": provider_name,
                "platform_family": platform_family,
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "service_name": _sanitize_service_name(service_name),
        "platform": platform_family,
        "provider": provider_name,
        "provider_display_name": template["display_name"],
        "state": state,
        "permission_summary": permission,
        "install_path_safety": path_safety,
        "platform_limitations": limitations,
        "supported_actions": sorted(template["supported_actions"]),
        "required_permissions": sorted(template["required_permissions"]),
        "warning_count": len(warnings),
        "warnings": warnings,
        "operator_summary": _provider_operator_summary(provider_name, state),
        **SERVICE_PROVIDER_SAFETY_FLAGS,
    }


def build_service_permission_summary(
    *,
    provider: str,
    platform_record: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    provider_name = _provider(provider, str(platform_record.get("platform_family") or "unknown"))
    permissions = platform_record.get("permissions") if isinstance(platform_record.get("permissions"), dict) else {}
    elevated = bool(permissions.get("elevated", False))
    requires_admin = provider_name == "windows-service-control-manager"
    manual_review = provider_name != "foreground-process"
    state = "degraded" if manual_review and not elevated and requires_admin else "supported"
    warnings: list[str] = []
    if manual_review:
        warnings.append("manual_operator_permission_review_required")
    if requires_admin:
        warnings.append("future_windows_service_registration_requires_admin")
    return {
        "record_type": "service_permission_summary",
        "record_version": SERVICE_PROVIDER_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "provider": provider_name,
        "state": state,
        "currently_elevated": elevated,
        "manual_permission_review_required": manual_review,
        "admin_or_root_required_for_future_operator_action": requires_admin,
        "elevation_requested": False,
        "warnings": sorted(set(warnings)),
        **SERVICE_PROVIDER_SAFETY_FLAGS,
    }


def build_install_path_safety_summary(
    *,
    provider: str,
    install_path: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    path = str(install_path or "")
    warnings: list[str] = ["install_path_preview_only"]
    state = "supported"
    if not path:
        state = "degraded"
        warnings.append("install_path_missing")
    if _contains_private_path(path):
        state = "unavailable"
        warnings.append("private_path_rejected")
    if _looks_system_path(path):
        state = "degraded"
        warnings.append("system_path_requires_manual_review")
    return {
        "record_type": "service_install_path_safety",
        "record_version": SERVICE_PROVIDER_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "provider": _provider(provider, "unknown"),
        "state": state,
        "install_path": path or "<operator-provided-install-path>",
        "path_is_placeholder": "<" in path and ">" in path,
        "system_directory_write_planned": False,
        "path_created": False,
        "warnings": sorted(set(warnings)),
        **SERVICE_PROVIDER_SAFETY_FLAGS,
    }


def build_platform_limitations_summary(
    *,
    provider: str,
    platform_family: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    provider_name = _provider(provider, platform_family)
    supported = _provider_supported_on_platform(provider_name, platform_family)
    warnings = []
    if not supported:
        warnings.append("provider_platform_mismatch")
    if provider_name == "raspberry-pi-systemd-edge":
        warnings.append("edge_resource_review_required")
    if provider_name == "windows-service-control-manager":
        warnings.append("windows_service_preview_only")
    if provider_name == "macos-launchd":
        warnings.append("launch_agent_creation_disabled")
    if provider_name in {"linux-systemd", "raspberry-pi-systemd-edge"}:
        warnings.append("systemd_unit_creation_disabled")
    return {
        "record_type": "service_platform_limitations",
        "record_version": SERVICE_PROVIDER_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "platform": platform_family,
        "provider": provider_name,
        "state": "supported" if supported else "unavailable",
        "provider_supported_on_platform": supported,
        "limitations": sorted(set(warnings)),
        "warnings": sorted(set(warnings)),
        **SERVICE_PROVIDER_SAFETY_FLAGS,
    }


def build_service_provider_catalog(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    fixtures = [
        ("linux-systemd", {"system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64", "python_version": "3.11.5"}),
        ("macos-launchd", {"system": "Darwin", "release": "macos-release-placeholder", "machine": "arm64", "python_version": "3.11.5"}),
        ("windows-service-control-manager", {"system": "Windows", "release": "windows-release-placeholder", "machine": "AMD64", "python_version": "3.11.5"}),
        ("raspberry-pi-systemd-edge", {"system": "Linux", "release": "raspberry-pi-release-placeholder", "machine": "aarch64", "python_version": "3.11.5"}),
        ("foreground-process", {"system": "Unknown", "release": "unknown-release-placeholder", "machine": "unknown", "python_version": "3.11.5"}),
    ]
    providers = [
        build_service_provider_readiness(provider=provider, platform_info=platform_info, generated_at=timestamp)
        for provider, platform_info in fixtures
    ]
    states = [row["state"] for row in providers]
    return {
        "record_type": "service_provider_catalog",
        "record_version": SERVICE_PROVIDER_RECORD_VERSION,
        "catalog_id": "service-provider-catalog-" + _digest({"generated_at": timestamp, "providers": [row["provider"] for row in providers]})[:16],
        "generated_at": timestamp,
        "provider_count": len(providers),
        "providers": sorted(providers, key=lambda item: item["provider"]),
        "supported_count": states.count("supported"),
        "degraded_count": states.count("degraded"),
        "unavailable_count": states.count("unavailable"),
        "unknown_count": states.count("unknown"),
        **SERVICE_PROVIDER_SAFETY_FLAGS,
    }


def service_provider_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record or {})
    return {
        "record_type": str(payload.get("record_type") or "service_provider_readiness"),
        "record_version": int(payload.get("record_version") or SERVICE_PROVIDER_RECORD_VERSION),
        "generated_at": str(payload.get("generated_at") or _now()),
        "service_name": _sanitize_service_name(payload.get("service_name") or "portmap-runtime"),
        "platform": str(payload.get("platform") or "unknown"),
        "provider": _provider(payload.get("provider"), str(payload.get("platform") or "unknown")),
        "state": _state(payload.get("state")),
        "required_permissions": _string_list(payload.get("required_permissions") or []),
        "warnings": _string_list(payload.get("warnings") or []),
        "operator_summary": str(payload.get("operator_summary") or ""),
        **SERVICE_PROVIDER_SAFETY_FLAGS,
    }


def _provider(provider: Any, platform_family: str) -> str:
    normalized = str(provider or "").strip().lower().replace("_", "-")
    aliases = {
        "systemd": "linux-systemd",
        "launchd": "macos-launchd",
        "windows": "windows-service-control-manager",
        "scm": "windows-service-control-manager",
        "foreground": "foreground-process",
        "daemon": "foreground-process",
        "raspberry-pi-systemd": "raspberry-pi-systemd-edge",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in SERVICE_PROVIDERS:
        return normalized
    if platform_family == "linux":
        return "linux-systemd"
    if platform_family == "raspberry-pi-linux-arm":
        return "raspberry-pi-systemd-edge"
    if platform_family == "macos":
        return "macos-launchd"
    if platform_family == "windows":
        return "windows-service-control-manager"
    return "foreground-process"


def _provider_templates() -> dict[str, dict[str, Any]]:
    actions = ("install_preview", "start_preview", "stop_preview", "restart_preview", "uninstall_preview", "status_preview")
    return {
        "linux-systemd": {
            "display_name": "Linux systemd",
            "supported_actions": actions,
            "required_permissions": ["manual_user_service_review"],
            "warnings": ["systemd_preview_only", "manual_install_required"],
        },
        "raspberry-pi-systemd-edge": {
            "display_name": "Raspberry Pi systemd edge mode",
            "supported_actions": actions,
            "required_permissions": ["manual_user_service_review", "edge_resource_review"],
            "warnings": ["systemd_preview_only", "edge_resource_review_required"],
        },
        "macos-launchd": {
            "display_name": "macOS launchd",
            "supported_actions": actions,
            "required_permissions": ["manual_launch_agent_review"],
            "warnings": ["launchd_preview_only", "launch_agent_creation_disabled"],
        },
        "windows-service-control-manager": {
            "display_name": "Windows Service Control Manager",
            "supported_actions": actions,
            "required_permissions": ["manual_admin_review"],
            "warnings": ["windows_service_preview_only", "registry_changes_disabled"],
        },
        "foreground-process": {
            "display_name": "Generic foreground process",
            "supported_actions": ("start_preview", "stop_preview", "restart_preview", "status_preview"),
            "required_permissions": ["operator_shell_review"],
            "warnings": ["foreground_process_preview_only"],
        },
    }


def _provider_state(*, provider: str, platform_family: str, permission_state: str, path_state: str) -> str:
    if not _provider_supported_on_platform(provider, platform_family):
        return "unavailable"
    if path_state == "unavailable":
        return "unavailable"
    if permission_state in {"degraded", "unknown"} or path_state in {"degraded", "unknown"}:
        return "degraded"
    return "supported"


def _provider_supported_on_platform(provider: str, platform_family: str) -> bool:
    matrix = {
        "linux-systemd": {"linux"},
        "raspberry-pi-systemd-edge": {"raspberry-pi-linux-arm"},
        "macos-launchd": {"macos"},
        "windows-service-control-manager": {"windows"},
        "foreground-process": {"macos", "linux", "raspberry-pi-linux-arm", "windows", "unknown"},
    }
    return platform_family in matrix.get(provider, set())


def _provider_operator_summary(provider: str, state: str) -> str:
    if state == "supported":
        return f"{provider} is ready for dry-run lifecycle previews."
    if state == "degraded":
        return f"{provider} can produce previews but requires operator review."
    if state == "unavailable":
        return f"{provider} is not available for the supplied platform fixture."
    return f"{provider} readiness is unknown."


def _sanitize_service_name(value: Any) -> str:
    text = str(value or "portmap-runtime").strip().lower().replace("_", "-")
    allowed = []
    previous_dash = False
    for char in text:
        if char.isalnum() or char in {"-", "."}:
            allowed.append(char)
            previous_dash = char == "-"
        elif char.isspace() or char in {"/", ":", "!"}:
            if allowed and not previous_dash:
                allowed.append("-")
                previous_dash = True
    sanitized = "".join(allowed).strip(".-")
    return sanitized or "portmap-runtime"


def _contains_private_path(value: str) -> bool:
    lowered = value.lower()
    return "/users/" in lowered or "/home/" in lowered or "\\users\\" in lowered


def _looks_system_path(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("/etc/") or lowered.startswith("/usr/") or lowered.startswith("/library/") or lowered.startswith("c:\\windows")


def _state(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in SERVICE_PROVIDER_STATES else "unknown"


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
