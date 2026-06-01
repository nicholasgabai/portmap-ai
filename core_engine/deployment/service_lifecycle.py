from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.service_providers import (
    SERVICE_PROVIDER_SAFETY_FLAGS,
    build_service_provider_readiness,
)


SERVICE_LIFECYCLE_RECORD_VERSION = 1

SERVICE_LIFECYCLE_ACTIONS = frozenset(
    {
        "install_preview",
        "start_preview",
        "stop_preview",
        "restart_preview",
        "uninstall_preview",
        "status_preview",
    }
)

SERVICE_LIFECYCLE_SAFETY_FLAGS = {
    **SERVICE_PROVIDER_SAFETY_FLAGS,
    "lifecycle_preview_only": True,
    "commands_executed": False,
    "command_preview_sanitized": True,
}


def build_service_lifecycle_readiness(
    *,
    service_name: str = "portmap-runtime",
    action: str = "status_preview",
    provider_readiness: dict[str, Any] | None = None,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    provider: str | None = None,
    install_path: str = "<portmap-install-dir>",
    is_admin: bool | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a dry-run lifecycle preview record without controlling services."""
    timestamp = generated_at or _now()
    provider_record = provider_readiness or build_service_provider_readiness(
        service_name=service_name,
        platform_record=platform_record,
        platform_info=platform_info,
        provider=provider,
        install_path=install_path,
        is_admin=is_admin,
        generated_at=timestamp,
    )
    normalized_action = _action(action)
    readiness_state = _readiness_state(provider_record, normalized_action)
    command_preview = build_service_command_preview(
        service_name=service_name,
        provider=str(provider_record.get("provider") or "foreground-process"),
        action=normalized_action,
    )
    warnings = build_lifecycle_safety_warnings(
        provider_readiness=provider_record,
        action=normalized_action,
        readiness_state=readiness_state,
        generated_at=timestamp,
    )
    operator_steps = build_lifecycle_operator_steps(
        provider_readiness=provider_record,
        action=normalized_action,
        readiness_state=readiness_state,
        generated_at=timestamp,
    )
    advisory_notes = build_lifecycle_advisory_notes(
        provider_readiness=provider_record,
        action=normalized_action,
        readiness_state=readiness_state,
    )
    record = {
        "record_type": "service_lifecycle_readiness",
        "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
        "lifecycle_readiness_id": "service-lifecycle-" + _digest(
            {
                "service_name": service_name,
                "provider": provider_record.get("provider"),
                "action": normalized_action,
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "service_name": _sanitize_service_name(service_name),
        "platform": str(provider_record.get("platform") or "unknown"),
        "provider": str(provider_record.get("provider") or "foreground-process"),
        "action": normalized_action,
        "readiness_state": readiness_state,
        "required_permissions": sorted(provider_record.get("required_permissions") or []),
        "operator_steps": operator_steps,
        "safety_warnings": warnings,
        "dry_run_only": True,
        "destructive_action": False,
        "command_preview": command_preview,
        "advisory_notes": advisory_notes,
        "provider_readiness": provider_record,
        "dashboard_status": build_service_lifecycle_dashboard_record(
            service_name=service_name,
            provider_readiness=provider_record,
            action=normalized_action,
            readiness_state=readiness_state,
            generated_at=timestamp,
        ),
        "api_status": build_service_lifecycle_api_response(
            service_name=service_name,
            provider_readiness=provider_record,
            action=normalized_action,
            readiness_state=readiness_state,
            generated_at=timestamp,
        ),
        "export": build_service_lifecycle_export_dict(
            service_name=service_name,
            provider_readiness=provider_record,
            action=normalized_action,
            readiness_state=readiness_state,
            generated_at=timestamp,
        ),
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }
    return record


def build_service_lifecycle_preview_plan(
    *,
    service_name: str = "portmap-runtime",
    provider_readiness: dict[str, Any] | None = None,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    provider: str | None = None,
    install_path: str = "<portmap-install-dir>",
    actions: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    provider_record = provider_readiness or build_service_provider_readiness(
        service_name=service_name,
        platform_record=platform_record,
        platform_info=platform_info,
        provider=provider,
        install_path=install_path,
        generated_at=timestamp,
    )
    previews = [
        build_service_lifecycle_readiness(
            service_name=service_name,
            action=action,
            provider_readiness=provider_record,
            generated_at=timestamp,
        )
        for action in sorted({_action(item) for item in (actions or SERVICE_LIFECYCLE_ACTIONS)})
    ]
    states = [row["readiness_state"] for row in previews]
    plan_state = "supported"
    if "unavailable" in states:
        plan_state = "unavailable"
    elif "degraded" in states:
        plan_state = "degraded"
    return {
        "record_type": "service_lifecycle_preview_plan",
        "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
        "preview_plan_id": "service-lifecycle-plan-" + _digest(
            {
                "service_name": service_name,
                "provider": provider_record.get("provider"),
                "generated_at": timestamp,
                "actions": [row["action"] for row in previews],
            }
        )[:16],
        "generated_at": timestamp,
        "service_name": _sanitize_service_name(service_name),
        "platform": str(provider_record.get("platform") or "unknown"),
        "provider": str(provider_record.get("provider") or "foreground-process"),
        "readiness_state": plan_state,
        "preview_count": len(previews),
        "previews": previews,
        "supported_count": states.count("supported"),
        "degraded_count": states.count("degraded"),
        "unavailable_count": states.count("unavailable"),
        "unknown_count": states.count("unknown"),
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }


def build_service_command_preview(
    *,
    service_name: str,
    provider: str,
    action: str,
) -> dict[str, Any]:
    sanitized_service = _sanitize_service_name(service_name)
    provider_name = str(provider or "foreground-process")
    action_name = _action(action)
    command = _command_parts(provider_name, action_name, sanitized_service)
    return {
        "record_type": "service_command_preview",
        "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
        "service_name": sanitized_service,
        "provider": provider_name,
        "action": action_name,
        "command": command,
        "command_text": " ".join(command),
        "sanitized": True,
        "executed": False,
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }


def build_lifecycle_operator_steps(
    *,
    provider_readiness: dict[str, Any],
    action: str,
    readiness_state: str,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    provider = str(provider_readiness.get("provider") or "foreground-process")
    steps = [
        ("review_provider", f"Review {provider} readiness and platform limitations."),
        ("review_command_preview", f"Inspect the sanitized {action} command preview before any external use."),
        ("confirm_permissions", "Confirm required permissions manually outside PortMap-AI."),
    ]
    if readiness_state != "supported":
        steps.append(("resolve_readiness", "Resolve degraded or unavailable readiness before operator-run service work."))
    steps.append(("manual_execution_only", "Run any lifecycle command manually outside this preview if approved."))
    return [
        {
            "record_type": "service_lifecycle_operator_step",
            "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
            "generated_at": generated_at or _now(),
            "step_id": step_id,
            "summary": summary,
            "required": True,
            **SERVICE_LIFECYCLE_SAFETY_FLAGS,
        }
        for step_id, summary in steps
    ]


def build_lifecycle_safety_warnings(
    *,
    provider_readiness: dict[str, Any],
    action: str,
    readiness_state: str,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    warning_codes = {
        "preview_only",
        "manual_operator_review_required",
        "service_control_disabled",
        "service_installation_disabled",
        "service_registration_disabled",
        "elevation_request_disabled",
    }
    warning_codes.update(provider_readiness.get("warnings") or [])
    if readiness_state != "supported":
        warning_codes.add(f"readiness_{readiness_state}")
    if action in {"install_preview", "uninstall_preview"}:
        warning_codes.add("install_uninstall_preview_only")
    return [
        {
            "record_type": "service_lifecycle_safety_warning",
            "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
            "generated_at": generated_at or _now(),
            "warning": warning,
            "operator_review_required": True,
            **SERVICE_LIFECYCLE_SAFETY_FLAGS,
        }
        for warning in sorted(warning_codes)
    ]


def build_lifecycle_advisory_notes(
    *,
    provider_readiness: dict[str, Any],
    action: str,
    readiness_state: str,
) -> list[str]:
    notes = [
        "Lifecycle readiness is advisory and dry-run only.",
        "No service is installed, registered, started, stopped, restarted, or uninstalled.",
        "Commands are sanitized previews for operator review.",
    ]
    if readiness_state != "supported":
        notes.append("Readiness is not fully supported; resolve warnings before manual service work.")
    if str(provider_readiness.get("provider") or "") == "windows-service-control-manager":
        notes.append("Windows service registration remains preview-only and does not write registry keys.")
    if str(provider_readiness.get("provider") or "") == "macos-launchd":
        notes.append("launchd plist creation remains disabled.")
    if "systemd" in str(provider_readiness.get("provider") or ""):
        notes.append("systemd unit creation remains disabled.")
    if action in {"start_preview", "restart_preview"}:
        notes.append("Starting runtime services remains a manual operator action outside this preview.")
    return sorted(set(notes))


def build_service_lifecycle_dashboard_record(
    *,
    service_name: str,
    provider_readiness: dict[str, Any],
    action: str,
    readiness_state: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "service_lifecycle_dashboard",
        "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "service_name": _sanitize_service_name(service_name),
        "provider": str(provider_readiness.get("provider") or "foreground-process"),
        "platform": str(provider_readiness.get("platform") or "unknown"),
        "action": action,
        "readiness_state": readiness_state,
        "operator_review_required": readiness_state != "supported",
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }


def build_service_lifecycle_api_response(
    *,
    service_name: str,
    provider_readiness: dict[str, Any],
    action: str,
    readiness_state: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "service_lifecycle_api_response",
        "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "service_name": _sanitize_service_name(service_name),
        "provider": str(provider_readiness.get("provider") or "foreground-process"),
        "action": action,
        "readiness_state": readiness_state,
        "dry_run_only": True,
        "destructive_action": False,
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }


def build_service_lifecycle_export_dict(
    *,
    service_name: str,
    provider_readiness: dict[str, Any],
    action: str,
    readiness_state: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "service_lifecycle_export",
        "record_version": SERVICE_LIFECYCLE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "service_name": _sanitize_service_name(service_name),
        "platform": str(provider_readiness.get("platform") or "unknown"),
        "provider": str(provider_readiness.get("provider") or "foreground-process"),
        "action": action,
        "readiness_state": readiness_state,
        "command_preview_sanitized": True,
        "commands_executed": False,
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }


def service_lifecycle_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record or {})
    return {
        "record_type": str(payload.get("record_type") or "service_lifecycle_readiness"),
        "record_version": int(payload.get("record_version") or SERVICE_LIFECYCLE_RECORD_VERSION),
        "generated_at": str(payload.get("generated_at") or _now()),
        "service_name": _sanitize_service_name(payload.get("service_name") or "portmap-runtime"),
        "platform": str(payload.get("platform") or "unknown"),
        "provider": str(payload.get("provider") or "foreground-process"),
        "action": _action(payload.get("action")),
        "readiness_state": str(payload.get("readiness_state") or "unknown"),
        "required_permissions": _string_list(payload.get("required_permissions") or []),
        "advisory_notes": _string_list(payload.get("advisory_notes") or []),
        **SERVICE_LIFECYCLE_SAFETY_FLAGS,
    }


def _readiness_state(provider_readiness: dict[str, Any], action: str) -> str:
    provider_state = str(provider_readiness.get("state") or "unknown")
    supported_actions = set(provider_readiness.get("supported_actions") or [])
    if action not in supported_actions:
        return "unavailable"
    if provider_state in {"supported", "degraded", "unavailable", "unknown"}:
        return provider_state
    return "unknown"


def _command_parts(provider: str, action: str, service_name: str) -> list[str]:
    action_map = {
        "install_preview": "install",
        "start_preview": "start",
        "stop_preview": "stop",
        "restart_preview": "restart",
        "uninstall_preview": "uninstall",
        "status_preview": "status",
    }
    verb = action_map[action]
    if provider in {"linux-systemd", "raspberry-pi-systemd-edge"}:
        unit = f"{service_name}.service"
        if verb == "install":
            return ["systemctl", "--user", "link", "<operator-reviewed-unit-file>"]
        if verb == "uninstall":
            return ["systemctl", "--user", "disable", unit]
        return ["systemctl", "--user", verb, unit]
    if provider == "macos-launchd":
        label = f"local.portmap.{service_name}"
        if verb == "install":
            return ["launchctl", "bootstrap", "gui/<operator-uid>", "<operator-reviewed-plist>"]
        if verb == "uninstall":
            return ["launchctl", "bootout", "gui/<operator-uid>", "<operator-reviewed-plist>"]
        if verb == "status":
            return ["launchctl", "print", f"gui/<operator-uid>/{label}"]
        return ["launchctl", verb, label]
    if provider == "windows-service-control-manager":
        if verb == "install":
            return ["sc.exe", "create", service_name, "binPath=", "<operator-reviewed-command>"]
        if verb == "uninstall":
            return ["sc.exe", "delete", service_name]
        return ["sc.exe", verb, service_name]
    if verb in {"install", "uninstall"}:
        return ["<foreground-process-mode>", verb, service_name]
    return ["<portmap-command>", "runtime", verb, "--service-name", service_name]


def _action(value: Any) -> str:
    normalized = str(value or "status_preview").strip().lower().replace("-", "_")
    return normalized if normalized in SERVICE_LIFECYCLE_ACTIONS else "status_preview"


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


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
