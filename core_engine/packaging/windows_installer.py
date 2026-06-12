from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import (
    PACKAGING_SAFETY_FLAGS,
    InstallerPreviewRecord,
    build_installer_preview,
    normalize_installer_preview,
    sanitize_command_preview,
    sanitize_list,
    summarize_installer_previews,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_text, sanitize_token


WINDOWS_INSTALLER_RECORD_VERSION = 1
WINDOWS_INSTALLER_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}
WINDOWS_INSTALLER_METHODS = {"powershell_preview", "msi_preview", "zip_app_preview", "winget_preview", "unknown"}
WINDOWS_INSTALLER_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    "actual_installer_generated": False,
    "windows_service_created": False,
    "windows_service_modified": False,
    "registry_keys_written": False,
    "path_modified": False,
    "admin_escalation_requested": False,
    "shortcut_created": False,
}


@dataclass(frozen=True)
class WindowsInstallerReadinessRecord:
    installer_id: str
    generated_at: str
    installer_state: str
    target_platform: str
    install_method: str
    install_steps: list[dict[str, Any]] = field(default_factory=list)
    service_preview: dict[str, Any] = field(default_factory=dict)
    shortcut_preview: dict[str, Any] = field(default_factory=dict)
    uninstall_preview: dict[str, Any] = field(default_factory=dict)
    rollback_preview: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)
    admin_required: bool = False
    signing_required: bool = False
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "windows_installer_readiness",
            "record_version": WINDOWS_INSTALLER_RECORD_VERSION,
            "installer_id": sanitize_reference(self.installer_id),
            "generated_at": str(self.generated_at or ""),
            "installer_state": normalize_installer_state(self.installer_state),
            "target_platform": normalize_target_platform(self.target_platform),
            "install_method": normalize_install_method(self.install_method),
            "install_steps": list(self.install_steps),
            "service_preview": dict(self.service_preview),
            "shortcut_preview": dict(self.shortcut_preview),
            "uninstall_preview": dict(self.uninstall_preview),
            "rollback_preview": dict(self.rollback_preview),
            "validation_summary": dict(self.validation_summary),
            "required_permissions": sanitize_list(self.required_permissions),
            "admin_required": bool(self.admin_required),
            "signing_required": bool(self.signing_required),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **WINDOWS_INSTALLER_SAFETY_FLAGS,
        }


def build_windows_installer_readiness(
    *,
    installer_id: Any = "",
    generated_at: Any = None,
    target_platform: Any = "windows",
    install_method: Any = "powershell_preview",
    install_steps: Iterable[dict[str, Any] | Any] | None = None,
    service_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    shortcut_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    uninstall_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    rollback_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    required_permissions: Iterable[Any] | None = None,
    admin_required: Any = False,
    signing_required: Any = False,
    advisory_notes: Iterable[Any] | None = None,
) -> WindowsInstallerReadinessRecord:
    timestamp = str(generated_at or now_timestamp())
    method = normalize_install_method(install_method)
    platform = normalize_target_platform(target_platform)
    permissions = sanitize_list(required_permissions or default_required_permissions(method))
    install_preview = build_install_method_preview(method, permissions=permissions)
    steps = normalize_install_steps(install_steps) if install_steps is not None else default_install_steps(method)
    service = normalize_installer_preview(service_preview) if service_preview is not None else default_service_preview()
    shortcut = normalize_installer_preview(shortcut_preview) if shortcut_preview is not None else default_shortcut_preview()
    uninstall = normalize_installer_preview(uninstall_preview) if uninstall_preview is not None else default_uninstall_preview()
    rollback = normalize_installer_preview(rollback_preview) if rollback_preview is not None else default_rollback_preview()
    preview_rows = [install_preview.to_dict(), service.to_dict(), shortcut.to_dict(), uninstall.to_dict(), rollback.to_dict()]
    state = infer_installer_state(
        platform=platform,
        method=method,
        admin_required=bool(admin_required),
        signing_required=bool(signing_required),
        previews=preview_rows,
    )
    validation = build_validation_summary(
        installer_state=state,
        install_method=method,
        previews=preview_rows,
        required_permissions=permissions,
        admin_required=bool(admin_required),
        signing_required=bool(signing_required),
        advisory_notes=advisory_notes,
    )
    safe_id = sanitize_reference(installer_id)
    if not safe_id:
        safe_id = "windows-installer-" + digest(
            {
                "generated_at": timestamp,
                "target_platform": platform,
                "install_method": method,
                "permissions": permissions,
                "admin_required": bool(admin_required),
                "signing_required": bool(signing_required),
            }
        )[:16]
    return WindowsInstallerReadinessRecord(
        installer_id=safe_id,
        generated_at=timestamp,
        installer_state=state,
        target_platform=platform,
        install_method=method,
        install_steps=steps,
        service_preview=service.to_dict(),
        shortcut_preview=shortcut.to_dict(),
        uninstall_preview=uninstall.to_dict(),
        rollback_preview=rollback.to_dict(),
        validation_summary=validation,
        required_permissions=permissions,
        admin_required=bool(admin_required),
        signing_required=bool(signing_required),
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_windows_installer_readiness(*, generated_at: Any = None) -> WindowsInstallerReadinessRecord:
    return build_windows_installer_readiness(
        generated_at=generated_at,
        target_platform="unknown",
        install_method="unknown",
        install_steps=[],
        admin_required=False,
        signing_required=False,
        advisory_notes=["empty Windows installer readiness summary"],
    )


def build_install_method_preview(method: str, *, permissions: list[str]) -> InstallerPreviewRecord:
    normalized_method = normalize_install_method(method)
    commands = {
        "powershell_preview": "powershell -NoProfile -ExecutionPolicy Bypass -File <portmap-install-script.ps1> -WhatIf",
        "msi_preview": "msiexec /i <portmap-ai.msi> /qn /l*v <install-log> PREVIEWONLY=1",
        "zip_app_preview": "Expand-Archive <portmap-ai.zip> -DestinationPath <install-dir> -WhatIf",
        "winget_preview": "winget install <portmap-ai-package-id> --source winget --silent --accept-source-agreements --preview",
        "unknown": "",
    }
    return build_installer_preview(
        preview_type="install",
        platform_family="windows",
        action_summary=f"{normalized_method} install plan preview",
        command_preview=commands.get(normalized_method, ""),
        required_permissions=permissions,
        rollback_available=True,
        uninstall_available=True,
        validation_steps=["review install method", "confirm no command execution", "verify rollback and uninstall previews"],
        safety_warnings=["preview only; no installer is generated or executed", "PATH and registry are not modified"],
    )


def default_service_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="service_install",
        platform_family="windows",
        action_summary="Windows service install preview",
        command_preview='New-Service -Name "PortMapAI" -BinaryPathName "<install-dir>\\portmap-worker.exe" -WhatIf',
        required_permissions=["operator_review", "future_admin_if_operator_approved"],
        rollback_available=True,
        uninstall_available=True,
        validation_steps=["review service name", "confirm service command remains preview-only"],
        safety_warnings=["Windows service is not created", "service control commands are not executed"],
    )


def default_shortcut_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="shortcut_create",
        platform_family="windows",
        action_summary="Start Menu and Desktop shortcut preview",
        command_preview='New-Item -ItemType SymbolicLink -Path "<shortcut-path>" -Target "<portmap-ui>" -WhatIf',
        required_permissions=["operator_review"],
        rollback_available=True,
        uninstall_available=True,
        validation_steps=["review shortcut targets", "confirm shortcut creation remains preview-only"],
        safety_warnings=["Start Menu and Desktop shortcuts are not created"],
    )


def default_uninstall_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="uninstall",
        platform_family="windows",
        action_summary="Windows uninstall preview",
        command_preview='Remove-Item "<install-dir>" -Recurse -WhatIf',
        required_permissions=["operator_review"],
        rollback_available=False,
        uninstall_available=True,
        validation_steps=["review files that would be removed", "confirm no uninstall action is executed"],
        safety_warnings=["uninstall is a preview only; no files, services, or registry keys are removed"],
    )


def default_rollback_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="rollback",
        platform_family="windows",
        action_summary="Windows rollback preview",
        command_preview='Restore-Item "<rollback-snapshot>" -Destination "<install-dir>" -WhatIf',
        required_permissions=["operator_review"],
        rollback_available=True,
        uninstall_available=False,
        validation_steps=["review rollback source", "confirm rollback remains preview-only"],
        safety_warnings=["rollback is a preview only; no restore or overwrite is performed"],
    )


def build_validation_summary(
    *,
    installer_state: str,
    install_method: str,
    previews: list[dict[str, Any]],
    required_permissions: list[str],
    admin_required: bool,
    signing_required: bool,
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    preview_summary = summarize_installer_previews(previews)
    checks = [
        "installer previews generated",
        "service preview generated",
        "shortcut preview generated",
        "uninstall preview generated",
        "rollback preview generated",
        "no commands executed",
        "no filesystem, service, registry, PATH, or admin escalation side effects",
    ]
    notes = sanitize_list(advisory_notes or [])
    if admin_required:
        notes.append("future install path may require operator-approved administrator context; no escalation requested")
    if signing_required:
        notes.append("future installer artifact may require signing; no signing performed")
    return {
        "record_type": "windows_installer_validation_summary",
        "record_version": WINDOWS_INSTALLER_RECORD_VERSION,
        "installer_state": normalize_installer_state(installer_state),
        "install_method": normalize_install_method(install_method),
        "preview_summary": preview_summary,
        "validation_steps": checks,
        "required_permissions": sanitize_list(required_permissions),
        "admin_required": bool(admin_required),
        "admin_escalation_requested": False,
        "signing_required": bool(signing_required),
        "signing_performed": False,
        "advisory_notes": notes,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **WINDOWS_INSTALLER_SAFETY_FLAGS,
    }


def infer_installer_state(
    *,
    platform: str,
    method: str,
    admin_required: bool,
    signing_required: bool,
    previews: list[dict[str, Any]],
) -> str:
    if platform != "windows":
        return "unavailable"
    if method == "unknown":
        return "blocked"
    if any(row.get("preview_type") == "unknown" for row in previews):
        return "degraded"
    if admin_required or signing_required:
        return "degraded"
    return "ready"


def default_required_permissions(method: str) -> list[str]:
    permissions = ["operator_review"]
    if normalize_install_method(method) in {"msi_preview", "winget_preview"}:
        permissions.append("future_admin_if_operator_approved")
    return permissions


def default_install_steps(method: str) -> list[dict[str, Any]]:
    labels = [
        "review install method",
        "review PowerShell/MSI/ZIP/winget preview",
        "review service and shortcut previews",
        "review uninstall and rollback previews",
        "run validation summary",
    ]
    return [
        {
            "step_id": f"windows-install-step-{index}",
            "install_method": normalize_install_method(method),
            "action_summary": label,
            "preview_only": True,
            "destructive_action": False,
        }
        for index, label in enumerate(labels, start=1)
    ]


def normalize_install_steps(values: Iterable[dict[str, Any] | Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for index, value in enumerate(list(values or [])[:32], start=1):
        if isinstance(value, dict):
            summary = sanitize_text(value.get("action_summary", value.get("summary", ""))) or f"install step {index}"
            method = normalize_install_method(value.get("install_method", "unknown"))
        else:
            summary = sanitize_text(value) or f"install step {index}"
            method = "unknown"
        steps.append(
            {
                "step_id": f"windows-install-step-{index}",
                "install_method": method,
                "action_summary": summary,
                "preview_only": True,
                "destructive_action": False,
            }
        )
    return steps


def normalize_install_method(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in WINDOWS_INSTALLER_METHODS else "unknown"


def normalize_installer_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in WINDOWS_INSTALLER_STATES else "unknown"


def normalize_target_platform(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"windows", "win32", "win64"}:
        return "windows"
    return "unknown"


def deterministic_windows_installer_json(record: WindowsInstallerReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, WindowsInstallerReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "WINDOWS_INSTALLER_METHODS",
    "WINDOWS_INSTALLER_STATES",
    "WindowsInstallerReadinessRecord",
    "build_install_method_preview",
    "build_validation_summary",
    "build_windows_installer_readiness",
    "default_rollback_preview",
    "default_service_preview",
    "default_shortcut_preview",
    "default_uninstall_preview",
    "deterministic_windows_installer_json",
    "empty_windows_installer_readiness",
    "infer_installer_state",
    "normalize_install_method",
    "normalize_installer_state",
    "normalize_target_platform",
    "sanitize_command_preview",
]
