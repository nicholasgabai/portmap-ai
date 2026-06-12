from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)


INSTALLER_PREVIEW_RECORD_VERSION = 1
INSTALLER_PREVIEW_TYPES = {
    "install",
    "service_install",
    "shortcut_create",
    "uninstall",
    "rollback",
    "validation",
    "unknown",
}
PACKAGING_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "installer_created": False,
    "command_executed": False,
    "powershell_executed": False,
    "filesystem_written": False,
    "service_created": False,
    "service_modified": False,
    "registry_written": False,
    "path_modified": False,
    "admin_escalation_requested": False,
    "shortcut_created": False,
    "driver_installed": False,
    "kernel_hook_installed": False,
    "credential_stored": False,
}


@dataclass(frozen=True)
class InstallerPreviewRecord:
    preview_id: str
    preview_type: str
    platform_family: str
    action_summary: str
    command_preview: str
    required_permissions: list[str] = field(default_factory=list)
    rollback_available: bool = False
    uninstall_available: bool = False
    validation_steps: list[str] = field(default_factory=list)
    safety_warnings: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "installer_preview",
            "record_version": INSTALLER_PREVIEW_RECORD_VERSION,
            "preview_id": sanitize_reference(self.preview_id),
            "preview_type": normalize_preview_type(self.preview_type),
            "platform_family": sanitize_token(self.platform_family).lower() or "unknown",
            "action_summary": sanitize_text(self.action_summary) or "Installer preview",
            "command_preview": sanitize_command_preview(self.command_preview),
            "required_permissions": sanitize_list(self.required_permissions),
            "rollback_available": bool(self.rollback_available),
            "uninstall_available": bool(self.uninstall_available),
            "validation_steps": sanitize_list(self.validation_steps),
            "safety_warnings": sanitize_list(self.safety_warnings),
            "advisory_notes": sanitize_list(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **PACKAGING_SAFETY_FLAGS,
        }


def build_installer_preview(
    *,
    preview_id: Any = "",
    preview_type: Any = "unknown",
    platform_family: Any = "unknown",
    action_summary: Any = "",
    command_preview: Any = "",
    required_permissions: Iterable[Any] | None = None,
    rollback_available: Any = False,
    uninstall_available: Any = False,
    validation_steps: Iterable[Any] | None = None,
    safety_warnings: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> InstallerPreviewRecord:
    normalized_type = normalize_preview_type(preview_type)
    permissions = sanitize_list(required_permissions or ["operator_review"])
    validations = sanitize_list(validation_steps or ["review preview record", "confirm no command execution"])
    warnings = sanitize_list(safety_warnings or ["preview only; no installer, service, filesystem, or registry changes are performed"])
    notes = sanitize_list(advisory_notes or ["installer preview is metadata-only and advisory"])
    safe_command = sanitize_command_preview(command_preview)
    safe_summary = sanitize_text(action_summary) or f"{normalized_type} preview"
    safe_id = sanitize_reference(preview_id)
    if not safe_id:
        safe_id = "installer-preview-" + digest(
            {
                "preview_type": normalized_type,
                "platform_family": sanitize_token(platform_family).lower(),
                "action_summary": safe_summary,
                "command_preview": safe_command,
                "required_permissions": permissions,
            }
        )[:16]
    return InstallerPreviewRecord(
        preview_id=safe_id,
        preview_type=normalized_type,
        platform_family=sanitize_token(platform_family).lower() or "unknown",
        action_summary=safe_summary,
        command_preview=safe_command,
        required_permissions=permissions,
        rollback_available=bool(rollback_available),
        uninstall_available=bool(uninstall_available),
        validation_steps=validations,
        safety_warnings=warnings,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_installer_preview(value: Any) -> InstallerPreviewRecord:
    if isinstance(value, InstallerPreviewRecord):
        return value
    if not isinstance(value, dict):
        return build_installer_preview(
            preview_type="unknown",
            platform_family="unknown",
            action_summary="Invalid installer preview",
            command_preview="",
            safety_warnings=["invalid preview generated from malformed input"],
        )
    try:
        return build_installer_preview(
            preview_id=value.get("preview_id", ""),
            preview_type=value.get("preview_type", value.get("type", "unknown")),
            platform_family=value.get("platform_family", value.get("platform", "unknown")),
            action_summary=value.get("action_summary", value.get("summary", "")),
            command_preview=value.get("command_preview", ""),
            required_permissions=value.get("required_permissions") if isinstance(value.get("required_permissions"), list) else None,
            rollback_available=value.get("rollback_available", False),
            uninstall_available=value.get("uninstall_available", False),
            validation_steps=value.get("validation_steps") if isinstance(value.get("validation_steps"), list) else None,
            safety_warnings=value.get("safety_warnings") if isinstance(value.get("safety_warnings"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_installer_preview(action_summary="Invalid installer preview", safety_warnings=[str(exc)])


def summarize_installer_previews(previews: Iterable[InstallerPreviewRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_installer_preview(preview).to_dict() for preview in list(previews or [])]
    type_counts: dict[str, int] = {}
    platform_counts: dict[str, int] = {}
    permission_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["preview_type"]] = type_counts.get(row["preview_type"], 0) + 1
        platform_counts[row["platform_family"]] = platform_counts.get(row["platform_family"], 0) + 1
        for permission in row.get("required_permissions", []):
            permission_counts[permission] = permission_counts.get(permission, 0) + 1
    return {
        "preview_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "platform_counts": dict(sorted(platform_counts.items())),
        "permission_counts": dict(sorted(permission_counts.items())),
        "rollback_available_count": sum(1 for row in rows if row.get("rollback_available")),
        "uninstall_available_count": sum(1 for row in rows if row.get("uninstall_available")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PACKAGING_SAFETY_FLAGS,
    }


def normalize_preview_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in INSTALLER_PREVIEW_TYPES else "unknown"


def sanitize_command_preview(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        text = " ".join(str(item) for item in value)
    else:
        text = str(value or "")
    text = re.sub(r"[\r\n\t]+", " ", text.strip())
    text = re.sub(r"[;&|`$<>]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "<no-command-preview>"
    return sanitize_text(text)[:240]


def sanitize_list(values: Iterable[Any]) -> list[str]:
    return [item for item in (sanitize_text(value) for value in values) if item][:32]


def deterministic_installer_preview_json(record: InstallerPreviewRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, InstallerPreviewRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "INSTALLER_PREVIEW_TYPES",
    "PACKAGING_SAFETY_FLAGS",
    "InstallerPreviewRecord",
    "build_installer_preview",
    "deterministic_installer_preview_json",
    "normalize_installer_preview",
    "normalize_preview_type",
    "sanitize_command_preview",
    "summarize_installer_previews",
]
