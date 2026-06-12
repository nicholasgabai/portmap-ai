from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import PACKAGING_SAFETY_FLAGS, sanitize_list
from core_engine.scaling.bus_envelopes import digest, sanitize_reference, sanitize_text, sanitize_token


LINUX_LAYOUT_RECORD_VERSION = 1
LINUX_LAYOUT_TYPES = {
    "deb_preview",
    "rpm_preview",
    "tarball_preview",
    "systemd_service_preview",
    "cli_only_preview",
    "unknown",
}
LINUX_DISTRIBUTION_FAMILIES = {
    "debian",
    "ubuntu",
    "fedora",
    "rhel",
    "arch",
    "raspberry_pi",
    "linux_arm",
    "generic_linux",
    "unknown",
}
LINUX_INSTALL_SCOPES = {"user", "system", "portable", "unknown"}
LINUX_LAYOUT_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    "package_created": False,
    "repository_published": False,
    "filesystem_written": False,
    "systemd_unit_written": False,
    "systemd_modified": False,
    "systemd_service_created": False,
    "systemd_service_loaded": False,
    "systemd_service_enabled": False,
    "admin_escalation_requested": False,
}


@dataclass(frozen=True)
class LinuxLayoutPreviewRecord:
    layout_id: str
    layout_type: str
    distribution_family: str
    install_scope: str
    package_name: str
    path_preview: str
    included_components: list[str] = field(default_factory=list)
    excluded_components: list[str] = field(default_factory=list)
    service_preview: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)
    rollback_available: bool = False
    uninstall_available: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "linux_layout_preview",
            "record_version": LINUX_LAYOUT_RECORD_VERSION,
            "layout_id": sanitize_reference(self.layout_id),
            "layout_type": normalize_linux_layout_type(self.layout_type),
            "distribution_family": normalize_linux_distribution_family(self.distribution_family),
            "install_scope": normalize_linux_install_scope(self.install_scope),
            "package_name": sanitize_package_name(self.package_name),
            "path_preview": sanitize_linux_path_preview(self.path_preview),
            "included_components": sanitize_list(self.included_components),
            "excluded_components": sanitize_list(self.excluded_components),
            "service_preview": sanitize_service_preview(self.service_preview),
            "required_permissions": sanitize_list(self.required_permissions),
            "rollback_available": bool(self.rollback_available),
            "uninstall_available": bool(self.uninstall_available),
            "advisory_notes": sanitize_list(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **LINUX_LAYOUT_SAFETY_FLAGS,
        }


def build_linux_layout_preview(
    *,
    layout_id: Any = "",
    layout_type: Any = "unknown",
    distribution_family: Any = "generic_linux",
    install_scope: Any = "user",
    package_name: Any = "portmap-ai",
    path_preview: Any = "",
    included_components: Iterable[Any] | None = None,
    excluded_components: Iterable[Any] | None = None,
    service_preview: dict[str, Any] | None = None,
    required_permissions: Iterable[Any] | None = None,
    rollback_available: Any = False,
    uninstall_available: Any = False,
    advisory_notes: Iterable[Any] | None = None,
) -> LinuxLayoutPreviewRecord:
    normalized_type = normalize_linux_layout_type(layout_type)
    normalized_family = normalize_linux_distribution_family(distribution_family)
    normalized_scope = normalize_linux_install_scope(install_scope)
    safe_path = sanitize_linux_path_preview(path_preview)
    permissions = sanitize_list(required_permissions or default_linux_required_permissions(normalized_scope))
    included = sanitize_list(included_components or default_linux_included_components(normalized_type))
    excluded = sanitize_list(excluded_components or ["payloads", "credentials", "runtime databases", "logs"])
    service = sanitize_service_preview(service_preview or default_service_preview(normalized_type))
    notes = sanitize_list(advisory_notes or ["Linux layout preview is metadata-only and advisory"])
    safe_id = sanitize_reference(layout_id)
    if not safe_id:
        safe_id = "linux-layout-" + digest(
            {
                "layout_type": normalized_type,
                "distribution_family": normalized_family,
                "install_scope": normalized_scope,
                "package_name": sanitize_package_name(package_name),
                "path_preview": safe_path,
            }
        )[:16]
    return LinuxLayoutPreviewRecord(
        layout_id=safe_id,
        layout_type=normalized_type,
        distribution_family=normalized_family,
        install_scope=normalized_scope,
        package_name=sanitize_package_name(package_name),
        path_preview=safe_path,
        included_components=included,
        excluded_components=excluded,
        service_preview=service,
        required_permissions=permissions,
        rollback_available=bool(rollback_available),
        uninstall_available=bool(uninstall_available),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_linux_layout_preview(value: Any) -> LinuxLayoutPreviewRecord:
    if isinstance(value, LinuxLayoutPreviewRecord):
        return value
    if not isinstance(value, dict):
        return build_linux_layout_preview(
            layout_type="unknown",
            distribution_family="unknown",
            install_scope="unknown",
            path_preview="",
            advisory_notes=["invalid Linux layout generated from malformed input"],
        )
    try:
        return build_linux_layout_preview(
            layout_id=value.get("layout_id", ""),
            layout_type=value.get("layout_type", value.get("type", "unknown")),
            distribution_family=value.get("distribution_family", value.get("distribution", "unknown")),
            install_scope=value.get("install_scope", "unknown"),
            package_name=value.get("package_name", "portmap-ai"),
            path_preview=value.get("path_preview", ""),
            included_components=value.get("included_components") if isinstance(value.get("included_components"), list) else None,
            excluded_components=value.get("excluded_components") if isinstance(value.get("excluded_components"), list) else None,
            service_preview=value.get("service_preview") if isinstance(value.get("service_preview"), dict) else None,
            required_permissions=value.get("required_permissions") if isinstance(value.get("required_permissions"), list) else None,
            rollback_available=value.get("rollback_available", False),
            uninstall_available=value.get("uninstall_available", False),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_linux_layout_preview(layout_type="unknown", advisory_notes=[str(exc)])


def summarize_linux_layouts(layouts: Iterable[LinuxLayoutPreviewRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_linux_layout_preview(layout).to_dict() for layout in list(layouts or [])]
    type_counts: dict[str, int] = {}
    distro_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    permission_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["layout_type"]] = type_counts.get(row["layout_type"], 0) + 1
        distro_counts[row["distribution_family"]] = distro_counts.get(row["distribution_family"], 0) + 1
        scope_counts[row["install_scope"]] = scope_counts.get(row["install_scope"], 0) + 1
        for permission in row.get("required_permissions", []):
            permission_counts[permission] = permission_counts.get(permission, 0) + 1
    return {
        "layout_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "distribution_family_counts": dict(sorted(distro_counts.items())),
        "scope_counts": dict(sorted(scope_counts.items())),
        "permission_counts": dict(sorted(permission_counts.items())),
        "rollback_available_count": sum(1 for row in rows if row.get("rollback_available")),
        "uninstall_available_count": sum(1 for row in rows if row.get("uninstall_available")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **LINUX_LAYOUT_SAFETY_FLAGS,
    }


def default_linux_required_permissions(scope: str) -> list[str]:
    if normalize_linux_install_scope(scope) == "system":
        return ["operator_review", "future_admin_if_operator_approved"]
    return ["operator_review"]


def default_linux_included_components(layout_type: str) -> list[str]:
    normalized = normalize_linux_layout_type(layout_type)
    if normalized == "systemd_service_preview":
        return ["systemd unit preview", "service command preview", "rollback metadata"]
    if normalized == "cli_only_preview":
        return ["portmap CLI entry point", "configuration templates", "documentation"]
    return ["package metadata preview", "portmap CLI entry point", "configuration templates", "documentation"]


def default_service_preview(layout_type: str) -> dict[str, Any]:
    if normalize_linux_layout_type(layout_type) != "systemd_service_preview":
        return {
            "service_preview_type": "none",
            "systemd_unit_preview": "",
            "preview_only": True,
            "destructive_action": False,
            **LINUX_LAYOUT_SAFETY_FLAGS,
        }
    return {
        "service_preview_type": "systemd_service_preview",
        "systemd_unit_preview": "portmap-ai.service",
        "service_command_preview": "systemctl --user status portmap-ai.service --preview",
        "preview_only": True,
        "destructive_action": False,
        **LINUX_LAYOUT_SAFETY_FLAGS,
    }


def sanitize_service_preview(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = {}
    return {
        "service_preview_type": sanitize_token(value.get("service_preview_type", "unknown")).lower() or "unknown",
        "systemd_unit_preview": sanitize_text(value.get("systemd_unit_preview", ""))[:120],
        "service_command_preview": sanitize_linux_path_preview(value.get("service_command_preview", "")),
        "preview_only": True,
        "destructive_action": False,
        **LINUX_LAYOUT_SAFETY_FLAGS,
    }


def sanitize_linux_path_preview(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        text = "/".join(str(item) for item in value)
    else:
        text = str(value or "")
    text = re.sub(r"[\r\n\t]+", " ", text.strip())
    text = re.sub(r"[;&|`$<>]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "<no-path-preview>"
    return sanitize_text(text)[:240]


def sanitize_package_name(value: Any) -> str:
    safe_value = str(value or "").strip().lower()
    safe_value = re.sub(r"[^a-z0-9.+-]+", "-", safe_value)
    safe_value = re.sub(r"-{2,}", "-", safe_value).strip(".-+")
    return safe_value[:120] or "portmap-ai"


def normalize_linux_layout_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LINUX_LAYOUT_TYPES else "unknown"


def normalize_linux_distribution_family(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LINUX_DISTRIBUTION_FAMILIES else "unknown"


def normalize_linux_install_scope(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LINUX_INSTALL_SCOPES else "unknown"


def deterministic_linux_layout_json(record: LinuxLayoutPreviewRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, LinuxLayoutPreviewRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "LINUX_DISTRIBUTION_FAMILIES",
    "LINUX_INSTALL_SCOPES",
    "LINUX_LAYOUT_SAFETY_FLAGS",
    "LINUX_LAYOUT_TYPES",
    "LinuxLayoutPreviewRecord",
    "build_linux_layout_preview",
    "deterministic_linux_layout_json",
    "normalize_linux_distribution_family",
    "normalize_linux_install_scope",
    "normalize_linux_layout_preview",
    "normalize_linux_layout_type",
    "sanitize_linux_path_preview",
    "sanitize_package_name",
    "summarize_linux_layouts",
]
