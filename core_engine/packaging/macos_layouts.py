from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import PACKAGING_SAFETY_FLAGS, sanitize_list
from core_engine.scaling.bus_envelopes import digest, sanitize_reference, sanitize_text, sanitize_token


MACOS_LAYOUT_RECORD_VERSION = 1
MACOS_LAYOUT_TYPES = {
    "app_bundle_preview",
    "pkg_installer_preview",
    "launchd_service_preview",
    "cli_only_preview",
    "unknown",
}
MACOS_INSTALL_SCOPES = {"user", "system", "portable", "unknown"}
MACOS_LAYOUT_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    "package_created": False,
    "app_bundle_created": False,
    "plist_written": False,
    "launchd_modified": False,
    "launchd_loaded": False,
    "filesystem_written": False,
    "signing_performed": False,
    "notarization_performed": False,
    "admin_escalation_requested": False,
}


@dataclass(frozen=True)
class MacOSLayoutPreviewRecord:
    layout_id: str
    layout_type: str
    bundle_identifier: str
    app_name: str
    install_scope: str
    path_preview: str
    included_components: list[str] = field(default_factory=list)
    excluded_components: list[str] = field(default_factory=list)
    required_permissions: list[str] = field(default_factory=list)
    rollback_available: bool = False
    uninstall_available: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "macos_layout_preview",
            "record_version": MACOS_LAYOUT_RECORD_VERSION,
            "layout_id": sanitize_reference(self.layout_id),
            "layout_type": normalize_macos_layout_type(self.layout_type),
            "bundle_identifier": sanitize_bundle_identifier(self.bundle_identifier),
            "app_name": sanitize_text(self.app_name) or "PortMap-AI",
            "install_scope": normalize_macos_install_scope(self.install_scope),
            "path_preview": sanitize_path_preview(self.path_preview),
            "included_components": sanitize_list(self.included_components),
            "excluded_components": sanitize_list(self.excluded_components),
            "required_permissions": sanitize_list(self.required_permissions),
            "rollback_available": bool(self.rollback_available),
            "uninstall_available": bool(self.uninstall_available),
            "advisory_notes": sanitize_list(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **MACOS_LAYOUT_SAFETY_FLAGS,
        }


def build_macos_layout_preview(
    *,
    layout_id: Any = "",
    layout_type: Any = "unknown",
    bundle_identifier: Any = "ai.portmap.preview",
    app_name: Any = "PortMap-AI",
    install_scope: Any = "user",
    path_preview: Any = "",
    included_components: Iterable[Any] | None = None,
    excluded_components: Iterable[Any] | None = None,
    required_permissions: Iterable[Any] | None = None,
    rollback_available: Any = False,
    uninstall_available: Any = False,
    advisory_notes: Iterable[Any] | None = None,
) -> MacOSLayoutPreviewRecord:
    normalized_type = normalize_macos_layout_type(layout_type)
    normalized_scope = normalize_macos_install_scope(install_scope)
    safe_path = sanitize_path_preview(path_preview)
    permissions = sanitize_list(required_permissions or default_required_permissions(normalized_scope))
    included = sanitize_list(included_components or default_included_components(normalized_type))
    excluded = sanitize_list(excluded_components or ["payloads", "credentials", "runtime databases", "logs"])
    notes = sanitize_list(advisory_notes or ["macOS layout preview is metadata-only and advisory"])
    safe_id = sanitize_reference(layout_id)
    if not safe_id:
        safe_id = "macos-layout-" + digest(
            {
                "layout_type": normalized_type,
                "bundle_identifier": sanitize_bundle_identifier(bundle_identifier),
                "app_name": sanitize_text(app_name),
                "install_scope": normalized_scope,
                "path_preview": safe_path,
            }
        )[:16]
    return MacOSLayoutPreviewRecord(
        layout_id=safe_id,
        layout_type=normalized_type,
        bundle_identifier=sanitize_bundle_identifier(bundle_identifier),
        app_name=sanitize_text(app_name) or "PortMap-AI",
        install_scope=normalized_scope,
        path_preview=safe_path,
        included_components=included,
        excluded_components=excluded,
        required_permissions=permissions,
        rollback_available=bool(rollback_available),
        uninstall_available=bool(uninstall_available),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_macos_layout_preview(value: Any) -> MacOSLayoutPreviewRecord:
    if isinstance(value, MacOSLayoutPreviewRecord):
        return value
    if not isinstance(value, dict):
        return build_macos_layout_preview(
            layout_type="unknown",
            install_scope="unknown",
            path_preview="",
            advisory_notes=["invalid macOS layout generated from malformed input"],
        )
    try:
        return build_macos_layout_preview(
            layout_id=value.get("layout_id", ""),
            layout_type=value.get("layout_type", value.get("type", "unknown")),
            bundle_identifier=value.get("bundle_identifier", "ai.portmap.preview"),
            app_name=value.get("app_name", "PortMap-AI"),
            install_scope=value.get("install_scope", "unknown"),
            path_preview=value.get("path_preview", ""),
            included_components=value.get("included_components") if isinstance(value.get("included_components"), list) else None,
            excluded_components=value.get("excluded_components") if isinstance(value.get("excluded_components"), list) else None,
            required_permissions=value.get("required_permissions") if isinstance(value.get("required_permissions"), list) else None,
            rollback_available=value.get("rollback_available", False),
            uninstall_available=value.get("uninstall_available", False),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_macos_layout_preview(layout_type="unknown", advisory_notes=[str(exc)])


def summarize_macos_layouts(layouts: Iterable[MacOSLayoutPreviewRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_macos_layout_preview(layout).to_dict() for layout in list(layouts or [])]
    type_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    permission_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["layout_type"]] = type_counts.get(row["layout_type"], 0) + 1
        scope_counts[row["install_scope"]] = scope_counts.get(row["install_scope"], 0) + 1
        for permission in row.get("required_permissions", []):
            permission_counts[permission] = permission_counts.get(permission, 0) + 1
    return {
        "layout_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "scope_counts": dict(sorted(scope_counts.items())),
        "permission_counts": dict(sorted(permission_counts.items())),
        "rollback_available_count": sum(1 for row in rows if row.get("rollback_available")),
        "uninstall_available_count": sum(1 for row in rows if row.get("uninstall_available")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **MACOS_LAYOUT_SAFETY_FLAGS,
    }


def default_required_permissions(scope: str) -> list[str]:
    if normalize_macos_install_scope(scope) == "system":
        return ["operator_review", "future_admin_if_operator_approved"]
    return ["operator_review"]


def default_included_components(layout_type: str) -> list[str]:
    normalized = normalize_macos_layout_type(layout_type)
    if normalized == "cli_only_preview":
        return ["portmap CLI entry point", "configuration templates", "documentation"]
    if normalized == "launchd_service_preview":
        return ["launchd plist preview", "service command preview", "rollback metadata"]
    return ["application entry point", "runtime package metadata", "configuration templates", "documentation"]


def sanitize_path_preview(value: Any) -> str:
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


def sanitize_bundle_identifier(value: Any) -> str:
    safe_value = str(value or "").strip().lower()
    safe_value = re.sub(r"[^a-z0-9.-]+", "-", safe_value)
    safe_value = re.sub(r"\.{2,}", ".", safe_value).strip(".-")
    return safe_value[:120] or "ai.portmap.preview"


def normalize_macos_layout_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in MACOS_LAYOUT_TYPES else "unknown"


def normalize_macos_install_scope(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in MACOS_INSTALL_SCOPES else "unknown"


def deterministic_macos_layout_json(record: MacOSLayoutPreviewRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, MacOSLayoutPreviewRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "MACOS_INSTALL_SCOPES",
    "MACOS_LAYOUT_SAFETY_FLAGS",
    "MACOS_LAYOUT_TYPES",
    "MacOSLayoutPreviewRecord",
    "build_macos_layout_preview",
    "deterministic_macos_layout_json",
    "normalize_macos_install_scope",
    "normalize_macos_layout_preview",
    "normalize_macos_layout_type",
    "sanitize_bundle_identifier",
    "sanitize_path_preview",
    "summarize_macos_layouts",
]
