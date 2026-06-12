from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import (
    PACKAGING_SAFETY_FLAGS,
    InstallerPreviewRecord,
    build_installer_preview,
    normalize_installer_preview,
    sanitize_list,
    summarize_installer_previews,
)
from core_engine.packaging.macos_layouts import (
    MACOS_LAYOUT_SAFETY_FLAGS,
    MacOSLayoutPreviewRecord,
    build_macos_layout_preview,
    normalize_macos_install_scope,
    normalize_macos_layout_preview,
    summarize_macos_layouts,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_text, sanitize_token


MACOS_PACKAGING_RECORD_VERSION = 1
MACOS_PACKAGING_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}
MACOS_PACKAGE_METHODS = {
    "app_bundle_preview",
    "pkg_preview",
    "dmg_preview",
    "homebrew_preview",
    "cli_only_preview",
    "unknown",
}
MACOS_PACKAGING_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    **MACOS_LAYOUT_SAFETY_FLAGS,
    "actual_package_created": False,
    "binary_signed": False,
    "notarization_submitted": False,
    "notarization_ticket_stapled": False,
    "launchd_plist_written": False,
    "launchd_service_loaded": False,
    "launchd_service_modified": False,
    "admin_escalation_requested": False,
}


@dataclass(frozen=True)
class MacOSPackagingReadinessRecord:
    packaging_id: str
    generated_at: str
    packaging_state: str
    target_platform: str
    package_method: str
    layout_previews: list[dict[str, Any]] = field(default_factory=list)
    launchd_preview: dict[str, Any] = field(default_factory=dict)
    signing_readiness: dict[str, Any] = field(default_factory=dict)
    notarization_readiness: dict[str, Any] = field(default_factory=dict)
    uninstall_preview: dict[str, Any] = field(default_factory=dict)
    rollback_preview: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)
    admin_required: bool = False
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "macos_packaging_readiness",
            "record_version": MACOS_PACKAGING_RECORD_VERSION,
            "packaging_id": sanitize_reference(self.packaging_id),
            "generated_at": str(self.generated_at or ""),
            "packaging_state": normalize_macos_packaging_state(self.packaging_state),
            "target_platform": normalize_macos_target_platform(self.target_platform),
            "package_method": normalize_macos_package_method(self.package_method),
            "layout_previews": list(self.layout_previews),
            "launchd_preview": dict(self.launchd_preview),
            "signing_readiness": dict(self.signing_readiness),
            "notarization_readiness": dict(self.notarization_readiness),
            "uninstall_preview": dict(self.uninstall_preview),
            "rollback_preview": dict(self.rollback_preview),
            "validation_summary": dict(self.validation_summary),
            "required_permissions": sanitize_list(self.required_permissions),
            "admin_required": bool(self.admin_required),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **MACOS_PACKAGING_SAFETY_FLAGS,
        }


def build_macos_packaging_readiness(
    *,
    packaging_id: Any = "",
    generated_at: Any = None,
    target_platform: Any = "macos",
    package_method: Any = "app_bundle_preview",
    layout_previews: Iterable[MacOSLayoutPreviewRecord | dict[str, Any] | Any] | None = None,
    launchd_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    signing_readiness: dict[str, Any] | None = None,
    notarization_readiness: dict[str, Any] | None = None,
    uninstall_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    rollback_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    required_permissions: Iterable[Any] | None = None,
    admin_required: Any = False,
    advisory_notes: Iterable[Any] | None = None,
) -> MacOSPackagingReadinessRecord:
    timestamp = str(generated_at or now_timestamp())
    platform = normalize_macos_target_platform(target_platform)
    method = normalize_macos_package_method(package_method)
    permissions = sanitize_list(required_permissions or default_macos_required_permissions(method))
    layouts = normalize_layout_previews(layout_previews, method=method)
    launchd = normalize_installer_preview(launchd_preview) if launchd_preview is not None else default_launchd_preview()
    uninstall = normalize_installer_preview(uninstall_preview) if uninstall_preview is not None else default_macos_uninstall_preview()
    rollback = normalize_installer_preview(rollback_preview) if rollback_preview is not None else default_macos_rollback_preview()
    signing = build_signing_readiness(signing_readiness)
    notarization = build_notarization_readiness(notarization_readiness)
    preview_rows = [launchd.to_dict(), uninstall.to_dict(), rollback.to_dict()]
    layout_rows = [layout.to_dict() for layout in layouts]
    state = infer_macos_packaging_state(
        platform=platform,
        method=method,
        admin_required=bool(admin_required),
        layouts=layout_rows,
        previews=preview_rows,
        signing_readiness=signing,
        notarization_readiness=notarization,
    )
    validation = build_macos_validation_summary(
        packaging_state=state,
        package_method=method,
        layouts=layout_rows,
        previews=preview_rows,
        signing_readiness=signing,
        notarization_readiness=notarization,
        required_permissions=permissions,
        admin_required=bool(admin_required),
        advisory_notes=advisory_notes,
    )
    safe_id = sanitize_reference(packaging_id)
    if not safe_id:
        safe_id = "macos-packaging-" + digest(
            {
                "generated_at": timestamp,
                "target_platform": platform,
                "package_method": method,
                "permissions": permissions,
                "admin_required": bool(admin_required),
            }
        )[:16]
    return MacOSPackagingReadinessRecord(
        packaging_id=safe_id,
        generated_at=timestamp,
        packaging_state=state,
        target_platform=platform,
        package_method=method,
        layout_previews=layout_rows,
        launchd_preview=launchd.to_dict(),
        signing_readiness=signing,
        notarization_readiness=notarization,
        uninstall_preview=uninstall.to_dict(),
        rollback_preview=rollback.to_dict(),
        validation_summary=validation,
        required_permissions=permissions,
        admin_required=bool(admin_required),
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_macos_packaging_readiness(*, generated_at: Any = None) -> MacOSPackagingReadinessRecord:
    return build_macos_packaging_readiness(
        generated_at=generated_at,
        target_platform="unknown",
        package_method="unknown",
        layout_previews=[],
        admin_required=False,
        advisory_notes=["empty macOS packaging readiness summary"],
    )


def normalize_layout_previews(
    values: Iterable[MacOSLayoutPreviewRecord | dict[str, Any] | Any] | None,
    *,
    method: str,
) -> list[MacOSLayoutPreviewRecord]:
    if values is None:
        return default_layout_previews(method)
    return [normalize_macos_layout_preview(value) for value in list(values or [])[:16]]


def default_layout_previews(method: str) -> list[MacOSLayoutPreviewRecord]:
    normalized = normalize_macos_package_method(method)
    layout_map = {
        "app_bundle_preview": ("app_bundle_preview", "user", "/Applications/PortMap-AI.app"),
        "pkg_preview": ("pkg_installer_preview", "system", "/Applications/PortMap-AI.app"),
        "dmg_preview": ("app_bundle_preview", "portable", "/Volumes/PortMap-AI/PortMap-AI.app"),
        "homebrew_preview": ("cli_only_preview", "user", "/opt/homebrew/bin/portmap"),
        "cli_only_preview": ("cli_only_preview", "user", "~/bin/portmap"),
        "unknown": ("unknown", "unknown", ""),
    }
    layout_type, scope, path = layout_map.get(normalized, layout_map["unknown"])
    return [
        build_macos_layout_preview(
            layout_type=layout_type,
            install_scope=scope,
            path_preview=path,
            rollback_available=True,
            uninstall_available=True,
        )
    ]


def default_launchd_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="service_install",
        platform_family="macos",
        action_summary="launchd service preview",
        command_preview="launchctl bootstrap gui/<uid> <portmap-ai.plist> -preview",
        required_permissions=["operator_review", "future_admin_if_operator_approved"],
        rollback_available=True,
        uninstall_available=True,
        validation_steps=["review launchd label", "confirm launchd remains preview-only"],
        safety_warnings=["launchd plist is not written", "launchd service is not loaded or modified"],
    )


def default_macos_uninstall_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="uninstall",
        platform_family="macos",
        action_summary="macOS uninstall preview",
        command_preview='rm -rf "<install-path>" --preview-only',
        required_permissions=["operator_review"],
        rollback_available=False,
        uninstall_available=True,
        validation_steps=["review app, CLI, and launchd paths", "confirm no uninstall action is executed"],
        safety_warnings=["uninstall is preview-only; no files or launchd records are removed"],
    )


def default_macos_rollback_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="rollback",
        platform_family="macos",
        action_summary="macOS rollback preview",
        command_preview='restore "<rollback-snapshot>" "<install-path>" --preview-only',
        required_permissions=["operator_review"],
        rollback_available=True,
        uninstall_available=False,
        validation_steps=["review rollback snapshot", "confirm rollback remains preview-only"],
        safety_warnings=["rollback is preview-only; no restore, overwrite, or launchd change is performed"],
    )


def build_signing_readiness(value: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    identity_required = bool(payload.get("identity_required", True))
    return {
        "record_type": "macos_signing_readiness",
        "record_version": MACOS_PACKAGING_RECORD_VERSION,
        "identity_required": identity_required,
        "identity_available": bool(payload.get("identity_available", False)),
        "codesign_preview": sanitize_text(payload.get("codesign_preview", "codesign --sign <developer-id> <artifact> --dry-run")),
        "signing_performed": False,
        "credential_stored": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **MACOS_PACKAGING_SAFETY_FLAGS,
    }


def build_notarization_readiness(value: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    return {
        "record_type": "macos_notarization_readiness",
        "record_version": MACOS_PACKAGING_RECORD_VERSION,
        "notarization_required": bool(payload.get("notarization_required", True)),
        "notarization_configured": bool(payload.get("notarization_configured", False)),
        "submission_preview": sanitize_text(payload.get("submission_preview", "notarytool submit <artifact> --dry-run")),
        "notarization_submitted": False,
        "notarization_ticket_stapled": False,
        "credential_stored": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **MACOS_PACKAGING_SAFETY_FLAGS,
    }


def build_macos_validation_summary(
    *,
    packaging_state: str,
    package_method: str,
    layouts: list[dict[str, Any]],
    previews: list[dict[str, Any]],
    signing_readiness: dict[str, Any],
    notarization_readiness: dict[str, Any],
    required_permissions: list[str],
    admin_required: bool,
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    notes = sanitize_list(advisory_notes or [])
    if admin_required:
        notes.append("future package path may require operator-approved administrator context; no escalation requested")
    return {
        "record_type": "macos_packaging_validation_summary",
        "record_version": MACOS_PACKAGING_RECORD_VERSION,
        "packaging_state": normalize_macos_packaging_state(packaging_state),
        "package_method": normalize_macos_package_method(package_method),
        "layout_summary": summarize_macos_layouts(layouts),
        "preview_summary": summarize_installer_previews(previews),
        "signing_readiness": {
            "identity_required": bool(signing_readiness.get("identity_required")),
            "identity_available": bool(signing_readiness.get("identity_available")),
            "signing_performed": False,
        },
        "notarization_readiness": {
            "notarization_required": bool(notarization_readiness.get("notarization_required")),
            "notarization_configured": bool(notarization_readiness.get("notarization_configured")),
            "notarization_submitted": False,
        },
        "validation_steps": [
            "layout previews generated",
            "launchd preview generated",
            "signing readiness summarized",
            "notarization readiness summarized",
            "uninstall preview generated",
            "rollback preview generated",
            "no package, filesystem, launchd, signing, notarization, or admin escalation side effects",
        ],
        "required_permissions": sanitize_list(required_permissions),
        "admin_required": bool(admin_required),
        "admin_escalation_requested": False,
        "advisory_notes": notes,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **MACOS_PACKAGING_SAFETY_FLAGS,
    }


def infer_macos_packaging_state(
    *,
    platform: str,
    method: str,
    admin_required: bool,
    layouts: list[dict[str, Any]],
    previews: list[dict[str, Any]],
    signing_readiness: dict[str, Any],
    notarization_readiness: dict[str, Any],
) -> str:
    if platform != "macos":
        return "unavailable"
    if method == "unknown":
        return "blocked"
    if not layouts or any(row.get("layout_type") == "unknown" for row in layouts):
        return "degraded"
    if any(row.get("preview_type") == "unknown" for row in previews):
        return "degraded"
    if admin_required:
        return "degraded"
    if signing_readiness.get("identity_required") and not signing_readiness.get("identity_available"):
        return "degraded"
    if notarization_readiness.get("notarization_required") and not notarization_readiness.get("notarization_configured"):
        return "degraded"
    return "ready"


def default_macos_required_permissions(method: str) -> list[str]:
    permissions = ["operator_review"]
    if normalize_macos_package_method(method) == "pkg_preview":
        permissions.append("future_admin_if_operator_approved")
    return permissions


def normalize_macos_package_method(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in MACOS_PACKAGE_METHODS else "unknown"


def normalize_macos_packaging_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in MACOS_PACKAGING_STATES else "unknown"


def normalize_macos_target_platform(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"macos", "darwin", "osx"}:
        return "macos"
    return "unknown"


def deterministic_macos_packaging_json(record: MacOSPackagingReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, MacOSPackagingReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "MACOS_PACKAGE_METHODS",
    "MACOS_PACKAGING_SAFETY_FLAGS",
    "MACOS_PACKAGING_STATES",
    "MacOSPackagingReadinessRecord",
    "build_macos_packaging_readiness",
    "build_macos_validation_summary",
    "build_notarization_readiness",
    "build_signing_readiness",
    "default_launchd_preview",
    "default_macos_rollback_preview",
    "default_macos_uninstall_preview",
    "deterministic_macos_packaging_json",
    "empty_macos_packaging_readiness",
    "infer_macos_packaging_state",
    "normalize_macos_install_scope",
    "normalize_macos_package_method",
    "normalize_macos_packaging_state",
    "normalize_macos_target_platform",
]
