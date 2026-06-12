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
from core_engine.packaging.linux_layouts import (
    LINUX_LAYOUT_SAFETY_FLAGS,
    LinuxLayoutPreviewRecord,
    build_linux_layout_preview,
    normalize_linux_distribution_family,
    normalize_linux_layout_preview,
    summarize_linux_layouts,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_text, sanitize_token


LINUX_PACKAGING_RECORD_VERSION = 1
LINUX_PACKAGING_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}
LINUX_PACKAGE_METHODS = {
    "deb_preview",
    "rpm_preview",
    "tarball_preview",
    "apt_repo_preview",
    "cli_only_preview",
    "unknown",
}
LINUX_PACKAGING_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    **LINUX_LAYOUT_SAFETY_FLAGS,
    "actual_package_created": False,
    "repository_published": False,
    "apt_repository_published": False,
    "systemd_unit_written": False,
    "systemd_service_created": False,
    "systemd_service_loaded": False,
    "systemd_service_enabled": False,
    "admin_escalation_requested": False,
}


@dataclass(frozen=True)
class LinuxPackagingReadinessRecord:
    packaging_id: str
    generated_at: str
    packaging_state: str
    target_platform: str
    package_method: str
    layout_previews: list[dict[str, Any]] = field(default_factory=list)
    systemd_preview: dict[str, Any] = field(default_factory=dict)
    raspberry_pi_readiness: dict[str, Any] = field(default_factory=dict)
    linux_arm_readiness: dict[str, Any] = field(default_factory=dict)
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
            "record_type": "linux_packaging_readiness",
            "record_version": LINUX_PACKAGING_RECORD_VERSION,
            "packaging_id": sanitize_reference(self.packaging_id),
            "generated_at": str(self.generated_at or ""),
            "packaging_state": normalize_linux_packaging_state(self.packaging_state),
            "target_platform": normalize_linux_target_platform(self.target_platform),
            "package_method": normalize_linux_package_method(self.package_method),
            "layout_previews": list(self.layout_previews),
            "systemd_preview": dict(self.systemd_preview),
            "raspberry_pi_readiness": dict(self.raspberry_pi_readiness),
            "linux_arm_readiness": dict(self.linux_arm_readiness),
            "uninstall_preview": dict(self.uninstall_preview),
            "rollback_preview": dict(self.rollback_preview),
            "validation_summary": dict(self.validation_summary),
            "required_permissions": sanitize_list(self.required_permissions),
            "admin_required": bool(self.admin_required),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **LINUX_PACKAGING_SAFETY_FLAGS,
        }


def build_linux_packaging_readiness(
    *,
    packaging_id: Any = "",
    generated_at: Any = None,
    target_platform: Any = "linux",
    package_method: Any = "deb_preview",
    distribution_family: Any = "debian",
    layout_previews: Iterable[LinuxLayoutPreviewRecord | dict[str, Any] | Any] | None = None,
    systemd_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    raspberry_pi_readiness: dict[str, Any] | None = None,
    linux_arm_readiness: dict[str, Any] | None = None,
    uninstall_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    rollback_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    required_permissions: Iterable[Any] | None = None,
    admin_required: Any = False,
    advisory_notes: Iterable[Any] | None = None,
) -> LinuxPackagingReadinessRecord:
    timestamp = str(generated_at or now_timestamp())
    platform = normalize_linux_target_platform(target_platform)
    method = normalize_linux_package_method(package_method)
    distro = normalize_linux_distribution_family(distribution_family)
    permissions = sanitize_list(required_permissions or default_linux_required_permissions(method))
    layouts = normalize_layout_previews(layout_previews, method=method, distribution_family=distro)
    systemd = normalize_installer_preview(systemd_preview) if systemd_preview is not None else default_systemd_preview()
    uninstall = normalize_installer_preview(uninstall_preview) if uninstall_preview is not None else default_linux_uninstall_preview()
    rollback = normalize_installer_preview(rollback_preview) if rollback_preview is not None else default_linux_rollback_preview()
    raspberry = build_raspberry_pi_readiness(raspberry_pi_readiness, distribution_family=distro)
    arm = build_linux_arm_readiness(linux_arm_readiness, distribution_family=distro)
    preview_rows = [systemd.to_dict(), uninstall.to_dict(), rollback.to_dict()]
    layout_rows = [layout.to_dict() for layout in layouts]
    state = infer_linux_packaging_state(
        platform=platform,
        method=method,
        admin_required=bool(admin_required),
        layouts=layout_rows,
        previews=preview_rows,
    )
    validation = build_linux_validation_summary(
        packaging_state=state,
        package_method=method,
        distribution_family=distro,
        layouts=layout_rows,
        previews=preview_rows,
        raspberry_pi_readiness=raspberry,
        linux_arm_readiness=arm,
        required_permissions=permissions,
        admin_required=bool(admin_required),
        advisory_notes=advisory_notes,
    )
    safe_id = sanitize_reference(packaging_id)
    if not safe_id:
        safe_id = "linux-packaging-" + digest(
            {
                "generated_at": timestamp,
                "target_platform": platform,
                "package_method": method,
                "distribution_family": distro,
                "permissions": permissions,
                "admin_required": bool(admin_required),
            }
        )[:16]
    return LinuxPackagingReadinessRecord(
        packaging_id=safe_id,
        generated_at=timestamp,
        packaging_state=state,
        target_platform=platform,
        package_method=method,
        layout_previews=layout_rows,
        systemd_preview=systemd.to_dict(),
        raspberry_pi_readiness=raspberry,
        linux_arm_readiness=arm,
        uninstall_preview=uninstall.to_dict(),
        rollback_preview=rollback.to_dict(),
        validation_summary=validation,
        required_permissions=permissions,
        admin_required=bool(admin_required),
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_linux_packaging_readiness(*, generated_at: Any = None) -> LinuxPackagingReadinessRecord:
    return build_linux_packaging_readiness(
        generated_at=generated_at,
        target_platform="unknown",
        package_method="unknown",
        distribution_family="unknown",
        layout_previews=[],
        admin_required=False,
        advisory_notes=["empty Linux packaging readiness summary"],
    )


def normalize_layout_previews(
    values: Iterable[LinuxLayoutPreviewRecord | dict[str, Any] | Any] | None,
    *,
    method: str,
    distribution_family: str,
) -> list[LinuxLayoutPreviewRecord]:
    if values is None:
        return default_layout_previews(method, distribution_family=distribution_family)
    return [normalize_linux_layout_preview(value) for value in list(values or [])[:16]]


def default_layout_previews(method: str, *, distribution_family: str) -> list[LinuxLayoutPreviewRecord]:
    normalized = normalize_linux_package_method(method)
    distro = normalize_linux_distribution_family(distribution_family)
    layout_map = {
        "deb_preview": ("deb_preview", "system", "/usr/share/portmap-ai"),
        "rpm_preview": ("rpm_preview", "system", "/usr/share/portmap-ai"),
        "tarball_preview": ("tarball_preview", "portable", "/opt/portmap-ai"),
        "apt_repo_preview": ("deb_preview", "system", "/usr/share/portmap-ai"),
        "cli_only_preview": ("cli_only_preview", "user", "~/.local/bin/portmap"),
        "unknown": ("unknown", "unknown", ""),
    }
    layout_type, scope, path = layout_map.get(normalized, layout_map["unknown"])
    return [
        build_linux_layout_preview(
            layout_type=layout_type,
            distribution_family=distro,
            install_scope=scope,
            path_preview=path,
            rollback_available=True,
            uninstall_available=True,
        )
    ]


def default_systemd_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="service_install",
        platform_family="linux",
        action_summary="systemd service preview",
        command_preview="systemctl --user status portmap-ai.service --preview",
        required_permissions=["operator_review", "future_admin_if_operator_approved"],
        rollback_available=True,
        uninstall_available=True,
        validation_steps=["review systemd unit name", "confirm systemd remains preview-only"],
        safety_warnings=["systemd unit is not written", "systemd service is not created, enabled, loaded, started, or modified"],
    )


def default_linux_uninstall_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="uninstall",
        platform_family="linux",
        action_summary="Linux uninstall preview",
        command_preview='package-manager remove portmap-ai --preview-only',
        required_permissions=["operator_review"],
        rollback_available=False,
        uninstall_available=True,
        validation_steps=["review package, CLI, and systemd paths", "confirm no uninstall action is executed"],
        safety_warnings=["uninstall is preview-only; no files, packages, repositories, or systemd records are changed"],
    )


def default_linux_rollback_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="rollback",
        platform_family="linux",
        action_summary="Linux rollback preview",
        command_preview='restore "<rollback-snapshot>" "<install-path>" --preview-only',
        required_permissions=["operator_review"],
        rollback_available=True,
        uninstall_available=False,
        validation_steps=["review rollback snapshot", "confirm rollback remains preview-only"],
        safety_warnings=["rollback is preview-only; no restore, overwrite, package, repository, or systemd change is performed"],
    )


def build_raspberry_pi_readiness(value: dict[str, Any] | None = None, *, distribution_family: str = "generic_linux") -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    distro = normalize_linux_distribution_family(distribution_family)
    supported = bool(payload.get("supported", distro == "raspberry_pi"))
    return {
        "record_type": "raspberry_pi_packaging_readiness",
        "record_version": LINUX_PACKAGING_RECORD_VERSION,
        "supported": supported,
        "distribution_family": distro,
        "architecture_summary": sanitize_text(payload.get("architecture_summary", "Linux ARM package layout preview")),
        "resource_notes": sanitize_list(payload.get("resource_notes", ["use lightweight collector profile", "keep package actions preview-only"])),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **LINUX_PACKAGING_SAFETY_FLAGS,
    }


def build_linux_arm_readiness(value: dict[str, Any] | None = None, *, distribution_family: str = "generic_linux") -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    distro = normalize_linux_distribution_family(distribution_family)
    supported = bool(payload.get("supported", distro in {"linux_arm", "raspberry_pi"}))
    return {
        "record_type": "linux_arm_packaging_readiness",
        "record_version": LINUX_PACKAGING_RECORD_VERSION,
        "supported": supported,
        "distribution_family": distro,
        "architecture_summary": sanitize_text(payload.get("architecture_summary", "ARM package metadata readiness preview")),
        "resource_notes": sanitize_list(payload.get("resource_notes", ["validate ARM wheels and service templates before future packaging"])),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **LINUX_PACKAGING_SAFETY_FLAGS,
    }


def build_linux_validation_summary(
    *,
    packaging_state: str,
    package_method: str,
    distribution_family: str,
    layouts: list[dict[str, Any]],
    previews: list[dict[str, Any]],
    raspberry_pi_readiness: dict[str, Any],
    linux_arm_readiness: dict[str, Any],
    required_permissions: list[str],
    admin_required: bool,
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    notes = sanitize_list(advisory_notes or [])
    if admin_required:
        notes.append("future package path may require operator-approved administrator context; no escalation requested")
    return {
        "record_type": "linux_packaging_validation_summary",
        "record_version": LINUX_PACKAGING_RECORD_VERSION,
        "packaging_state": normalize_linux_packaging_state(packaging_state),
        "package_method": normalize_linux_package_method(package_method),
        "distribution_family": normalize_linux_distribution_family(distribution_family),
        "layout_summary": summarize_linux_layouts(layouts),
        "preview_summary": summarize_installer_previews(previews),
        "raspberry_pi_readiness": {
            "supported": bool(raspberry_pi_readiness.get("supported")),
            "preview_only": True,
            "destructive_action": False,
        },
        "linux_arm_readiness": {
            "supported": bool(linux_arm_readiness.get("supported")),
            "preview_only": True,
            "destructive_action": False,
        },
        "validation_steps": [
            "layout previews generated",
            "systemd preview generated",
            "Raspberry Pi readiness summarized",
            "Linux ARM readiness summarized",
            "uninstall preview generated",
            "rollback preview generated",
            "no package, repository, filesystem, systemd, service, or admin escalation side effects",
        ],
        "required_permissions": sanitize_list(required_permissions),
        "admin_required": bool(admin_required),
        "admin_escalation_requested": False,
        "advisory_notes": notes,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **LINUX_PACKAGING_SAFETY_FLAGS,
    }


def infer_linux_packaging_state(
    *,
    platform: str,
    method: str,
    admin_required: bool,
    layouts: list[dict[str, Any]],
    previews: list[dict[str, Any]],
) -> str:
    if platform != "linux":
        return "unavailable"
    if method == "unknown":
        return "blocked"
    if not layouts or any(row.get("layout_type") == "unknown" for row in layouts):
        return "degraded"
    if any(row.get("preview_type") == "unknown" for row in previews):
        return "degraded"
    if admin_required:
        return "degraded"
    return "ready"


def default_linux_required_permissions(method: str) -> list[str]:
    permissions = ["operator_review"]
    if normalize_linux_package_method(method) in {"deb_preview", "rpm_preview", "apt_repo_preview"}:
        permissions.append("future_admin_if_operator_approved")
    return permissions


def normalize_linux_package_method(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LINUX_PACKAGE_METHODS else "unknown"


def normalize_linux_packaging_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LINUX_PACKAGING_STATES else "unknown"


def normalize_linux_target_platform(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"linux", "linux_arm", "raspberry_pi", "debian", "ubuntu", "fedora", "rhel", "arch", "generic_linux"}:
        return "linux"
    return "unknown"


def deterministic_linux_packaging_json(record: LinuxPackagingReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, LinuxPackagingReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "LINUX_PACKAGE_METHODS",
    "LINUX_PACKAGING_SAFETY_FLAGS",
    "LINUX_PACKAGING_STATES",
    "LinuxPackagingReadinessRecord",
    "build_linux_arm_readiness",
    "build_linux_packaging_readiness",
    "build_linux_validation_summary",
    "build_raspberry_pi_readiness",
    "default_linux_rollback_preview",
    "default_linux_uninstall_preview",
    "default_systemd_preview",
    "deterministic_linux_packaging_json",
    "empty_linux_packaging_readiness",
    "infer_linux_packaging_state",
    "normalize_linux_package_method",
    "normalize_linux_packaging_state",
    "normalize_linux_target_platform",
]
