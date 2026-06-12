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
from core_engine.packaging.update_channels import (
    UPDATE_CHANNEL_SAFETY_FLAGS,
    UpdateChannelRecord,
    build_update_channel,
    normalize_update_channel,
    summarize_update_channels,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_text, sanitize_token


AUTO_UPDATER_RECORD_VERSION = 1
AUTO_UPDATER_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}
UPDATE_METHODS = {
    "manual_preview",
    "package_manager_preview",
    "container_preview",
    "bundled_updater_preview",
    "offline_preview",
    "unknown",
}
AUTO_UPDATER_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    **UPDATE_CHANNEL_SAFETY_FLAGS,
    "network_called": False,
    "update_server_contacted": False,
    "update_downloaded": False,
    "update_executed": False,
    "update_installed": False,
    "package_modified": False,
    "filesystem_written": False,
    "real_signature_verified": False,
    "admin_escalation_requested": False,
    "credential_stored": False,
}


@dataclass(frozen=True)
class AutoUpdaterReadinessRecord:
    updater_id: str
    generated_at: str
    updater_state: str
    target_platform: str
    update_method: str
    update_channels: list[dict[str, Any]] = field(default_factory=list)
    version_validation: dict[str, Any] = field(default_factory=dict)
    checksum_validation: dict[str, Any] = field(default_factory=dict)
    signature_validation: dict[str, Any] = field(default_factory=dict)
    staged_rollout_preview: dict[str, Any] = field(default_factory=dict)
    rollback_preview: dict[str, Any] = field(default_factory=dict)
    update_preview: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "auto_updater_readiness",
            "record_version": AUTO_UPDATER_RECORD_VERSION,
            "updater_id": sanitize_reference(self.updater_id),
            "generated_at": str(self.generated_at or ""),
            "updater_state": normalize_auto_updater_state(self.updater_state),
            "target_platform": normalize_updater_target_platform(self.target_platform),
            "update_method": normalize_update_method(self.update_method),
            "update_channels": list(self.update_channels),
            "version_validation": dict(self.version_validation),
            "checksum_validation": dict(self.checksum_validation),
            "signature_validation": dict(self.signature_validation),
            "staged_rollout_preview": dict(self.staged_rollout_preview),
            "rollback_preview": dict(self.rollback_preview),
            "update_preview": dict(self.update_preview),
            "validation_summary": dict(self.validation_summary),
            "required_permissions": sanitize_list(self.required_permissions),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **AUTO_UPDATER_SAFETY_FLAGS,
        }


def build_auto_updater_readiness(
    *,
    updater_id: Any = "",
    generated_at: Any = None,
    target_platform: Any = "cross_platform",
    update_method: Any = "manual_preview",
    update_channels: Iterable[UpdateChannelRecord | dict[str, Any] | Any] | None = None,
    version_validation: dict[str, Any] | None = None,
    checksum_validation: dict[str, Any] | None = None,
    signature_validation: dict[str, Any] | None = None,
    staged_rollout_preview: dict[str, Any] | None = None,
    rollback_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    update_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    required_permissions: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> AutoUpdaterReadinessRecord:
    timestamp = str(generated_at or now_timestamp())
    platform = normalize_updater_target_platform(target_platform)
    method = normalize_update_method(update_method)
    channels = normalize_update_channels(update_channels)
    channel_rows = [channel.to_dict() for channel in channels]
    permissions = sanitize_list(required_permissions or default_required_permissions(method))
    version = build_version_validation(version_validation)
    checksum = build_checksum_validation(checksum_validation, channels=channel_rows)
    signature = build_signature_validation(signature_validation, channels=channel_rows)
    rollout = build_staged_rollout_preview(staged_rollout_preview, method=method)
    rollback = normalize_installer_preview(rollback_preview) if rollback_preview is not None else default_rollback_preview()
    update = normalize_installer_preview(update_preview) if update_preview is not None else default_update_preview(method)
    preview_rows = [rollback.to_dict(), update.to_dict()]
    state = infer_auto_updater_state(
        platform=platform,
        method=method,
        channels=channel_rows,
        version_validation=version,
        checksum_validation=checksum,
        signature_validation=signature,
    )
    validation = build_update_validation_summary(
        updater_state=state,
        update_method=method,
        channels=channel_rows,
        previews=preview_rows,
        version_validation=version,
        checksum_validation=checksum,
        signature_validation=signature,
        staged_rollout_preview=rollout,
        required_permissions=permissions,
        advisory_notes=advisory_notes,
    )
    safe_id = sanitize_reference(updater_id)
    if not safe_id:
        safe_id = "auto-updater-" + digest(
            {
                "generated_at": timestamp,
                "target_platform": platform,
                "update_method": method,
                "channel_count": len(channel_rows),
                "required_permissions": permissions,
            }
        )[:16]
    return AutoUpdaterReadinessRecord(
        updater_id=safe_id,
        generated_at=timestamp,
        updater_state=state,
        target_platform=platform,
        update_method=method,
        update_channels=channel_rows,
        version_validation=version,
        checksum_validation=checksum,
        signature_validation=signature,
        staged_rollout_preview=rollout,
        rollback_preview=rollback.to_dict(),
        update_preview=update.to_dict(),
        validation_summary=validation,
        required_permissions=permissions,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_auto_updater_readiness(*, generated_at: Any = None) -> AutoUpdaterReadinessRecord:
    return build_auto_updater_readiness(
        generated_at=generated_at,
        target_platform="unknown",
        update_method="unknown",
        update_channels=[],
        advisory_notes=["empty auto-updater readiness summary"],
    )


def normalize_update_channels(
    values: Iterable[UpdateChannelRecord | dict[str, Any] | Any] | None,
) -> list[UpdateChannelRecord]:
    if values is None:
        return default_update_channels()
    return [normalize_update_channel(value) for value in list(values or [])[:16]]


def default_update_channels() -> list[UpdateChannelRecord]:
    return [
        build_update_channel(
            channel_name="Stable",
            channel_type="stable",
            release_tier="production",
            update_frequency="manual",
            rollback_available=True,
        )
    ]


def build_version_validation(value: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    return {
        "record_type": "updater_version_validation",
        "record_version": AUTO_UPDATER_RECORD_VERSION,
        "current_version_preview": sanitize_text(payload.get("current_version_preview", "current-version")),
        "target_version_preview": sanitize_text(payload.get("target_version_preview", "target-version")),
        "version_compatible": bool(payload.get("version_compatible", True)),
        "downgrade_preview": bool(payload.get("downgrade_preview", False)),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **AUTO_UPDATER_SAFETY_FLAGS,
    }


def build_checksum_validation(value: dict[str, Any] | None = None, *, channels: list[dict[str, Any]]) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    required = any(channel.get("checksum_required") for channel in channels)
    return {
        "record_type": "updater_checksum_validation",
        "record_version": AUTO_UPDATER_RECORD_VERSION,
        "checksum_required": bool(payload.get("checksum_required", required)),
        "checksum_available": bool(payload.get("checksum_available", True)),
        "checksum_algorithm_preview": sanitize_text(payload.get("checksum_algorithm_preview", "sha256")),
        "checksum_verified": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **AUTO_UPDATER_SAFETY_FLAGS,
    }


def build_signature_validation(value: dict[str, Any] | None = None, *, channels: list[dict[str, Any]]) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    required = any(channel.get("signature_required") for channel in channels)
    return {
        "record_type": "updater_signature_validation",
        "record_version": AUTO_UPDATER_RECORD_VERSION,
        "signature_required": bool(payload.get("signature_required", required)),
        "signature_available": bool(payload.get("signature_available", True)),
        "signing_identity_preview": sanitize_text(payload.get("signing_identity_preview", "release-signing-identity-preview")),
        "signature_verified": False,
        "real_signature_verified": False,
        "credential_stored": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **AUTO_UPDATER_SAFETY_FLAGS,
    }


def build_staged_rollout_preview(value: dict[str, Any] | None = None, *, method: str) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    rollout_percentages = payload.get("rollout_percentages", [0, 10, 25, 50, 100])
    if not isinstance(rollout_percentages, list):
        rollout_percentages = [0]
    safe_percentages = [max(0, min(100, int(item))) for item in rollout_percentages[:16] if isinstance(item, (int, float))]
    return {
        "record_type": "updater_staged_rollout_preview",
        "record_version": AUTO_UPDATER_RECORD_VERSION,
        "update_method": normalize_update_method(method),
        "rollout_percentages": safe_percentages or [0],
        "operator_approval_required": bool(payload.get("operator_approval_required", True)),
        "automatic_rollout_enabled": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **AUTO_UPDATER_SAFETY_FLAGS,
    }


def default_rollback_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="rollback",
        platform_family="updater",
        action_summary="secure updater rollback preview",
        command_preview='portmap update rollback --preview-only "<previous-version>"',
        required_permissions=["operator_review"],
        rollback_available=True,
        uninstall_available=False,
        validation_steps=["review previous version", "confirm rollback remains preview-only"],
        safety_warnings=["rollback is preview-only; no files, packages, services, containers, or runtime state are changed"],
    )


def default_update_preview(method: str) -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="install",
        platform_family="updater",
        action_summary=f"{normalize_update_method(method)} update preview",
        command_preview='portmap update apply --preview-only "<target-version>"',
        required_permissions=default_required_permissions(method),
        rollback_available=True,
        uninstall_available=False,
        validation_steps=["review update channel", "confirm no download or update execution"],
        safety_warnings=["update is preview-only; no download, server communication, package change, or file modification is performed"],
    )


def build_update_validation_summary(
    *,
    updater_state: str,
    update_method: str,
    channels: list[dict[str, Any]],
    previews: list[dict[str, Any]],
    version_validation: dict[str, Any],
    checksum_validation: dict[str, Any],
    signature_validation: dict[str, Any],
    staged_rollout_preview: dict[str, Any],
    required_permissions: list[str],
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "auto_updater_validation_summary",
        "record_version": AUTO_UPDATER_RECORD_VERSION,
        "updater_state": normalize_auto_updater_state(updater_state),
        "update_method": normalize_update_method(update_method),
        "channel_summary": summarize_update_channels(channels),
        "preview_summary": summarize_installer_previews(previews),
        "version_compatible": bool(version_validation.get("version_compatible")),
        "checksum_required": bool(checksum_validation.get("checksum_required")),
        "checksum_available": bool(checksum_validation.get("checksum_available")),
        "checksum_verified": False,
        "signature_required": bool(signature_validation.get("signature_required")),
        "signature_available": bool(signature_validation.get("signature_available")),
        "signature_verified": False,
        "automatic_rollout_enabled": False,
        "rollout_percentages": list(staged_rollout_preview.get("rollout_percentages", [])),
        "validation_steps": [
            "update channels summarized",
            "version compatibility preview generated",
            "checksum readiness summarized",
            "signature readiness summarized",
            "staged rollout preview generated",
            "rollback preview generated",
            "update preview generated",
            "no download, server communication, signature verification, update execution, package change, or file modification",
        ],
        "required_permissions": sanitize_list(required_permissions),
        "advisory_notes": sanitize_list(advisory_notes or []),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **AUTO_UPDATER_SAFETY_FLAGS,
    }


def infer_auto_updater_state(
    *,
    platform: str,
    method: str,
    channels: list[dict[str, Any]],
    version_validation: dict[str, Any],
    checksum_validation: dict[str, Any],
    signature_validation: dict[str, Any],
) -> str:
    if platform == "unknown":
        return "unavailable"
    if method == "unknown":
        return "blocked"
    if not channels or any(channel.get("channel_type") == "unknown" for channel in channels):
        return "degraded"
    if not version_validation.get("version_compatible", False):
        return "degraded"
    if checksum_validation.get("checksum_required") and not checksum_validation.get("checksum_available"):
        return "degraded"
    if signature_validation.get("signature_required") and not signature_validation.get("signature_available"):
        return "degraded"
    return "ready"


def default_required_permissions(method: Any) -> list[str]:
    normalized = normalize_update_method(method)
    if normalized in {"package_manager_preview", "bundled_updater_preview"}:
        return ["operator_review", "future_admin_if_operator_approved"]
    return ["operator_review"]


def normalize_update_method(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in UPDATE_METHODS else "unknown"


def normalize_auto_updater_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in AUTO_UPDATER_STATES else "unknown"


def normalize_updater_target_platform(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"cross_platform", "windows", "macos", "linux", "raspberry_pi", "linux_arm", "container"}:
        return safe_value
    return "unknown"


def deterministic_auto_updater_json(record: AutoUpdaterReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, AutoUpdaterReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "AUTO_UPDATER_SAFETY_FLAGS",
    "AUTO_UPDATER_STATES",
    "UPDATE_METHODS",
    "AutoUpdaterReadinessRecord",
    "build_auto_updater_readiness",
    "build_checksum_validation",
    "build_signature_validation",
    "build_staged_rollout_preview",
    "build_update_validation_summary",
    "build_version_validation",
    "deterministic_auto_updater_json",
    "empty_auto_updater_readiness",
    "infer_auto_updater_state",
    "normalize_auto_updater_state",
    "normalize_update_method",
    "normalize_updater_target_platform",
]
