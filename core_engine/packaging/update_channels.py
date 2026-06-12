from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import PACKAGING_SAFETY_FLAGS, sanitize_list
from core_engine.scaling.bus_envelopes import digest, sanitize_reference, sanitize_text, sanitize_token


UPDATE_CHANNEL_RECORD_VERSION = 1
UPDATE_CHANNEL_TYPES = {"stable", "beta", "preview", "development", "offline", "unknown"}
RELEASE_TIERS = {"production", "validation", "testing", "development", "unknown"}
UPDATE_CHANNEL_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    "network_called": False,
    "update_server_contacted": False,
    "update_downloaded": False,
    "update_retrieved": False,
    "update_executed": False,
    "package_modified": False,
    "filesystem_written": False,
    "credential_stored": False,
}


@dataclass(frozen=True)
class UpdateChannelRecord:
    channel_id: str
    channel_name: str
    channel_type: str
    release_tier: str
    update_frequency: str
    validation_requirements: list[str] = field(default_factory=list)
    rollback_available: bool = False
    signature_required: bool = True
    checksum_required: bool = True
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "update_channel",
            "record_version": UPDATE_CHANNEL_RECORD_VERSION,
            "channel_id": sanitize_update_identifier(self.channel_id),
            "channel_name": sanitize_text(self.channel_name) or "update channel",
            "channel_type": normalize_update_channel_type(self.channel_type),
            "release_tier": normalize_release_tier(self.release_tier),
            "update_frequency": sanitize_text(self.update_frequency) or "manual",
            "validation_requirements": sanitize_list(self.validation_requirements),
            "rollback_available": bool(self.rollback_available),
            "signature_required": bool(self.signature_required),
            "checksum_required": bool(self.checksum_required),
            "advisory_notes": sanitize_list(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **UPDATE_CHANNEL_SAFETY_FLAGS,
        }


def build_update_channel(
    *,
    channel_id: Any = "",
    channel_name: Any = "Stable",
    channel_type: Any = "stable",
    release_tier: Any = "production",
    update_frequency: Any = "manual",
    validation_requirements: Iterable[Any] | None = None,
    rollback_available: Any = True,
    signature_required: Any = True,
    checksum_required: Any = True,
    advisory_notes: Iterable[Any] | None = None,
) -> UpdateChannelRecord:
    normalized_type = normalize_update_channel_type(channel_type)
    normalized_tier = normalize_release_tier(release_tier)
    requirements = sanitize_list(
        validation_requirements
        or default_validation_requirements(
            signature_required=bool(signature_required),
            checksum_required=bool(checksum_required),
        )
    )
    notes = sanitize_list(advisory_notes or ["update channel is metadata-only and advisory"])
    safe_id = sanitize_update_identifier(channel_id)
    if not safe_id:
        safe_id = "update-channel-" + digest(
            {
                "channel_name": sanitize_text(channel_name),
                "channel_type": normalized_type,
                "release_tier": normalized_tier,
                "update_frequency": sanitize_text(update_frequency),
            }
        )[:16]
    return UpdateChannelRecord(
        channel_id=safe_id,
        channel_name=sanitize_text(channel_name) or "Stable",
        channel_type=normalized_type,
        release_tier=normalized_tier,
        update_frequency=sanitize_text(update_frequency) or "manual",
        validation_requirements=requirements,
        rollback_available=bool(rollback_available),
        signature_required=bool(signature_required),
        checksum_required=bool(checksum_required),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_update_channel(value: Any) -> UpdateChannelRecord:
    if isinstance(value, UpdateChannelRecord):
        return value
    if not isinstance(value, dict):
        return build_update_channel(
            channel_type="unknown",
            release_tier="unknown",
            advisory_notes=["invalid update channel generated from malformed input"],
        )
    try:
        return build_update_channel(
            channel_id=value.get("channel_id", ""),
            channel_name=value.get("channel_name", value.get("name", "Update channel")),
            channel_type=value.get("channel_type", value.get("type", "unknown")),
            release_tier=value.get("release_tier", "unknown"),
            update_frequency=value.get("update_frequency", "manual"),
            validation_requirements=value.get("validation_requirements")
            if isinstance(value.get("validation_requirements"), list)
            else None,
            rollback_available=value.get("rollback_available", True),
            signature_required=value.get("signature_required", True),
            checksum_required=value.get("checksum_required", True),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_update_channel(channel_type="unknown", advisory_notes=[str(exc)])


def summarize_update_channels(channels: Iterable[UpdateChannelRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_update_channel(channel).to_dict() for channel in list(channels or [])]
    type_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["channel_type"]] = type_counts.get(row["channel_type"], 0) + 1
        tier_counts[row["release_tier"]] = tier_counts.get(row["release_tier"], 0) + 1
    return {
        "channel_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "release_tier_counts": dict(sorted(tier_counts.items())),
        "signature_required_count": sum(1 for row in rows if row.get("signature_required")),
        "checksum_required_count": sum(1 for row in rows if row.get("checksum_required")),
        "rollback_available_count": sum(1 for row in rows if row.get("rollback_available")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **UPDATE_CHANNEL_SAFETY_FLAGS,
    }


def default_validation_requirements(*, signature_required: bool, checksum_required: bool) -> list[str]:
    requirements = ["version compatibility preview"]
    if checksum_required:
        requirements.append("checksum readiness preview")
    if signature_required:
        requirements.append("signature readiness preview")
    requirements.append("rollback preview")
    return requirements


def sanitize_update_identifier(value: Any) -> str:
    safe_value = str(value or "").strip().lower()
    safe_value = re.sub(r"[^a-z0-9._-]+", "-", safe_value)
    safe_value = re.sub(r"-{2,}", "-", safe_value).strip(".-_")
    return safe_value[:120]


def normalize_update_channel_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in UPDATE_CHANNEL_TYPES else "unknown"


def normalize_release_tier(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in RELEASE_TIERS else "unknown"


def deterministic_update_channel_json(record: UpdateChannelRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, UpdateChannelRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "RELEASE_TIERS",
    "UPDATE_CHANNEL_SAFETY_FLAGS",
    "UPDATE_CHANNEL_TYPES",
    "UpdateChannelRecord",
    "build_update_channel",
    "deterministic_update_channel_json",
    "normalize_release_tier",
    "normalize_update_channel",
    "normalize_update_channel_type",
    "sanitize_update_identifier",
    "summarize_update_channels",
]
