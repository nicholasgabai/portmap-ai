from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


UPDATE_TARGETS = {
    "release_manifest",
    "package_digest",
    "signature_status",
    "migration_manifest",
    "compatibility_manifest",
    "rollback_manifest",
}
UPDATE_VERIFICATION_STATES = {"verified", "degraded", "blocked", "unavailable", "unknown"}
UPDATE_DIGEST_STATES = UPDATE_VERIFICATION_STATES
UPDATE_SIGNATURE_STATES = UPDATE_VERIFICATION_STATES
UPDATE_COMPATIBILITY_STATES = UPDATE_VERIFICATION_STATES

_VERSION_PATTERN = re.compile(r"^(?:[0-9]+(?:\.[0-9]+){0,3}|unknown|fixture-[A-Za-z0-9_.-]+)$")


class UpdateVerificationError(ValueError):
    """Raised when a secure update verification record is malformed."""


@dataclass(frozen=True, slots=True)
class UpdateVerificationRecord:
    update_target: str
    current_version: str
    target_version: str
    verification_state: str
    digest_state: str
    signature_state: str
    compatibility_state: str
    migration_required: bool
    rollback_available: bool
    operator_action_required: bool
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.update_target, UPDATE_TARGETS, "update_target")
        _validate_version(self.current_version, "current_version")
        _validate_version(self.target_version, "target_version")
        _validate_choice(self.verification_state, UPDATE_VERIFICATION_STATES, "verification_state")
        _validate_choice(self.digest_state, UPDATE_DIGEST_STATES, "digest_state")
        _validate_choice(self.signature_state, UPDATE_SIGNATURE_STATES, "signature_state")
        _validate_choice(self.compatibility_state, UPDATE_COMPATIBILITY_STATES, "compatibility_state")
        if not isinstance(self.migration_required, bool):
            raise UpdateVerificationError("migration_required must be a boolean")
        if not isinstance(self.rollback_available, bool):
            raise UpdateVerificationError("rollback_available must be a boolean")
        if not isinstance(self.operator_action_required, bool):
            raise UpdateVerificationError("operator_action_required must be a boolean")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise UpdateVerificationError("advisory_notes must be a tuple of strings")
        for note in self.advisory_notes:
            if not note.strip() or _contains_private_or_remote_identifier(note):
                raise UpdateVerificationError("advisory_notes must be sanitized non-empty strings")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def preview_only(self) -> bool:
        return True

    @property
    def update_downloaded(self) -> bool:
        return False

    @property
    def installer_executed(self) -> bool:
        return False

    @property
    def file_modified(self) -> bool:
        return False

    @property
    def migration_executed(self) -> bool:
        return False

    @property
    def private_key_material_present(self) -> bool:
        return False

    @property
    def signing_material_generated(self) -> bool:
        return False

    @property
    def live_signature_trust_enabled(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "update_target": self.update_target,
            "current_version": self.current_version,
            "target_version": self.target_version,
            "verification_state": self.verification_state,
            "digest_state": self.digest_state,
            "signature_state": self.signature_state,
            "compatibility_state": self.compatibility_state,
            "migration_required": self.migration_required,
            "rollback_available": self.rollback_available,
            "operator_action_required": self.operator_action_required,
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "preview_only": self.preview_only,
            "update_downloaded": self.update_downloaded,
            "installer_executed": self.installer_executed,
            "file_modified": self.file_modified,
            "migration_executed": self.migration_executed,
            "private_key_material_present": self.private_key_material_present,
            "signing_material_generated": self.signing_material_generated,
            "live_signature_trust_enabled": self.live_signature_trust_enabled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "UpdateVerificationRecord":
        if not isinstance(payload, dict):
            raise UpdateVerificationError("update verification record must be an object")
        allowed = {
            "update_target",
            "current_version",
            "target_version",
            "verification_state",
            "digest_state",
            "signature_state",
            "compatibility_state",
            "migration_required",
            "rollback_available",
            "operator_action_required",
            "advisory_notes",
            "export_safe",
            "preview_only",
            "update_downloaded",
            "installer_executed",
            "file_modified",
            "migration_executed",
            "private_key_material_present",
            "signing_material_generated",
            "live_signature_trust_enabled",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise UpdateVerificationError(f"unknown update verification fields: {', '.join(unknown)}")
        _reject_true(payload, "update_downloaded", "update verification records cannot download updates")
        _reject_true(payload, "installer_executed", "update verification records cannot execute installers")
        _reject_true(payload, "file_modified", "update verification records cannot modify files")
        _reject_true(payload, "migration_executed", "update verification records cannot execute migrations")
        _reject_true(payload, "private_key_material_present", "update verification records cannot contain private keys")
        _reject_true(payload, "signing_material_generated", "update verification records cannot generate signing material")
        _reject_true(payload, "live_signature_trust_enabled", "update verification records cannot enable live signature trust")
        data = {key: payload[key] for key in (
            "update_target",
            "current_version",
            "target_version",
            "verification_state",
            "digest_state",
            "signature_state",
            "compatibility_state",
            "migration_required",
            "rollback_available",
            "operator_action_required",
            "advisory_notes",
        ) if key in payload}
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise UpdateVerificationError(f"malformed update verification record: {exc}") from exc


def create_update_verification_record(
    update_target: str,
    *,
    current_version: str = "unknown",
    target_version: str = "unknown",
    verification_state: str = "unknown",
    digest_state: str | None = None,
    signature_state: str | None = None,
    compatibility_state: str | None = None,
    migration_required: bool | None = None,
    rollback_available: bool | None = None,
    advisory_notes: tuple[str, ...] | None = None,
) -> UpdateVerificationRecord:
    _validate_choice(update_target, UPDATE_TARGETS, "update_target")
    _validate_choice(verification_state, UPDATE_VERIFICATION_STATES, "verification_state")
    digest = digest_state or _default_digest_state(update_target, verification_state)
    signature = signature_state or _default_signature_state(update_target, verification_state)
    compatibility = compatibility_state or _default_compatibility_state(update_target, verification_state)
    _validate_choice(digest, UPDATE_DIGEST_STATES, "digest_state")
    _validate_choice(signature, UPDATE_SIGNATURE_STATES, "signature_state")
    _validate_choice(compatibility, UPDATE_COMPATIBILITY_STATES, "compatibility_state")
    migration = _default_migration_required(update_target, verification_state) if migration_required is None else migration_required
    rollback = _default_rollback_available(update_target, verification_state) if rollback_available is None else rollback_available
    action_required = verification_state in {"degraded", "blocked", "unavailable", "unknown"} or compatibility in {"degraded", "blocked", "unavailable"}
    return UpdateVerificationRecord(
        update_target=update_target,
        current_version=current_version,
        target_version=target_version,
        verification_state=verification_state,
        digest_state=digest,
        signature_state=signature,
        compatibility_state=compatibility,
        migration_required=migration,
        rollback_available=rollback,
        operator_action_required=action_required,
        advisory_notes=advisory_notes or _default_notes(update_target, verification_state),
    )


def summarize_update_verification(records: list[UpdateVerificationRecord | dict[str, Any]] | None = None) -> dict[str, Any]:
    verification_records = _coerce_records(records) if records is not None else [
        create_update_verification_record(target) for target in sorted(UPDATE_TARGETS)
    ]
    by_state = {state: 0 for state in sorted(UPDATE_VERIFICATION_STATES)}
    for record in verification_records:
        by_state[record.verification_state] += 1
    return {
        "summary_type": "secure_update_verification_readiness",
        "record_count": len(verification_records),
        "by_verification_state": by_state,
        "migration_required_count": sum(1 for record in verification_records if record.migration_required),
        "rollback_available_count": sum(1 for record in verification_records if record.rollback_available),
        "operator_action_required": any(record.operator_action_required for record in verification_records),
        "records": [record.to_dict() for record in verification_records],
        "export_safe": True,
        "preview_only": True,
        "update_downloaded": False,
        "installer_executed": False,
        "file_modified": False,
        "migration_executed": False,
        "private_key_material_present": False,
        "signing_material_generated": False,
        "live_signature_trust_enabled": False,
    }


def _coerce_records(records: list[UpdateVerificationRecord | dict[str, Any]]) -> list[UpdateVerificationRecord]:
    coerced: list[UpdateVerificationRecord] = []
    for record in records:
        coerced.append(record if isinstance(record, UpdateVerificationRecord) else UpdateVerificationRecord.from_dict(record))
    return coerced


def _default_digest_state(update_target: str, verification_state: str) -> str:
    if update_target in {"package_digest", "release_manifest"}:
        return verification_state
    if update_target == "signature_status":
        return "degraded" if verification_state == "verified" else verification_state
    return "unknown" if verification_state == "verified" else verification_state


def _default_signature_state(update_target: str, verification_state: str) -> str:
    if update_target == "signature_status":
        return verification_state
    if update_target in {"release_manifest", "rollback_manifest"}:
        return "degraded" if verification_state == "verified" else verification_state
    return "unknown" if verification_state == "verified" else verification_state


def _default_compatibility_state(update_target: str, verification_state: str) -> str:
    if update_target == "compatibility_manifest":
        return verification_state
    if verification_state == "verified":
        return "verified"
    return verification_state


def _default_migration_required(update_target: str, verification_state: str) -> bool:
    return update_target == "migration_manifest" and verification_state in {"verified", "degraded", "unknown"}


def _default_rollback_available(update_target: str, verification_state: str) -> bool:
    return update_target == "rollback_manifest" and verification_state in {"verified", "degraded"}


def _default_notes(update_target: str, verification_state: str) -> tuple[str, ...]:
    notes = [f"{update_target} verification is modeled as a preview record"]
    if verification_state == "verified":
        notes.append("verified state is fixture-safe and does not enable update execution")
    if verification_state in {"degraded", "blocked", "unavailable", "unknown"}:
        notes.append("operator review is required before future update execution")
    return tuple(notes)


def _validate_version(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _VERSION_PATTERN.match(value):
        raise UpdateVerificationError(f"{field_name} must be a sanitized version label")


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise UpdateVerificationError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise UpdateVerificationError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _contains_private_or_remote_identifier(value: str) -> bool:
    stripped = value.strip()
    return (
        stripped.startswith("/")
        or stripped.startswith("~")
        or ":\\" in stripped
        or ("\\" + "Users" + "\\") in stripped
        or ("/" + "Users" + "/") in stripped
        or "://" in stripped
        or "@" in stripped
    )
