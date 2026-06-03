from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


ROLLBACK_NAMES = {
    "config_rollback",
    "package_rollback",
    "migration_rollback",
    "identity_rollback",
    "trust_chain_rollback",
    "history_store_rollback",
}
ROLLBACK_TYPES = {"configuration", "package", "migration", "identity", "trust_chain", "history_store"}
ROLLBACK_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}

_ROLLBACK_TYPE_BY_NAME = {
    "config_rollback": "configuration",
    "package_rollback": "package",
    "migration_rollback": "migration",
    "identity_rollback": "identity",
    "trust_chain_rollback": "trust_chain",
    "history_store_rollback": "history_store",
}


class RollbackPlanError(ValueError):
    """Raised when a rollback preview record is malformed."""


@dataclass(frozen=True, slots=True)
class RollbackPreviewRecord:
    rollback_name: str
    rollback_type: str
    rollback_state: str
    backup_required: bool
    compatibility_required: bool
    operator_steps: tuple[str, ...]
    validation_steps: tuple[str, ...]
    risk_summary: str
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.rollback_name, ROLLBACK_NAMES, "rollback_name")
        _validate_choice(self.rollback_type, ROLLBACK_TYPES, "rollback_type")
        expected_type = _ROLLBACK_TYPE_BY_NAME[self.rollback_name]
        if self.rollback_type != expected_type:
            raise RollbackPlanError(f"rollback_type for {self.rollback_name} must be {expected_type}")
        _validate_choice(self.rollback_state, ROLLBACK_STATES, "rollback_state")
        if not isinstance(self.backup_required, bool):
            raise RollbackPlanError("backup_required must be a boolean")
        if not isinstance(self.compatibility_required, bool):
            raise RollbackPlanError("compatibility_required must be a boolean")
        _validate_text_tuple(self.operator_steps, "operator_steps")
        _validate_text_tuple(self.validation_steps, "validation_steps")
        if not isinstance(self.risk_summary, str) or not self.risk_summary.strip() or _contains_private_or_remote_identifier(self.risk_summary):
            raise RollbackPlanError("risk_summary must be a sanitized non-empty string")
        if self.preview_only is not True:
            raise RollbackPlanError("rollback records must remain preview-only")
        if self.destructive_action is not False:
            raise RollbackPlanError("rollback records cannot be destructive")
        _validate_text_tuple(self.advisory_notes, "advisory_notes")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def restore_executed(self) -> bool:
        return False

    @property
    def file_deleted(self) -> bool:
        return False

    @property
    def file_overwritten(self) -> bool:
        return False

    @property
    def config_modified(self) -> bool:
        return False

    @property
    def migration_executed(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "rollback_name": self.rollback_name,
            "rollback_type": self.rollback_type,
            "rollback_state": self.rollback_state,
            "backup_required": self.backup_required,
            "compatibility_required": self.compatibility_required,
            "operator_steps": list(self.operator_steps),
            "validation_steps": list(self.validation_steps),
            "risk_summary": self.risk_summary,
            "preview_only": self.preview_only,
            "destructive_action": self.destructive_action,
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "restore_executed": self.restore_executed,
            "file_deleted": self.file_deleted,
            "file_overwritten": self.file_overwritten,
            "config_modified": self.config_modified,
            "migration_executed": self.migration_executed,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RollbackPreviewRecord":
        if not isinstance(payload, dict):
            raise RollbackPlanError("rollback preview record must be an object")
        allowed = {
            "rollback_name",
            "rollback_type",
            "rollback_state",
            "backup_required",
            "compatibility_required",
            "operator_steps",
            "validation_steps",
            "risk_summary",
            "preview_only",
            "destructive_action",
            "advisory_notes",
            "export_safe",
            "restore_executed",
            "file_deleted",
            "file_overwritten",
            "config_modified",
            "migration_executed",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise RollbackPlanError(f"unknown rollback preview fields: {', '.join(unknown)}")
        _reject_true(payload, "restore_executed", "rollback previews cannot restore files")
        _reject_true(payload, "file_deleted", "rollback previews cannot delete files")
        _reject_true(payload, "file_overwritten", "rollback previews cannot overwrite files")
        _reject_true(payload, "config_modified", "rollback previews cannot modify configuration")
        _reject_true(payload, "migration_executed", "rollback previews cannot execute migrations")
        data = {key: payload[key] for key in (
            "rollback_name",
            "rollback_type",
            "rollback_state",
            "backup_required",
            "compatibility_required",
            "operator_steps",
            "validation_steps",
            "risk_summary",
            "preview_only",
            "destructive_action",
            "advisory_notes",
        ) if key in payload}
        for key in ("operator_steps", "validation_steps", "advisory_notes"):
            if key in data:
                data[key] = tuple(data[key])
        try:
            return cls(**data)
        except TypeError as exc:
            raise RollbackPlanError(f"malformed rollback preview record: {exc}") from exc


def create_rollback_preview_record(
    rollback_name: str,
    *,
    rollback_state: str = "unknown",
    backup_required: bool | None = None,
    compatibility_required: bool | None = None,
    operator_steps: tuple[str, ...] | None = None,
    validation_steps: tuple[str, ...] | None = None,
    risk_summary: str | None = None,
    advisory_notes: tuple[str, ...] | None = None,
) -> RollbackPreviewRecord:
    _validate_choice(rollback_name, ROLLBACK_NAMES, "rollback_name")
    _validate_choice(rollback_state, ROLLBACK_STATES, "rollback_state")
    return RollbackPreviewRecord(
        rollback_name=rollback_name,
        rollback_type=_ROLLBACK_TYPE_BY_NAME[rollback_name],
        rollback_state=rollback_state,
        backup_required=_default_backup_required(rollback_name) if backup_required is None else backup_required,
        compatibility_required=_default_compatibility_required(rollback_name) if compatibility_required is None else compatibility_required,
        operator_steps=operator_steps or _default_operator_steps(rollback_name),
        validation_steps=validation_steps or _default_validation_steps(rollback_name),
        risk_summary=risk_summary or _default_risk_summary(rollback_name, rollback_state),
        advisory_notes=advisory_notes or _default_notes(rollback_name),
    )


def summarize_rollback_previews(records: list[RollbackPreviewRecord | dict[str, Any]] | None = None) -> dict[str, Any]:
    rollback_records = _coerce_records(records) if records is not None else [
        create_rollback_preview_record(name) for name in sorted(ROLLBACK_NAMES)
    ]
    by_state = {state: 0 for state in sorted(ROLLBACK_STATES)}
    for record in rollback_records:
        by_state[record.rollback_state] += 1
    return {
        "summary_type": "secure_rollback_preview_readiness",
        "record_count": len(rollback_records),
        "by_rollback_state": by_state,
        "backup_required_count": sum(1 for record in rollback_records if record.backup_required),
        "compatibility_required_count": sum(1 for record in rollback_records if record.compatibility_required),
        "records": [record.to_dict() for record in rollback_records],
        "export_safe": True,
        "preview_only": True,
        "destructive_action": False,
        "restore_executed": False,
        "file_deleted": False,
        "file_overwritten": False,
        "config_modified": False,
        "migration_executed": False,
    }


def _coerce_records(records: list[RollbackPreviewRecord | dict[str, Any]]) -> list[RollbackPreviewRecord]:
    coerced: list[RollbackPreviewRecord] = []
    for record in records:
        coerced.append(record if isinstance(record, RollbackPreviewRecord) else RollbackPreviewRecord.from_dict(record))
    return coerced


def _default_backup_required(rollback_name: str) -> bool:
    return rollback_name in {"config_rollback", "package_rollback", "migration_rollback", "history_store_rollback"}


def _default_compatibility_required(rollback_name: str) -> bool:
    return rollback_name in {"package_rollback", "migration_rollback", "identity_rollback", "trust_chain_rollback"}


def _default_operator_steps(rollback_name: str) -> tuple[str, ...]:
    return (
        f"review {rollback_name} preview before any future restore workflow",
        "confirm operator-approved backup references are available",
    )


def _default_validation_steps(rollback_name: str) -> tuple[str, ...]:
    return (
        f"validate {rollback_name} compatibility in dry-run records",
        "confirm no files are restored, deleted, or overwritten in this phase",
    )


def _default_risk_summary(rollback_name: str, rollback_state: str) -> str:
    if rollback_state == "ready":
        return f"{rollback_name} is ready as a preview and still requires explicit operator approval"
    if rollback_state == "blocked":
        return f"{rollback_name} is blocked until backup and compatibility issues are resolved"
    return f"{rollback_name} requires operator review before future rollback execution"


def _default_notes(rollback_name: str) -> tuple[str, ...]:
    return (
        f"{rollback_name} is modeled as a rollback preview only",
        "no restore, delete, overwrite, config change, or migration is executed",
    )


def _validate_text_tuple(value: tuple[str, ...], field_name: str) -> None:
    if not isinstance(value, tuple) or not value:
        raise RollbackPlanError(f"{field_name} must be a non-empty tuple")
    for item in value:
        if not isinstance(item, str) or not item.strip() or _contains_private_or_remote_identifier(item):
            raise RollbackPlanError(f"{field_name} entries must be sanitized non-empty strings")


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise RollbackPlanError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise RollbackPlanError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


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
