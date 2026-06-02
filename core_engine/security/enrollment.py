from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from .node_identity import SecureNodeIdentity, SecureNodeIdentityError


ENROLLMENT_STATES = {"pending", "trusted", "rejected", "rotated", "expired"}
TRUST_LEVELS = {"none", "candidate", "trusted", "limited", "rejected"}
ENROLLMENT_METHODS = {"manual_preview", "signed_preview", "operator_import", "fixture"}


class SecureEnrollmentError(ValueError):
    """Raised when a worker enrollment preview is malformed."""


@dataclass(frozen=True, slots=True)
class WorkerEnrollmentPreview:
    enrollment_id: str
    node_identity_reference: str
    enrollment_state: str
    trust_level: str
    enrollment_method: str
    issued_timestamp: str
    expiration_preview: str
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _required_str(self.enrollment_id, "enrollment_id")
        _required_str(self.node_identity_reference, "node_identity_reference")
        _validate_choice(self.enrollment_state, ENROLLMENT_STATES, "enrollment_state")
        _validate_choice(self.trust_level, TRUST_LEVELS, "trust_level")
        _validate_choice(self.enrollment_method, ENROLLMENT_METHODS, "enrollment_method")
        _required_str(self.issued_timestamp, "issued_timestamp")
        _required_str(self.expiration_preview, "expiration_preview")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise SecureEnrollmentError("advisory_notes must be a tuple of strings")

    @property
    def advisory_only(self) -> bool:
        return True

    @property
    def credential_exchange_performed(self) -> bool:
        return False

    @property
    def privileged_registration_performed(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "enrollment_id": self.enrollment_id,
            "node_identity_reference": self.node_identity_reference,
            "enrollment_state": self.enrollment_state,
            "trust_level": self.trust_level,
            "enrollment_method": self.enrollment_method,
            "issued_timestamp": self.issued_timestamp,
            "expiration_preview": self.expiration_preview,
            "advisory_notes": list(self.advisory_notes),
            "advisory_only": self.advisory_only,
            "credential_exchange_performed": self.credential_exchange_performed,
            "privileged_registration_performed": self.privileged_registration_performed,
            "dry_run_only": True,
            "destructive_action": False,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "WorkerEnrollmentPreview":
        if not isinstance(payload, dict):
            raise SecureEnrollmentError("worker enrollment preview must be an object")
        allowed = {
            "enrollment_id",
            "node_identity_reference",
            "enrollment_state",
            "trust_level",
            "enrollment_method",
            "issued_timestamp",
            "expiration_preview",
            "advisory_notes",
            "advisory_only",
            "credential_exchange_performed",
            "privileged_registration_performed",
            "dry_run_only",
            "destructive_action",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise SecureEnrollmentError(f"unknown worker enrollment fields: {', '.join(unknown)}")
        if payload.get("credential_exchange_performed") is True:
            raise SecureEnrollmentError("worker enrollment preview cannot perform credential exchange")
        if payload.get("privileged_registration_performed") is True:
            raise SecureEnrollmentError("worker enrollment preview cannot perform privileged registration")
        data = {key: payload[key] for key in (
            "enrollment_id",
            "node_identity_reference",
            "enrollment_state",
            "trust_level",
            "enrollment_method",
            "issued_timestamp",
            "expiration_preview",
            "advisory_notes",
        ) if key in payload}
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise SecureEnrollmentError(f"malformed worker enrollment preview: {exc}") from exc


def create_worker_enrollment_preview(
    *,
    identity: SecureNodeIdentity | dict[str, Any],
    enrollment_state: str = "pending",
    trust_level: str = "candidate",
    enrollment_method: str = "manual_preview",
    issued_timestamp: str | None = None,
    expires_in_seconds: int = 86400,
    advisory_notes: list[str] | tuple[str, ...] | None = None,
) -> WorkerEnrollmentPreview:
    secure_identity = _coerce_identity(identity)
    issued = issued_timestamp or _now()
    if not isinstance(expires_in_seconds, int) or expires_in_seconds <= 0:
        raise SecureEnrollmentError("expires_in_seconds must be a positive integer")
    expiration = (_parse_iso(issued) + timedelta(seconds=expires_in_seconds)).isoformat()
    enrollment_id = _enrollment_id(secure_identity.node_uuid, issued, enrollment_method)
    return WorkerEnrollmentPreview(
        enrollment_id=enrollment_id,
        node_identity_reference=secure_identity.node_uuid,
        enrollment_state=enrollment_state,
        trust_level=trust_level,
        enrollment_method=enrollment_method,
        issued_timestamp=issued,
        expiration_preview=expiration,
        advisory_notes=tuple(advisory_notes or ("operator review required before trust changes",)),
    )


def _coerce_identity(identity: SecureNodeIdentity | dict[str, Any]) -> SecureNodeIdentity:
    if isinstance(identity, SecureNodeIdentity):
        return identity
    if isinstance(identity, dict):
        try:
            return SecureNodeIdentity.from_dict(identity)
        except SecureNodeIdentityError as exc:
            raise SecureEnrollmentError(str(exc)) from exc
    raise SecureEnrollmentError("identity must be a SecureNodeIdentity or dictionary")


def _enrollment_id(node_uuid: str, issued_timestamp: str, enrollment_method: str) -> str:
    digest = sha256(f"{node_uuid}:{issued_timestamp}:{enrollment_method}".encode("utf-8")).hexdigest()[:16]
    return f"enroll-{digest}"


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise SecureEnrollmentError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SecureEnrollmentError(f"{field_name} must be a non-empty string")
    return value


def _parse_iso(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise SecureEnrollmentError(f"invalid issued_timestamp: {value}") from exc


def _now() -> str:
    return datetime.now(UTC).isoformat()
