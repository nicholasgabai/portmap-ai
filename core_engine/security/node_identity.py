from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5


LOGICAL_NODE_CLASSES = {"orchestrator", "master", "worker", "edge"}
ENROLLMENT_IDENTITY_STATES = {"pending", "trusted", "rejected", "rotated", "expired", "unknown"}
TRUST_IDENTITY_STATES = {"trusted", "degraded", "untrusted", "unknown"}
IDENTITY_VERSION = "secure-node-identity-v1"


class SecureNodeIdentityError(ValueError):
    """Raised when a secure logical node identity is malformed."""


@dataclass(frozen=True, slots=True)
class SecureNodeIdentity:
    node_uuid: str
    logical_node_class: str
    enrollment_state: str
    trust_state: str
    identity_version: str
    issued_timestamp: str
    rotation_supported: bool = True

    def __post_init__(self) -> None:
        _validate_uuid(self.node_uuid)
        _validate_choice(self.logical_node_class, LOGICAL_NODE_CLASSES, "logical_node_class")
        _validate_choice(self.enrollment_state, ENROLLMENT_IDENTITY_STATES, "enrollment_state")
        _validate_choice(self.trust_state, TRUST_IDENTITY_STATES, "trust_state")
        _required_str(self.identity_version, "identity_version")
        _required_str(self.issued_timestamp, "issued_timestamp")
        if not isinstance(self.rotation_supported, bool):
            raise SecureNodeIdentityError("rotation_supported must be a boolean")

    @property
    def local_first(self) -> bool:
        return True

    @property
    def advisory_only(self) -> bool:
        return True

    @property
    def hardware_identifiers_stored(self) -> bool:
        return False

    @property
    def plaintext_secrets_stored(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_uuid": self.node_uuid,
            "logical_node_class": self.logical_node_class,
            "enrollment_state": self.enrollment_state,
            "trust_state": self.trust_state,
            "identity_version": self.identity_version,
            "issued_timestamp": self.issued_timestamp,
            "rotation_supported": self.rotation_supported,
            "local_first": self.local_first,
            "advisory_only": self.advisory_only,
            "hardware_identifiers_stored": self.hardware_identifiers_stored,
            "plaintext_secrets_stored": self.plaintext_secrets_stored,
            "raw_hardware_identifiers_used": False,
            "automatic_privileged_enrollment": False,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecureNodeIdentity":
        if not isinstance(payload, dict):
            raise SecureNodeIdentityError("secure node identity must be an object")
        allowed = {
            "node_uuid",
            "logical_node_class",
            "enrollment_state",
            "trust_state",
            "identity_version",
            "issued_timestamp",
            "rotation_supported",
            "local_first",
            "advisory_only",
            "hardware_identifiers_stored",
            "plaintext_secrets_stored",
            "raw_hardware_identifiers_used",
            "automatic_privileged_enrollment",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise SecureNodeIdentityError(f"unknown secure node identity fields: {', '.join(unknown)}")
        if payload.get("hardware_identifiers_stored") is True:
            raise SecureNodeIdentityError("secure node identity cannot store hardware identifiers")
        if payload.get("plaintext_secrets_stored") is True:
            raise SecureNodeIdentityError("secure node identity cannot store plaintext secrets")
        data = {key: payload[key] for key in (
            "node_uuid",
            "logical_node_class",
            "enrollment_state",
            "trust_state",
            "identity_version",
            "issued_timestamp",
            "rotation_supported",
        ) if key in payload}
        try:
            return cls(**data)
        except TypeError as exc:
            raise SecureNodeIdentityError(f"malformed secure node identity: {exc}") from exc


def create_secure_node_identity(
    *,
    installation_reference: str,
    logical_node_class: str,
    enrollment_state: str = "pending",
    trust_state: str = "unknown",
    issued_timestamp: str | None = None,
    identity_version: str = IDENTITY_VERSION,
    rotation_supported: bool = True,
) -> SecureNodeIdentity:
    """Create a deterministic logical identity from an installation-scoped reference.

    The installation reference is hashed before UUID generation so it is never
    reflected in export dictionaries. Callers should pass an existing local
    installation ID, not a hardware identifier.
    """

    _required_str(installation_reference, "installation_reference")
    _validate_choice(logical_node_class, LOGICAL_NODE_CLASSES, "logical_node_class")
    seed_digest = sha256(
        json.dumps(
            {
                "installation_reference": installation_reference,
                "logical_node_class": logical_node_class,
                "identity_version": identity_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    node_uuid = str(uuid5(NAMESPACE_URL, f"portmap-ai:{identity_version}:{seed_digest}"))
    return SecureNodeIdentity(
        node_uuid=node_uuid,
        logical_node_class=logical_node_class,
        enrollment_state=enrollment_state,
        trust_state=trust_state,
        identity_version=identity_version,
        issued_timestamp=issued_timestamp or _now(),
        rotation_supported=rotation_supported,
    )


def identity_regeneration_preview(
    identity: SecureNodeIdentity | dict[str, Any],
    *,
    reason: str = "operator_requested",
    requested_timestamp: str | None = None,
) -> dict[str, Any]:
    current = _coerce_identity(identity)
    preview_uuid = _preview_uuid(current, "regenerate", reason)
    return {
        "preview_type": "identity_regeneration",
        "current_node_uuid": current.node_uuid,
        "preview_node_uuid": preview_uuid,
        "logical_node_class": current.logical_node_class,
        "reason": _required_str(reason, "reason"),
        "requested_timestamp": requested_timestamp or _now(),
        "requires_operator_approval": True,
        "dry_run_only": True,
        "destructive_action": False,
        "plaintext_secrets_stored": False,
        "hardware_identifiers_stored": False,
    }


def identity_rotation_preview(
    identity: SecureNodeIdentity | dict[str, Any],
    *,
    target_version: str | None = None,
    requested_timestamp: str | None = None,
) -> dict[str, Any]:
    current = _coerce_identity(identity)
    version = target_version or current.identity_version
    preview_uuid = _preview_uuid(current, "rotate", version)
    return {
        "preview_type": "identity_rotation",
        "current_node_uuid": current.node_uuid,
        "preview_node_uuid": preview_uuid,
        "logical_node_class": current.logical_node_class,
        "current_identity_version": current.identity_version,
        "target_identity_version": version,
        "rotation_supported": current.rotation_supported,
        "requested_timestamp": requested_timestamp or _now(),
        "requires_operator_approval": True,
        "dry_run_only": True,
        "destructive_action": False,
        "plaintext_secrets_stored": False,
        "hardware_identifiers_stored": False,
    }


def _coerce_identity(identity: SecureNodeIdentity | dict[str, Any]) -> SecureNodeIdentity:
    if isinstance(identity, SecureNodeIdentity):
        return identity
    if isinstance(identity, dict):
        return SecureNodeIdentity.from_dict(identity)
    raise SecureNodeIdentityError("identity must be a SecureNodeIdentity or dictionary")


def _preview_uuid(identity: SecureNodeIdentity, action: str, salt: str) -> str:
    material = f"portmap-ai:{identity.node_uuid}:{identity.identity_version}:{action}:{salt}"
    return str(uuid5(NAMESPACE_URL, material))


def _validate_uuid(value: str) -> None:
    _required_str(value, "node_uuid")
    try:
        UUID(value)
    except ValueError as exc:
        raise SecureNodeIdentityError("node_uuid must be a valid UUID") from exc


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise SecureNodeIdentityError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SecureNodeIdentityError(f"{field_name} must be a non-empty string")
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
