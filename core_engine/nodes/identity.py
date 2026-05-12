from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4


class NodeIdentityError(ValueError):
    """Raised when a local node identity is malformed."""


@dataclass(slots=True)
class NodeIdentity:
    node_id: str
    role: str
    created_at: str
    updated_at: str
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_identity_fields(self)
        expected = node_identity_fingerprint(self)
        if self.fingerprint and self.fingerprint != expected:
            raise NodeIdentityError("node identity fingerprint mismatch")
        self.fingerprint = expected

    @property
    def local_only(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "role": self.role,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "fingerprint": self.fingerprint,
            "metadata": dict(self.metadata),
            "local_only": self.local_only,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NodeIdentity":
        if not isinstance(payload, dict):
            raise NodeIdentityError("node identity must be an object")
        allowed = {"node_id", "role", "created_at", "updated_at", "fingerprint", "metadata", "local_only"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise NodeIdentityError(f"unknown node identity fields: {', '.join(unknown)}")
        if payload.get("local_only") is False:
            raise NodeIdentityError("node identity must remain local-only")
        data = {key: value for key, value in payload.items() if key != "local_only"}
        try:
            return cls(**data)
        except TypeError as exc:
            raise NodeIdentityError(f"malformed node identity: {exc}") from exc


def generate_node_id(prefix: str = "node") -> str:
    if not isinstance(prefix, str) or not prefix.strip():
        raise NodeIdentityError("node ID prefix must be a non-empty string")
    return f"{prefix}-{uuid4().hex[:16]}"


def create_node_identity(
    *,
    role: str,
    node_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    now: str | None = None,
) -> NodeIdentity:
    timestamp = now or _now()
    return NodeIdentity(
        node_id=node_id or generate_node_id(role),
        role=role,
        created_at=timestamp,
        updated_at=timestamp,
        metadata=metadata or {},
    )


def node_identity_fingerprint(identity: NodeIdentity | dict[str, Any]) -> str:
    payload = identity if isinstance(identity, dict) else {
        "node_id": identity.node_id,
        "role": identity.role,
        "created_at": identity.created_at,
    }
    material = {
        "node_id": _required_str(payload.get("node_id"), "node_id"),
        "role": _required_str(payload.get("role"), "role"),
        "created_at": _required_str(payload.get("created_at"), "created_at"),
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def save_node_identity(identity: NodeIdentity, path: str | Path, *, updated_at: str | None = None) -> None:
    if not isinstance(identity, NodeIdentity):
        raise NodeIdentityError("save_node_identity requires a NodeIdentity")
    if updated_at is not None:
        identity.updated_at = updated_at
        identity.fingerprint = node_identity_fingerprint(identity)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(identity.to_dict(), sort_keys=True, indent=2), encoding="utf-8")


def load_node_identity(path: str | Path) -> NodeIdentity:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise NodeIdentityError(f"invalid node identity JSON: {exc.msg}") from exc
    except OSError as exc:
        raise NodeIdentityError(f"unable to read node identity: {exc}") from exc
    return NodeIdentity.from_dict(payload)


def _validate_identity_fields(identity: NodeIdentity) -> None:
    _required_str(identity.node_id, "node_id")
    _required_str(identity.role, "role")
    _required_str(identity.created_at, "created_at")
    _required_str(identity.updated_at, "updated_at")
    if not isinstance(identity.metadata, dict):
        raise NodeIdentityError("metadata must be an object")


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NodeIdentityError(f"{field_name} must be a non-empty string")
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
