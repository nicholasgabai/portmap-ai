from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


TRUST_RELATIONSHIP_STATES = {"trusted", "degraded", "untrusted", "unknown"}
TRUST_NODE_ROLES = {"orchestrator", "master", "worker", "edge"}
VERIFICATION_MODES = {"manual_preview", "signed_summary_preview", "fixture", "unknown"}


class SecureTrustChainError(ValueError):
    """Raised when a secure trust relationship summary is malformed."""


@dataclass(frozen=True, slots=True)
class TrustRelationshipSummary:
    source_role: str
    destination_role: str
    trust_state: str
    trust_reason: str
    verification_mode: str
    rotation_ready: bool
    degraded_reason: str = ""

    def __post_init__(self) -> None:
        _validate_choice(self.source_role, TRUST_NODE_ROLES, "source_role")
        _validate_choice(self.destination_role, TRUST_NODE_ROLES, "destination_role")
        _validate_choice(self.trust_state, TRUST_RELATIONSHIP_STATES, "trust_state")
        _required_str(self.trust_reason, "trust_reason")
        _validate_choice(self.verification_mode, VERIFICATION_MODES, "verification_mode")
        if not isinstance(self.rotation_ready, bool):
            raise SecureTrustChainError("rotation_ready must be a boolean")
        if not isinstance(self.degraded_reason, str):
            raise SecureTrustChainError("degraded_reason must be a string")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def advisory_only(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_role": self.source_role,
            "destination_role": self.destination_role,
            "trust_state": self.trust_state,
            "trust_reason": self.trust_reason,
            "verification_mode": self.verification_mode,
            "rotation_ready": self.rotation_ready,
            "degraded_reason": self.degraded_reason,
            "export_safe": self.export_safe,
            "advisory_only": self.advisory_only,
            "credential_exchange_performed": False,
            "remote_enrollment_performed": False,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrustRelationshipSummary":
        if not isinstance(payload, dict):
            raise SecureTrustChainError("trust relationship summary must be an object")
        allowed = {
            "source_role",
            "destination_role",
            "trust_state",
            "trust_reason",
            "verification_mode",
            "rotation_ready",
            "degraded_reason",
            "export_safe",
            "advisory_only",
            "credential_exchange_performed",
            "remote_enrollment_performed",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise SecureTrustChainError(f"unknown trust relationship fields: {', '.join(unknown)}")
        if payload.get("credential_exchange_performed") is True:
            raise SecureTrustChainError("trust relationship summary cannot perform credential exchange")
        if payload.get("remote_enrollment_performed") is True:
            raise SecureTrustChainError("trust relationship summary cannot perform remote enrollment")
        data = {key: payload[key] for key in (
            "source_role",
            "destination_role",
            "trust_state",
            "trust_reason",
            "verification_mode",
            "rotation_ready",
            "degraded_reason",
        ) if key in payload}
        try:
            return cls(**data)
        except TypeError as exc:
            raise SecureTrustChainError(f"malformed trust relationship summary: {exc}") from exc


def create_trust_relationship_summary(
    *,
    source_role: str,
    destination_role: str,
    trust_state: str = "unknown",
    trust_reason: str = "operator review required",
    verification_mode: str = "manual_preview",
    rotation_ready: bool = False,
    degraded_reason: str = "",
) -> TrustRelationshipSummary:
    return TrustRelationshipSummary(
        source_role=source_role,
        destination_role=destination_role,
        trust_state=trust_state,
        trust_reason=trust_reason,
        verification_mode=verification_mode,
        rotation_ready=rotation_ready,
        degraded_reason=degraded_reason,
    )


def build_trust_chain_summary(
    relationships: list[TrustRelationshipSummary | dict[str, Any]],
    *,
    summary_id: str = "trust-chain-preview",
) -> dict[str, Any]:
    normalized = [_coerce_relationship(item) for item in relationships]
    counts = {state: 0 for state in sorted(TRUST_RELATIONSHIP_STATES)}
    for item in normalized:
        counts[item.trust_state] += 1
    if counts["untrusted"]:
        aggregate_state = "untrusted"
    elif counts["degraded"]:
        aggregate_state = "degraded"
    elif counts["unknown"]:
        aggregate_state = "unknown"
    else:
        aggregate_state = "trusted"
    return {
        "summary_id": _required_str(summary_id, "summary_id"),
        "aggregate_trust_state": aggregate_state,
        "relationship_count": len(normalized),
        "by_state": counts,
        "relationships": [item.to_dict() for item in normalized],
        "export_safe": True,
        "advisory_only": True,
        "credential_exchange_performed": False,
        "remote_enrollment_performed": False,
    }


def _coerce_relationship(item: TrustRelationshipSummary | dict[str, Any]) -> TrustRelationshipSummary:
    if isinstance(item, TrustRelationshipSummary):
        return item
    if isinstance(item, dict):
        return TrustRelationshipSummary.from_dict(item)
    raise SecureTrustChainError("relationship must be a TrustRelationshipSummary or dictionary")


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise SecureTrustChainError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SecureTrustChainError(f"{field_name} must be a non-empty string")
    return value
