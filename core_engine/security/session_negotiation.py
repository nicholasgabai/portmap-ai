from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .transport_security import TRANSPORT_PROFILE_NAMES, TRANSPORT_ROLES, TransportSecurityError, create_transport_security_profile


NEGOTIATION_TRUST_STATES = {"trusted", "degraded", "untrusted", "unknown"}
ROLE_PAIRS = {
    ("orchestrator", "master"),
    ("orchestrator", "worker"),
    ("master", "worker"),
    ("edge", "orchestrator"),
}


class SessionNegotiationError(ValueError):
    """Raised when a session negotiation preview is malformed."""


@dataclass(frozen=True, slots=True)
class SessionNegotiationPreview:
    session_id: str
    source_role: str
    target_role: str
    requested_transport: str
    negotiated_transport: str
    encryption_required: bool
    mutual_auth_required: bool
    downgrade_detected: bool
    downgrade_reason: str
    trust_state: str
    operator_action_required: bool
    dry_run_only: bool = True

    def __post_init__(self) -> None:
        _required_str(self.session_id, "session_id")
        _validate_role(self.source_role, "source_role")
        _validate_role(self.target_role, "target_role")
        if (self.source_role, self.target_role) not in ROLE_PAIRS:
            raise SessionNegotiationError("unsupported orchestration role pair")
        _validate_transport(self.requested_transport, "requested_transport")
        _validate_transport(self.negotiated_transport, "negotiated_transport")
        if not isinstance(self.encryption_required, bool):
            raise SessionNegotiationError("encryption_required must be a boolean")
        if not isinstance(self.mutual_auth_required, bool):
            raise SessionNegotiationError("mutual_auth_required must be a boolean")
        if not isinstance(self.downgrade_detected, bool):
            raise SessionNegotiationError("downgrade_detected must be a boolean")
        if not isinstance(self.downgrade_reason, str):
            raise SessionNegotiationError("downgrade_reason must be a string")
        if not isinstance(self.trust_state, str) or self.trust_state not in NEGOTIATION_TRUST_STATES:
            raise SessionNegotiationError(
                f"trust_state must be one of: {', '.join(sorted(NEGOTIATION_TRUST_STATES))}"
            )
        if not isinstance(self.operator_action_required, bool):
            raise SessionNegotiationError("operator_action_required must be a boolean")
        if self.dry_run_only is not True:
            raise SessionNegotiationError("session negotiation previews must remain dry-run only")

    @property
    def credential_exchange_performed(self) -> bool:
        return False

    @property
    def mtls_handshake_performed(self) -> bool:
        return False

    @property
    def network_listener_changed(self) -> bool:
        return False

    @property
    def export_safe(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source_role": self.source_role,
            "target_role": self.target_role,
            "requested_transport": self.requested_transport,
            "negotiated_transport": self.negotiated_transport,
            "encryption_required": self.encryption_required,
            "mutual_auth_required": self.mutual_auth_required,
            "downgrade_detected": self.downgrade_detected,
            "downgrade_reason": self.downgrade_reason,
            "trust_state": self.trust_state,
            "operator_action_required": self.operator_action_required,
            "dry_run_only": self.dry_run_only,
            "credential_exchange_performed": self.credential_exchange_performed,
            "mtls_handshake_performed": self.mtls_handshake_performed,
            "network_listener_changed": self.network_listener_changed,
            "export_safe": self.export_safe,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SessionNegotiationPreview":
        if not isinstance(payload, dict):
            raise SessionNegotiationError("session negotiation preview must be an object")
        allowed = {
            "session_id",
            "source_role",
            "target_role",
            "requested_transport",
            "negotiated_transport",
            "encryption_required",
            "mutual_auth_required",
            "downgrade_detected",
            "downgrade_reason",
            "trust_state",
            "operator_action_required",
            "dry_run_only",
            "credential_exchange_performed",
            "mtls_handshake_performed",
            "network_listener_changed",
            "export_safe",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise SessionNegotiationError(f"unknown session negotiation fields: {', '.join(unknown)}")
        if payload.get("credential_exchange_performed") is True:
            raise SessionNegotiationError("session negotiation preview cannot perform credential exchange")
        if payload.get("mtls_handshake_performed") is True:
            raise SessionNegotiationError("session negotiation preview cannot perform mTLS handshakes")
        if payload.get("network_listener_changed") is True:
            raise SessionNegotiationError("session negotiation preview cannot change network listeners")
        data = {key: payload[key] for key in (
            "session_id",
            "source_role",
            "target_role",
            "requested_transport",
            "negotiated_transport",
            "encryption_required",
            "mutual_auth_required",
            "downgrade_detected",
            "downgrade_reason",
            "trust_state",
            "operator_action_required",
            "dry_run_only",
        ) if key in payload}
        try:
            return cls(**data)
        except TypeError as exc:
            raise SessionNegotiationError(f"malformed session negotiation preview: {exc}") from exc


def create_session_negotiation_preview(
    *,
    source_role: str,
    target_role: str,
    requested_transport: str,
    negotiated_transport: str | None = None,
    trust_state: str = "unknown",
) -> SessionNegotiationPreview:
    _validate_role(source_role, "source_role")
    _validate_role(target_role, "target_role")
    if (source_role, target_role) not in ROLE_PAIRS:
        raise SessionNegotiationError("unsupported orchestration role pair")
    requested = _profile_name(requested_transport)
    negotiated = _profile_name(negotiated_transport or requested_transport)
    if trust_state not in NEGOTIATION_TRUST_STATES:
        raise SessionNegotiationError(f"trust_state must be one of: {', '.join(sorted(NEGOTIATION_TRUST_STATES))}")

    requested_profile = create_transport_security_profile(requested)
    negotiated_profile = create_transport_security_profile(negotiated)
    downgrade_detected = _transport_rank(negotiated) < _transport_rank(requested)
    downgrade_reason = ""
    if downgrade_detected:
        downgrade_reason = negotiated_profile.downgrade_warning or "negotiated transport is weaker than requested transport"
    encryption_required = requested_profile.encryption_state == "required" or requested in {
        "mtls_ready",
        "pinned_cert_ready",
        "production_required",
    }
    mutual_auth_required = requested_profile.authentication_state in {"mutual_auth_ready", "required"}
    operator_action_required = downgrade_detected or trust_state in {"degraded", "untrusted", "unknown"}
    return SessionNegotiationPreview(
        session_id=_session_id(source_role, target_role, requested, negotiated, trust_state),
        source_role=source_role,
        target_role=target_role,
        requested_transport=requested,
        negotiated_transport=negotiated,
        encryption_required=encryption_required,
        mutual_auth_required=mutual_auth_required,
        downgrade_detected=downgrade_detected,
        downgrade_reason=downgrade_reason,
        trust_state=trust_state,
        operator_action_required=operator_action_required,
    )


def summarize_session_negotiations(previews: list[SessionNegotiationPreview | dict[str, Any]]) -> dict[str, Any]:
    normalized = [_coerce_preview(item) for item in previews]
    return {
        "summary_type": "session_negotiation_previews",
        "preview_count": len(normalized),
        "downgrade_count": sum(1 for item in normalized if item.downgrade_detected),
        "operator_action_count": sum(1 for item in normalized if item.operator_action_required),
        "mutual_auth_required_count": sum(1 for item in normalized if item.mutual_auth_required),
        "previews": [item.to_dict() for item in normalized],
        "dry_run_only": True,
        "credential_exchange_performed": False,
        "mtls_handshake_performed": False,
        "network_listener_changed": False,
        "export_safe": True,
    }


def _coerce_preview(item: SessionNegotiationPreview | dict[str, Any]) -> SessionNegotiationPreview:
    if isinstance(item, SessionNegotiationPreview):
        return item
    if isinstance(item, dict):
        return SessionNegotiationPreview.from_dict(item)
    raise SessionNegotiationError("preview must be a SessionNegotiationPreview or dictionary")


def _profile_name(value: str) -> str:
    _validate_transport(value, "transport")
    return value


def _transport_rank(value: str) -> int:
    return {
        "plaintext_dev": 0,
        "tls_ready": 1,
        "mtls_ready": 2,
        "pinned_cert_ready": 3,
        "production_required": 4,
    }[value]


def _session_id(source_role: str, target_role: str, requested_transport: str, negotiated_transport: str, trust_state: str) -> str:
    digest = sha256(
        f"{source_role}:{target_role}:{requested_transport}:{negotiated_transport}:{trust_state}".encode("utf-8")
    ).hexdigest()[:16]
    return f"session-preview-{digest}"


def _validate_role(value: str, field_name: str) -> None:
    if not isinstance(value, str) or value not in TRANSPORT_ROLES:
        raise SessionNegotiationError(f"{field_name} must be one of: {', '.join(sorted(TRANSPORT_ROLES))}")


def _validate_transport(value: str, field_name: str) -> None:
    if not isinstance(value, str) or value not in TRANSPORT_PROFILE_NAMES:
        raise SessionNegotiationError(f"{field_name} must be one of: {', '.join(sorted(TRANSPORT_PROFILE_NAMES))}")


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SessionNegotiationError(f"{field_name} must be a non-empty string")
    return value
