from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


TRANSPORT_PROFILE_NAMES = {
    "plaintext_dev",
    "tls_ready",
    "mtls_ready",
    "pinned_cert_ready",
    "production_required",
}
TRANSPORT_STATES = {"unavailable", "degraded", "ready", "required"}
AUTHENTICATION_STATES = {"none", "server_authenticated", "mutual_auth_ready", "required"}
VERIFICATION_MODES = {"none", "ca_validation", "pinned_certificate", "manual_preview", "unknown"}
CERTIFICATE_MODES = {"none", "placeholder_reference", "operator_provided", "managed_preview"}
TRANSPORT_ROLES = {"orchestrator", "master", "worker", "edge"}


class TransportSecurityError(ValueError):
    """Raised when a transport security profile is malformed."""


@dataclass(frozen=True, slots=True)
class TransportSecurityProfile:
    profile_name: str
    encryption_state: str
    authentication_state: str
    verification_mode: str
    certificate_mode: str
    rotation_supported: bool
    downgrade_allowed: bool
    downgrade_warning: str
    supported_roles: tuple[str, ...]
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.profile_name, TRANSPORT_PROFILE_NAMES, "profile_name")
        _validate_choice(self.encryption_state, TRANSPORT_STATES, "encryption_state")
        _validate_choice(self.authentication_state, AUTHENTICATION_STATES, "authentication_state")
        _validate_choice(self.verification_mode, VERIFICATION_MODES, "verification_mode")
        _validate_choice(self.certificate_mode, CERTIFICATE_MODES, "certificate_mode")
        if not isinstance(self.rotation_supported, bool):
            raise TransportSecurityError("rotation_supported must be a boolean")
        if not isinstance(self.downgrade_allowed, bool):
            raise TransportSecurityError("downgrade_allowed must be a boolean")
        if not isinstance(self.downgrade_warning, str):
            raise TransportSecurityError("downgrade_warning must be a string")
        if not isinstance(self.supported_roles, tuple) or not self.supported_roles:
            raise TransportSecurityError("supported_roles must be a non-empty tuple")
        for role in self.supported_roles:
            _validate_choice(role, TRANSPORT_ROLES, "supported_roles")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise TransportSecurityError("advisory_notes must be a tuple of strings")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def dry_run_only(self) -> bool:
        return True

    @property
    def certificate_generated(self) -> bool:
        return False

    @property
    def private_key_material_present(self) -> bool:
        return False

    @property
    def network_listener_changed(self) -> bool:
        return False

    @property
    def live_auth_exchange_performed(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "encryption_state": self.encryption_state,
            "authentication_state": self.authentication_state,
            "verification_mode": self.verification_mode,
            "certificate_mode": self.certificate_mode,
            "rotation_supported": self.rotation_supported,
            "downgrade_allowed": self.downgrade_allowed,
            "downgrade_warning": self.downgrade_warning,
            "supported_roles": list(self.supported_roles),
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "dry_run_only": self.dry_run_only,
            "certificate_generated": self.certificate_generated,
            "private_key_material_present": self.private_key_material_present,
            "network_listener_changed": self.network_listener_changed,
            "live_auth_exchange_performed": self.live_auth_exchange_performed,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TransportSecurityProfile":
        if not isinstance(payload, dict):
            raise TransportSecurityError("transport security profile must be an object")
        allowed = {
            "profile_name",
            "encryption_state",
            "authentication_state",
            "verification_mode",
            "certificate_mode",
            "rotation_supported",
            "downgrade_allowed",
            "downgrade_warning",
            "supported_roles",
            "advisory_notes",
            "export_safe",
            "dry_run_only",
            "certificate_generated",
            "private_key_material_present",
            "network_listener_changed",
            "live_auth_exchange_performed",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise TransportSecurityError(f"unknown transport security fields: {', '.join(unknown)}")
        _reject_performed_action(payload, "certificate_generated", "transport profiles cannot generate certificates")
        _reject_performed_action(payload, "private_key_material_present", "transport profiles cannot contain private key material")
        _reject_performed_action(payload, "network_listener_changed", "transport profiles cannot change network listeners")
        _reject_performed_action(payload, "live_auth_exchange_performed", "transport profiles cannot perform live auth exchange")
        data = {key: payload[key] for key in (
            "profile_name",
            "encryption_state",
            "authentication_state",
            "verification_mode",
            "certificate_mode",
            "rotation_supported",
            "downgrade_allowed",
            "downgrade_warning",
            "supported_roles",
            "advisory_notes",
        ) if key in payload}
        if "supported_roles" in data:
            data["supported_roles"] = tuple(data["supported_roles"])
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise TransportSecurityError(f"malformed transport security profile: {exc}") from exc


def create_transport_security_profile(profile_name: str) -> TransportSecurityProfile:
    _validate_choice(profile_name, TRANSPORT_PROFILE_NAMES, "profile_name")
    if profile_name == "plaintext_dev":
        return TransportSecurityProfile(
            profile_name=profile_name,
            encryption_state="degraded",
            authentication_state="none",
            verification_mode="none",
            certificate_mode="none",
            rotation_supported=False,
            downgrade_allowed=True,
            downgrade_warning="plaintext development transport is allowed only for local dry-run development",
            supported_roles=("orchestrator", "master", "worker", "edge"),
            advisory_notes=("use only for local development fixtures", "upgrade to mTLS before production"),
        )
    if profile_name == "tls_ready":
        return TransportSecurityProfile(
            profile_name=profile_name,
            encryption_state="ready",
            authentication_state="server_authenticated",
            verification_mode="ca_validation",
            certificate_mode="placeholder_reference",
            rotation_supported=True,
            downgrade_allowed=True,
            downgrade_warning="downgrade requires explicit operator review",
            supported_roles=("orchestrator", "master", "worker", "edge"),
            advisory_notes=("certificate references are placeholders only",),
        )
    if profile_name == "mtls_ready":
        return TransportSecurityProfile(
            profile_name=profile_name,
            encryption_state="ready",
            authentication_state="mutual_auth_ready",
            verification_mode="ca_validation",
            certificate_mode="operator_provided",
            rotation_supported=True,
            downgrade_allowed=False,
            downgrade_warning="mTLS downgrade is not allowed without a separate operator-approved profile",
            supported_roles=("orchestrator", "master", "worker", "edge"),
            advisory_notes=("mutual authentication is modeled only; no handshake is performed",),
        )
    if profile_name == "pinned_cert_ready":
        return TransportSecurityProfile(
            profile_name=profile_name,
            encryption_state="ready",
            authentication_state="mutual_auth_ready",
            verification_mode="pinned_certificate",
            certificate_mode="operator_provided",
            rotation_supported=True,
            downgrade_allowed=False,
            downgrade_warning="certificate pinning downgrade is blocked in readiness summaries",
            supported_roles=("orchestrator", "master", "worker", "edge"),
            advisory_notes=("pin references must be operator supplied in a future phase",),
        )
    return TransportSecurityProfile(
        profile_name=profile_name,
        encryption_state="required",
        authentication_state="required",
        verification_mode="ca_validation",
        certificate_mode="managed_preview",
        rotation_supported=True,
        downgrade_allowed=False,
        downgrade_warning="production transport requires encrypted mutual authentication",
        supported_roles=("orchestrator", "master", "worker", "edge"),
        advisory_notes=("production readiness is a requirement record only", "no certificates are generated"),
    )


def summarize_transport_profiles(profile_names: list[str] | None = None) -> dict[str, Any]:
    names = profile_names or sorted(TRANSPORT_PROFILE_NAMES)
    profiles = [create_transport_security_profile(name) for name in names]
    by_state = {state: 0 for state in sorted(TRANSPORT_STATES)}
    for profile in profiles:
        by_state[profile.encryption_state] += 1
    return {
        "summary_type": "transport_security_profiles",
        "profile_count": len(profiles),
        "by_encryption_state": by_state,
        "profiles": [profile.to_dict() for profile in profiles],
        "export_safe": True,
        "dry_run_only": True,
        "certificate_generated": False,
        "private_key_material_present": False,
        "network_listener_changed": False,
        "live_auth_exchange_performed": False,
    }


def _reject_performed_action(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise TransportSecurityError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise TransportSecurityError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")
