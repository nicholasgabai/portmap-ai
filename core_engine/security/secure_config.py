from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SECURE_CONFIG_PROFILE_NAMES = {"development", "staging", "production", "edge", "ephemeral_runtime"}
SECURE_CONFIG_STATES = {"insecure", "degraded", "recommended", "required"}
SECRET_STORAGE_MODES = {"plaintext_dev_preview", "memory_only", "encrypted_storage_ready", "external_secret_provider_ready"}
PERSISTENCE_MODES = {"none", "ephemeral", "local_metadata_only", "encrypted_storage_ready", "external_provider_ready"}
BOOTSTRAP_MODES = {"manual_preview", "environment_preview", "operator_supplied", "external_provider_preview"}


class SecureConfigError(ValueError):
    """Raised when a secure configuration profile is malformed."""


@dataclass(frozen=True, slots=True)
class SecureConfigProfile:
    config_profile_name: str
    secret_storage_mode: str
    encryption_required: bool
    rotation_supported: bool
    persistence_mode: str
    bootstrap_mode: str
    export_safety: str
    downgrade_risk: str
    operator_actions_required: tuple[str, ...]
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.config_profile_name, SECURE_CONFIG_PROFILE_NAMES, "config_profile_name")
        _validate_choice(self.secret_storage_mode, SECRET_STORAGE_MODES, "secret_storage_mode")
        if not isinstance(self.encryption_required, bool):
            raise SecureConfigError("encryption_required must be a boolean")
        if not isinstance(self.rotation_supported, bool):
            raise SecureConfigError("rotation_supported must be a boolean")
        _validate_choice(self.persistence_mode, PERSISTENCE_MODES, "persistence_mode")
        _validate_choice(self.bootstrap_mode, BOOTSTRAP_MODES, "bootstrap_mode")
        _validate_choice(self.export_safety, SECURE_CONFIG_STATES, "export_safety")
        if not isinstance(self.downgrade_risk, str):
            raise SecureConfigError("downgrade_risk must be a string")
        _validate_str_tuple(self.operator_actions_required, "operator_actions_required")
        _validate_str_tuple(self.advisory_notes, "advisory_notes")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def dry_run_only(self) -> bool:
        return True

    @property
    def live_encryption_enabled(self) -> bool:
        return False

    @property
    def os_keychain_integrated(self) -> bool:
        return False

    @property
    def plaintext_secret_persistence_allowed(self) -> bool:
        return False

    @property
    def credentials_stored(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_profile_name": self.config_profile_name,
            "secret_storage_mode": self.secret_storage_mode,
            "encryption_required": self.encryption_required,
            "rotation_supported": self.rotation_supported,
            "persistence_mode": self.persistence_mode,
            "bootstrap_mode": self.bootstrap_mode,
            "export_safety": self.export_safety,
            "downgrade_risk": self.downgrade_risk,
            "operator_actions_required": list(self.operator_actions_required),
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "dry_run_only": self.dry_run_only,
            "live_encryption_enabled": self.live_encryption_enabled,
            "os_keychain_integrated": self.os_keychain_integrated,
            "plaintext_secret_persistence_allowed": self.plaintext_secret_persistence_allowed,
            "credentials_stored": self.credentials_stored,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecureConfigProfile":
        if not isinstance(payload, dict):
            raise SecureConfigError("secure configuration profile must be an object")
        allowed = {
            "config_profile_name",
            "secret_storage_mode",
            "encryption_required",
            "rotation_supported",
            "persistence_mode",
            "bootstrap_mode",
            "export_safety",
            "downgrade_risk",
            "operator_actions_required",
            "advisory_notes",
            "export_safe",
            "dry_run_only",
            "live_encryption_enabled",
            "os_keychain_integrated",
            "plaintext_secret_persistence_allowed",
            "credentials_stored",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise SecureConfigError(f"unknown secure configuration fields: {', '.join(unknown)}")
        _reject_true(payload, "live_encryption_enabled", "secure configuration profiles cannot enable live encryption")
        _reject_true(payload, "os_keychain_integrated", "secure configuration profiles cannot integrate OS keychains")
        _reject_true(payload, "plaintext_secret_persistence_allowed", "plaintext secret persistence is not allowed")
        _reject_true(payload, "credentials_stored", "secure configuration profiles cannot store credentials")
        data = {key: payload[key] for key in (
            "config_profile_name",
            "secret_storage_mode",
            "encryption_required",
            "rotation_supported",
            "persistence_mode",
            "bootstrap_mode",
            "export_safety",
            "downgrade_risk",
            "operator_actions_required",
            "advisory_notes",
        ) if key in payload}
        if "operator_actions_required" in data:
            data["operator_actions_required"] = tuple(data["operator_actions_required"])
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise SecureConfigError(f"malformed secure configuration profile: {exc}") from exc


def create_secure_config_profile(config_profile_name: str) -> SecureConfigProfile:
    _validate_choice(config_profile_name, SECURE_CONFIG_PROFILE_NAMES, "config_profile_name")
    if config_profile_name == "development":
        return SecureConfigProfile(
            config_profile_name=config_profile_name,
            secret_storage_mode="plaintext_dev_preview",
            encryption_required=False,
            rotation_supported=False,
            persistence_mode="local_metadata_only",
            bootstrap_mode="manual_preview",
            export_safety="insecure",
            downgrade_risk="development preview must not persist plaintext secrets",
            operator_actions_required=("review before distributed use",),
            advisory_notes=("local development only", "no credentials are stored by this profile"),
        )
    if config_profile_name == "staging":
        return SecureConfigProfile(
            config_profile_name=config_profile_name,
            secret_storage_mode="encrypted_storage_ready",
            encryption_required=True,
            rotation_supported=True,
            persistence_mode="encrypted_storage_ready",
            bootstrap_mode="operator_supplied",
            export_safety="recommended",
            downgrade_risk="downgrade to plaintext development requires operator review",
            operator_actions_required=("provide protected secret source in a future phase",),
            advisory_notes=("readiness profile only",),
        )
    if config_profile_name == "production":
        return SecureConfigProfile(
            config_profile_name=config_profile_name,
            secret_storage_mode="external_secret_provider_ready",
            encryption_required=True,
            rotation_supported=True,
            persistence_mode="external_provider_ready",
            bootstrap_mode="external_provider_preview",
            export_safety="required",
            downgrade_risk="production configuration requires protected secret storage",
            operator_actions_required=("approve external secret provider", "validate rotation policy"),
            advisory_notes=("no live provider integration is performed",),
        )
    if config_profile_name == "edge":
        return SecureConfigProfile(
            config_profile_name=config_profile_name,
            secret_storage_mode="memory_only",
            encryption_required=True,
            rotation_supported=True,
            persistence_mode="ephemeral",
            bootstrap_mode="operator_supplied",
            export_safety="recommended",
            downgrade_risk="edge nodes should avoid disk persistence for sensitive material",
            operator_actions_required=("review edge bootstrap workflow",),
            advisory_notes=("Raspberry Pi and low-resource friendly readiness profile",),
        )
    return SecureConfigProfile(
        config_profile_name=config_profile_name,
        secret_storage_mode="memory_only",
        encryption_required=True,
        rotation_supported=False,
        persistence_mode="ephemeral",
        bootstrap_mode="environment_preview",
        export_safety="degraded",
        downgrade_risk="ephemeral runtime loses secret material on restart",
        operator_actions_required=("review restart behavior",),
        advisory_notes=("runtime-only preview; no secrets are generated",),
    )


def summarize_secure_config_profiles(profile_names: list[str] | None = None) -> dict[str, Any]:
    names = profile_names or sorted(SECURE_CONFIG_PROFILE_NAMES)
    profiles = [create_secure_config_profile(name) for name in names]
    by_state = {state: 0 for state in sorted(SECURE_CONFIG_STATES)}
    for profile in profiles:
        by_state[profile.export_safety] += 1
    return {
        "summary_type": "secure_config_profiles",
        "profile_count": len(profiles),
        "by_export_safety": by_state,
        "profiles": [profile.to_dict() for profile in profiles],
        "export_safe": True,
        "dry_run_only": True,
        "live_encryption_enabled": False,
        "os_keychain_integrated": False,
        "credentials_stored": False,
    }


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise SecureConfigError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise SecureConfigError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _validate_str_tuple(value: tuple[str, ...], field_name: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise SecureConfigError(f"{field_name} must be a tuple of strings")
