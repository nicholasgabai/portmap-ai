from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SECRET_CLASSES = {
    "orchestrator_token",
    "worker_enrollment_secret",
    "future_mtls_material",
    "api_session_token",
    "runtime_encryption_key",
}
SECRET_STORAGE_MODES = {"ephemeral", "memory_only", "encrypted_storage_ready", "external_secret_provider_ready"}
EXPOSURE_RISK_STATES = {"low", "medium", "high", "blocked"}


class SecretsManagementError(ValueError):
    """Raised when a secrets-management preview is malformed."""


@dataclass(frozen=True, slots=True)
class SecretManagementPreview:
    secret_class: str
    storage_mode: str
    plaintext_allowed: bool
    rotation_ready: bool
    expiration_supported: bool
    exposure_risk: str
    mitigation_summary: str
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.secret_class, SECRET_CLASSES, "secret_class")
        _validate_choice(self.storage_mode, SECRET_STORAGE_MODES, "storage_mode")
        if self.plaintext_allowed is not False:
            raise SecretsManagementError("plaintext_allowed must remain false")
        if not isinstance(self.rotation_ready, bool):
            raise SecretsManagementError("rotation_ready must be a boolean")
        if not isinstance(self.expiration_supported, bool):
            raise SecretsManagementError("expiration_supported must be a boolean")
        _validate_choice(self.exposure_risk, EXPOSURE_RISK_STATES, "exposure_risk")
        if not isinstance(self.mitigation_summary, str) or not self.mitigation_summary.strip():
            raise SecretsManagementError("mitigation_summary must be a non-empty string")
        if self.preview_only is not True:
            raise SecretsManagementError("secret management records must remain preview-only")
        if self.destructive_action is not False:
            raise SecretsManagementError("secret management records cannot perform destructive actions")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise SecretsManagementError("advisory_notes must be a tuple of strings")

    @property
    def secret_generated(self) -> bool:
        return False

    @property
    def credential_stored(self) -> bool:
        return False

    @property
    def plaintext_persisted(self) -> bool:
        return False

    @property
    def os_credential_store_modified(self) -> bool:
        return False

    @property
    def live_secret_exchange_performed(self) -> bool:
        return False

    @property
    def export_safe(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_class": self.secret_class,
            "storage_mode": self.storage_mode,
            "plaintext_allowed": self.plaintext_allowed,
            "rotation_ready": self.rotation_ready,
            "expiration_supported": self.expiration_supported,
            "exposure_risk": self.exposure_risk,
            "mitigation_summary": self.mitigation_summary,
            "preview_only": self.preview_only,
            "destructive_action": self.destructive_action,
            "advisory_notes": list(self.advisory_notes),
            "secret_generated": self.secret_generated,
            "credential_stored": self.credential_stored,
            "plaintext_persisted": self.plaintext_persisted,
            "os_credential_store_modified": self.os_credential_store_modified,
            "live_secret_exchange_performed": self.live_secret_exchange_performed,
            "export_safe": self.export_safe,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecretManagementPreview":
        if not isinstance(payload, dict):
            raise SecretsManagementError("secret management preview must be an object")
        allowed = {
            "secret_class",
            "storage_mode",
            "plaintext_allowed",
            "rotation_ready",
            "expiration_supported",
            "exposure_risk",
            "mitigation_summary",
            "preview_only",
            "destructive_action",
            "advisory_notes",
            "secret_generated",
            "credential_stored",
            "plaintext_persisted",
            "os_credential_store_modified",
            "live_secret_exchange_performed",
            "export_safe",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise SecretsManagementError(f"unknown secret management fields: {', '.join(unknown)}")
        _reject_true(payload, "secret_generated", "secret management previews cannot generate real secrets")
        _reject_true(payload, "credential_stored", "secret management previews cannot store credentials")
        _reject_true(payload, "plaintext_persisted", "secret management previews cannot persist plaintext")
        _reject_true(payload, "os_credential_store_modified", "secret management previews cannot modify OS credential stores")
        _reject_true(payload, "live_secret_exchange_performed", "secret management previews cannot exchange secrets")
        data = {key: payload[key] for key in (
            "secret_class",
            "storage_mode",
            "plaintext_allowed",
            "rotation_ready",
            "expiration_supported",
            "exposure_risk",
            "mitigation_summary",
            "preview_only",
            "destructive_action",
            "advisory_notes",
        ) if key in payload}
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise SecretsManagementError(f"malformed secret management preview: {exc}") from exc


def create_secret_management_preview(
    secret_class: str,
    *,
    storage_mode: str | None = None,
) -> SecretManagementPreview:
    _validate_choice(secret_class, SECRET_CLASSES, "secret_class")
    mode = storage_mode or _default_storage_mode(secret_class)
    _validate_choice(mode, SECRET_STORAGE_MODES, "storage_mode")
    rotation_ready = mode in {"encrypted_storage_ready", "external_secret_provider_ready"}
    expiration_supported = secret_class in {
        "orchestrator_token",
        "worker_enrollment_secret",
        "api_session_token",
        "future_mtls_material",
    }
    exposure_risk = _exposure_risk(mode, rotation_ready)
    return SecretManagementPreview(
        secret_class=secret_class,
        storage_mode=mode,
        plaintext_allowed=False,
        rotation_ready=rotation_ready,
        expiration_supported=expiration_supported,
        exposure_risk=exposure_risk,
        mitigation_summary=_mitigation_summary(secret_class, mode),
        advisory_notes=("preview only; no secret material is generated",),
    )


def summarize_secret_management_previews(secret_classes: list[str] | None = None) -> dict[str, Any]:
    classes = secret_classes or sorted(SECRET_CLASSES)
    previews = [create_secret_management_preview(secret_class) for secret_class in classes]
    by_storage = {mode: 0 for mode in sorted(SECRET_STORAGE_MODES)}
    by_risk = {risk: 0 for risk in sorted(EXPOSURE_RISK_STATES)}
    for preview in previews:
        by_storage[preview.storage_mode] += 1
        by_risk[preview.exposure_risk] += 1
    return {
        "summary_type": "secret_management_previews",
        "preview_count": len(previews),
        "by_storage_mode": by_storage,
        "by_exposure_risk": by_risk,
        "previews": [preview.to_dict() for preview in previews],
        "preview_only": True,
        "destructive_action": False,
        "secret_generated": False,
        "credential_stored": False,
        "plaintext_persisted": False,
        "os_credential_store_modified": False,
        "live_secret_exchange_performed": False,
        "export_safe": True,
    }


def _default_storage_mode(secret_class: str) -> str:
    if secret_class in {"orchestrator_token", "worker_enrollment_secret", "api_session_token"}:
        return "memory_only"
    if secret_class == "future_mtls_material":
        return "external_secret_provider_ready"
    return "encrypted_storage_ready"


def _exposure_risk(storage_mode: str, rotation_ready: bool) -> str:
    if storage_mode == "ephemeral":
        return "medium"
    if storage_mode == "memory_only":
        return "medium" if not rotation_ready else "low"
    if storage_mode == "encrypted_storage_ready":
        return "low"
    return "low"


def _mitigation_summary(secret_class: str, storage_mode: str) -> str:
    if storage_mode == "memory_only":
        return f"{secret_class} should be rotated and moved to protected storage before production"
    if storage_mode == "ephemeral":
        return f"{secret_class} should be reissued after runtime restart"
    if storage_mode == "external_secret_provider_ready":
        return f"{secret_class} should be supplied by an operator-approved external provider"
    return f"{secret_class} should use encrypted storage when live secret handling is implemented"


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise SecretsManagementError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise SecretsManagementError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")
