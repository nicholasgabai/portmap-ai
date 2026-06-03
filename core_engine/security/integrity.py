from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


INTEGRITY_TARGET_NAMES = {
    "runtime_config",
    "deployment_manifest",
    "node_identity",
    "trust_chain",
    "transport_profile",
    "package_manifest",
    "binary_artifact",
    "history_store",
}
INTEGRITY_TARGET_CLASSES = {
    "configuration",
    "deployment",
    "identity",
    "trust",
    "transport",
    "package",
    "artifact",
    "history",
}
INTEGRITY_STATES = {"verified", "drift_detected", "unverifiable", "unknown"}
INTEGRITY_VERIFICATION_MODES = {
    "digest_preview",
    "signature_preview",
    "digest_and_signature_preview",
    "manual_review",
    "unavailable",
    "unknown",
}

_TARGET_CLASS_BY_NAME = {
    "runtime_config": "configuration",
    "deployment_manifest": "deployment",
    "node_identity": "identity",
    "trust_chain": "trust",
    "transport_profile": "transport",
    "package_manifest": "package",
    "binary_artifact": "artifact",
    "history_store": "history",
}


class IntegrityError(ValueError):
    """Raised when an integrity readiness record is malformed."""


@dataclass(frozen=True, slots=True)
class IntegrityTargetRecord:
    target_name: str
    target_class: str
    integrity_state: str
    verification_mode: str
    digest_available: bool
    signature_available: bool
    last_verified_preview: str
    drift_detected: bool
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.target_name, INTEGRITY_TARGET_NAMES, "target_name")
        _validate_choice(self.target_class, INTEGRITY_TARGET_CLASSES, "target_class")
        expected_class = _TARGET_CLASS_BY_NAME[self.target_name]
        if self.target_class != expected_class:
            raise IntegrityError(f"target_class for {self.target_name} must be {expected_class}")
        _validate_choice(self.integrity_state, INTEGRITY_STATES, "integrity_state")
        _validate_choice(self.verification_mode, INTEGRITY_VERIFICATION_MODES, "verification_mode")
        if not isinstance(self.digest_available, bool):
            raise IntegrityError("digest_available must be a boolean")
        if not isinstance(self.signature_available, bool):
            raise IntegrityError("signature_available must be a boolean")
        if not isinstance(self.last_verified_preview, str) or _contains_private_path(self.last_verified_preview):
            raise IntegrityError("last_verified_preview must be a sanitized string")
        if not isinstance(self.drift_detected, bool):
            raise IntegrityError("drift_detected must be a boolean")
        if self.integrity_state == "drift_detected" and not self.drift_detected:
            raise IntegrityError("drift_detected state requires drift_detected to be true")
        if self.integrity_state != "drift_detected" and self.drift_detected:
            raise IntegrityError("drift_detected flag requires drift_detected state")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise IntegrityError("advisory_notes must be a tuple of strings")
        for note in self.advisory_notes:
            if _contains_private_path(note):
                raise IntegrityError("advisory_notes must not contain private paths")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def preview_only(self) -> bool:
        return True

    @property
    def file_watcher_started(self) -> bool:
        return False

    @property
    def real_private_file_hashed(self) -> bool:
        return False

    @property
    def system_file_modified(self) -> bool:
        return False

    @property
    def private_path_exposed(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_class": self.target_class,
            "integrity_state": self.integrity_state,
            "verification_mode": self.verification_mode,
            "digest_available": self.digest_available,
            "signature_available": self.signature_available,
            "last_verified_preview": self.last_verified_preview,
            "drift_detected": self.drift_detected,
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "preview_only": self.preview_only,
            "file_watcher_started": self.file_watcher_started,
            "real_private_file_hashed": self.real_private_file_hashed,
            "system_file_modified": self.system_file_modified,
            "private_path_exposed": self.private_path_exposed,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IntegrityTargetRecord":
        if not isinstance(payload, dict):
            raise IntegrityError("integrity target record must be an object")
        allowed = {
            "target_name",
            "target_class",
            "integrity_state",
            "verification_mode",
            "digest_available",
            "signature_available",
            "last_verified_preview",
            "drift_detected",
            "advisory_notes",
            "export_safe",
            "preview_only",
            "file_watcher_started",
            "real_private_file_hashed",
            "system_file_modified",
            "private_path_exposed",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise IntegrityError(f"unknown integrity target fields: {', '.join(unknown)}")
        _reject_true(payload, "file_watcher_started", "integrity records cannot start file watchers")
        _reject_true(payload, "real_private_file_hashed", "integrity records cannot hash private files")
        _reject_true(payload, "system_file_modified", "integrity records cannot modify system files")
        _reject_true(payload, "private_path_exposed", "integrity records cannot expose private paths")
        data = {key: payload[key] for key in (
            "target_name",
            "target_class",
            "integrity_state",
            "verification_mode",
            "digest_available",
            "signature_available",
            "last_verified_preview",
            "drift_detected",
            "advisory_notes",
        ) if key in payload}
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise IntegrityError(f"malformed integrity target record: {exc}") from exc


def create_integrity_target_record(
    target_name: str,
    *,
    integrity_state: str = "unknown",
    verification_mode: str | None = None,
    digest_available: bool | None = None,
    signature_available: bool | None = None,
    last_verified_preview: str = "not_verified",
    advisory_notes: tuple[str, ...] | None = None,
) -> IntegrityTargetRecord:
    _validate_choice(target_name, INTEGRITY_TARGET_NAMES, "target_name")
    _validate_choice(integrity_state, INTEGRITY_STATES, "integrity_state")
    mode = verification_mode or _default_verification_mode(target_name)
    digest = _default_digest_available(target_name) if digest_available is None else digest_available
    signature = _default_signature_available(target_name) if signature_available is None else signature_available
    notes = advisory_notes or _default_notes(target_name, integrity_state)
    return IntegrityTargetRecord(
        target_name=target_name,
        target_class=_TARGET_CLASS_BY_NAME[target_name],
        integrity_state=integrity_state,
        verification_mode=mode,
        digest_available=digest,
        signature_available=signature,
        last_verified_preview=last_verified_preview,
        drift_detected=integrity_state == "drift_detected",
        advisory_notes=notes,
    )


def summarize_integrity_targets(target_names: list[str] | None = None) -> dict[str, Any]:
    names = target_names or sorted(INTEGRITY_TARGET_NAMES)
    targets = [create_integrity_target_record(name) for name in names]
    by_state = {state: 0 for state in sorted(INTEGRITY_STATES)}
    by_class = {target_class: 0 for target_class in sorted(INTEGRITY_TARGET_CLASSES)}
    for target in targets:
        by_state[target.integrity_state] += 1
        by_class[target.target_class] += 1
    return {
        "summary_type": "integrity_target_readiness",
        "target_count": len(targets),
        "by_integrity_state": by_state,
        "by_target_class": by_class,
        "targets": [target.to_dict() for target in targets],
        "export_safe": True,
        "preview_only": True,
        "file_watcher_started": False,
        "real_private_file_hashed": False,
        "system_file_modified": False,
        "private_path_exposed": False,
    }


def _default_verification_mode(target_name: str) -> str:
    if target_name in {"package_manifest", "binary_artifact"}:
        return "digest_and_signature_preview"
    if target_name in {"node_identity", "trust_chain", "transport_profile"}:
        return "signature_preview"
    if target_name in {"runtime_config", "deployment_manifest", "history_store"}:
        return "digest_preview"
    return "unknown"


def _default_digest_available(target_name: str) -> bool:
    return target_name in {"runtime_config", "deployment_manifest", "package_manifest", "binary_artifact", "history_store"}


def _default_signature_available(target_name: str) -> bool:
    return target_name in {"node_identity", "trust_chain", "transport_profile", "package_manifest", "binary_artifact"}


def _default_notes(target_name: str, integrity_state: str) -> tuple[str, ...]:
    notes = [f"{target_name} integrity is modeled as a local preview record"]
    if integrity_state == "unknown":
        notes.append("operator review is required before production enforcement")
    if integrity_state == "unverifiable":
        notes.append("verification material is unavailable or incomplete")
    if integrity_state == "drift_detected":
        notes.append("drift is reported for review only")
    return tuple(notes)


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise IntegrityError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise IntegrityError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _contains_private_path(value: str) -> bool:
    stripped = value.strip()
    return (
        stripped.startswith("/")
        or stripped.startswith("~")
        or ":\\" in stripped
        or ("\\" + "Users" + "\\") in stripped
        or ("/" + "Users" + "/") in stripped
    )
