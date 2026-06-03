from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .integrity import INTEGRITY_TARGET_NAMES, IntegrityTargetRecord, create_integrity_target_record


TAMPER_DETECTION_NAMES = {
    "config_change",
    "manifest_change",
    "identity_rotation_mismatch",
    "trust_chain_drift",
    "transport_downgrade",
    "package_digest_mismatch",
    "history_store_drift",
}
TAMPER_DETECTION_STATES = {"clean", "suspicious", "tampered", "unverifiable", "unknown"}
TAMPER_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
TAMPER_ENFORCEMENT_MODES = {"preview", "operator_review", "disabled"}

_AFFECTED_TARGETS_BY_DETECTION = {
    "config_change": ("runtime_config",),
    "manifest_change": ("deployment_manifest",),
    "identity_rotation_mismatch": ("node_identity",),
    "trust_chain_drift": ("trust_chain",),
    "transport_downgrade": ("transport_profile",),
    "package_digest_mismatch": ("package_manifest", "binary_artifact"),
    "history_store_drift": ("history_store",),
}


class TamperDetectionError(ValueError):
    """Raised when a tamper detection preview is malformed."""


@dataclass(frozen=True, slots=True)
class TamperDetectionPreview:
    detection_name: str
    severity: str
    affected_target: str
    detection_state: str
    evidence_summary: tuple[str, ...]
    operator_action_required: bool
    remediation_preview: str
    enforcement_mode: str
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_choice(self.detection_name, TAMPER_DETECTION_NAMES, "detection_name")
        _validate_choice(self.severity, TAMPER_SEVERITIES, "severity")
        _validate_choice(self.affected_target, INTEGRITY_TARGET_NAMES, "affected_target")
        expected_targets = _AFFECTED_TARGETS_BY_DETECTION[self.detection_name]
        if self.affected_target not in expected_targets:
            raise TamperDetectionError(f"affected_target for {self.detection_name} must be one of: {', '.join(expected_targets)}")
        _validate_choice(self.detection_state, TAMPER_DETECTION_STATES, "detection_state")
        _validate_choice(self.enforcement_mode, TAMPER_ENFORCEMENT_MODES, "enforcement_mode")
        if not isinstance(self.evidence_summary, tuple) or not self.evidence_summary:
            raise TamperDetectionError("evidence_summary must be a non-empty tuple")
        for evidence in self.evidence_summary:
            if not isinstance(evidence, str) or not evidence.strip() or _contains_private_path(evidence):
                raise TamperDetectionError("evidence_summary entries must be sanitized non-empty strings")
        if not isinstance(self.operator_action_required, bool):
            raise TamperDetectionError("operator_action_required must be a boolean")
        if not isinstance(self.remediation_preview, str) or not self.remediation_preview.strip():
            raise TamperDetectionError("remediation_preview must be a non-empty string")
        if _contains_private_path(self.remediation_preview):
            raise TamperDetectionError("remediation_preview must not contain private paths")
        if self.preview_only is not True:
            raise TamperDetectionError("tamper detection records must remain preview-only")
        if self.destructive_action is not False:
            raise TamperDetectionError("tamper detection records cannot be destructive")
        if not isinstance(self.advisory_notes, tuple) or not all(isinstance(note, str) for note in self.advisory_notes):
            raise TamperDetectionError("advisory_notes must be a tuple of strings")
        for note in self.advisory_notes:
            if _contains_private_path(note):
                raise TamperDetectionError("advisory_notes must not contain private paths")

    @property
    def export_safe(self) -> bool:
        return True

    @property
    def live_blocking_enabled(self) -> bool:
        return False

    @property
    def quarantine_performed(self) -> bool:
        return False

    @property
    def file_deleted(self) -> bool:
        return False

    @property
    def rollback_executed(self) -> bool:
        return False

    @property
    def config_modified(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_name": self.detection_name,
            "severity": self.severity,
            "affected_target": self.affected_target,
            "detection_state": self.detection_state,
            "evidence_summary": list(self.evidence_summary),
            "operator_action_required": self.operator_action_required,
            "remediation_preview": self.remediation_preview,
            "enforcement_mode": self.enforcement_mode,
            "preview_only": self.preview_only,
            "destructive_action": self.destructive_action,
            "advisory_notes": list(self.advisory_notes),
            "export_safe": self.export_safe,
            "live_blocking_enabled": self.live_blocking_enabled,
            "quarantine_performed": self.quarantine_performed,
            "file_deleted": self.file_deleted,
            "rollback_executed": self.rollback_executed,
            "config_modified": self.config_modified,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TamperDetectionPreview":
        if not isinstance(payload, dict):
            raise TamperDetectionError("tamper detection preview must be an object")
        allowed = {
            "detection_name",
            "severity",
            "affected_target",
            "detection_state",
            "evidence_summary",
            "operator_action_required",
            "remediation_preview",
            "enforcement_mode",
            "preview_only",
            "destructive_action",
            "advisory_notes",
            "export_safe",
            "live_blocking_enabled",
            "quarantine_performed",
            "file_deleted",
            "rollback_executed",
            "config_modified",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise TamperDetectionError(f"unknown tamper detection fields: {', '.join(unknown)}")
        _reject_true(payload, "live_blocking_enabled", "tamper previews cannot enable live blocking")
        _reject_true(payload, "quarantine_performed", "tamper previews cannot quarantine files")
        _reject_true(payload, "file_deleted", "tamper previews cannot delete files")
        _reject_true(payload, "rollback_executed", "tamper previews cannot execute rollback")
        _reject_true(payload, "config_modified", "tamper previews cannot modify configuration")
        data = {key: payload[key] for key in (
            "detection_name",
            "severity",
            "affected_target",
            "detection_state",
            "evidence_summary",
            "operator_action_required",
            "remediation_preview",
            "enforcement_mode",
            "preview_only",
            "destructive_action",
            "advisory_notes",
        ) if key in payload}
        if "evidence_summary" in data:
            data["evidence_summary"] = tuple(data["evidence_summary"])
        if "advisory_notes" in data:
            data["advisory_notes"] = tuple(data["advisory_notes"])
        try:
            return cls(**data)
        except TypeError as exc:
            raise TamperDetectionError(f"malformed tamper detection preview: {exc}") from exc


def create_tamper_detection_preview(
    detection_name: str,
    *,
    detection_state: str = "unknown",
    affected_target: str | IntegrityTargetRecord | None = None,
    evidence_summary: tuple[str, ...] | None = None,
    remediation_preview: str | None = None,
    enforcement_mode: str = "preview",
    advisory_notes: tuple[str, ...] | None = None,
) -> TamperDetectionPreview:
    _validate_choice(detection_name, TAMPER_DETECTION_NAMES, "detection_name")
    _validate_choice(detection_state, TAMPER_DETECTION_STATES, "detection_state")
    target_name = _coerce_target_name(affected_target) if affected_target is not None else _AFFECTED_TARGETS_BY_DETECTION[detection_name][0]
    severity = _severity_for(detection_name, detection_state)
    return TamperDetectionPreview(
        detection_name=detection_name,
        severity=severity,
        affected_target=target_name,
        detection_state=detection_state,
        evidence_summary=evidence_summary or _default_evidence(detection_name, detection_state),
        operator_action_required=detection_state in {"suspicious", "tampered", "unverifiable"} or detection_name == "transport_downgrade",
        remediation_preview=remediation_preview or _default_remediation(detection_name, detection_state),
        enforcement_mode=enforcement_mode,
        advisory_notes=advisory_notes or _default_notes(detection_name),
    )


def build_tamper_previews_from_integrity(targets: list[IntegrityTargetRecord | dict[str, Any]]) -> dict[str, Any]:
    previews: list[TamperDetectionPreview] = []
    malformed_records: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        try:
            record = target if isinstance(target, IntegrityTargetRecord) else IntegrityTargetRecord.from_dict(target)
        except Exception as exc:  # noqa: BLE001 - malformed records are isolated in summaries.
            malformed_records.append({"record_index": index, "error": str(exc), "detection_state": "unverifiable"})
            continue
        detection_name = _detection_for_target(record.target_name)
        state = "tampered" if record.integrity_state == "drift_detected" else record.integrity_state
        if state == "verified":
            state = "clean"
        previews.append(
            create_tamper_detection_preview(
                detection_name,
                detection_state=state,
                affected_target=record,
                evidence_summary=(f"{record.target_name} integrity state is {record.integrity_state}",),
            )
        )
    by_state = {state: 0 for state in sorted(TAMPER_DETECTION_STATES)}
    for preview in previews:
        by_state[preview.detection_state] += 1
    return {
        "summary_type": "tamper_detection_preview",
        "preview_count": len(previews),
        "malformed_record_count": len(malformed_records),
        "by_detection_state": by_state,
        "previews": [preview.to_dict() for preview in previews],
        "malformed_records": malformed_records,
        "export_safe": True,
        "preview_only": True,
        "destructive_action": False,
        "live_blocking_enabled": False,
        "quarantine_performed": False,
        "file_deleted": False,
        "rollback_executed": False,
        "config_modified": False,
    }


def summarize_tamper_detection(detection_names: list[str] | None = None) -> dict[str, Any]:
    names = detection_names or sorted(TAMPER_DETECTION_NAMES)
    previews = [create_tamper_detection_preview(name) for name in names]
    by_state = {state: 0 for state in sorted(TAMPER_DETECTION_STATES)}
    by_severity = {severity: 0 for severity in sorted(TAMPER_SEVERITIES)}
    for preview in previews:
        by_state[preview.detection_state] += 1
        by_severity[preview.severity] += 1
    return {
        "summary_type": "tamper_detection_readiness",
        "preview_count": len(previews),
        "by_detection_state": by_state,
        "by_severity": by_severity,
        "previews": [preview.to_dict() for preview in previews],
        "export_safe": True,
        "preview_only": True,
        "destructive_action": False,
        "live_blocking_enabled": False,
        "quarantine_performed": False,
        "file_deleted": False,
        "rollback_executed": False,
        "config_modified": False,
    }


def _coerce_target_name(target: str | IntegrityTargetRecord) -> str:
    if isinstance(target, IntegrityTargetRecord):
        return target.target_name
    _validate_choice(target, INTEGRITY_TARGET_NAMES, "affected_target")
    return target


def _detection_for_target(target_name: str) -> str:
    for detection_name, affected_targets in _AFFECTED_TARGETS_BY_DETECTION.items():
        if target_name in affected_targets:
            return detection_name
    if target_name == "binary_artifact":
        return "package_digest_mismatch"
    return "config_change"


def _severity_for(detection_name: str, detection_state: str) -> str:
    if detection_state == "clean":
        return "info"
    if detection_state == "unknown":
        return "unknown"
    if detection_state == "unverifiable":
        return "medium"
    if detection_state == "suspicious":
        return "high" if detection_name in {"transport_downgrade", "identity_rotation_mismatch"} else "medium"
    if detection_name in {"trust_chain_drift", "package_digest_mismatch", "transport_downgrade"}:
        return "critical"
    return "high"


def _default_evidence(detection_name: str, detection_state: str) -> tuple[str, ...]:
    return (f"{detection_name} detection is {detection_state} in preview records",)


def _default_remediation(detection_name: str, detection_state: str) -> str:
    if detection_state == "clean":
        return "no action required beyond routine operator review"
    return f"review {detection_name} evidence and compare against operator-approved manifests"


def _default_notes(detection_name: str) -> tuple[str, ...]:
    return (
        f"{detection_name} is a tamper-detection preview only",
        "no blocking, quarantine, deletion, rollback, or configuration change is performed",
    )


def _reject_true(payload: dict[str, Any], field_name: str, message: str) -> None:
    if payload.get(field_name) is True:
        raise TamperDetectionError(message)


def _validate_choice(value: str, allowed: set[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise TamperDetectionError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _contains_private_path(value: str) -> bool:
    stripped = value.strip()
    return (
        stripped.startswith("/")
        or stripped.startswith("~")
        or ":\\" in stripped
        or ("\\" + "Users" + "\\") in stripped
        or ("/" + "Users" + "/") in stripped
    )
