from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes
from core_engine.governance.compliance_profiles import ComplianceProfileRecord, normalize_compliance_profile
from core_engine.governance.data_classification import (
    DATA_GOVERNANCE_SAFETY_FLAGS,
    DataClassificationRecord,
    build_data_classification,
    normalize_data_classification,
    summarize_classifications,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_token


DATA_GOVERNANCE_RECORD_VERSION = 1
DATA_GOVERNANCE_STATES = {"ready", "review_recommended", "restricted", "degraded", "unavailable", "unknown"}
DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS = {
    **GOVERNANCE_SAFETY_FLAGS,
    **DATA_GOVERNANCE_SAFETY_FLAGS,
    "governance_control_enforced": False,
    "data_deleted": False,
    "file_read_performed": False,
    "filesystem_written": False,
    "runtime_behavior_changed": False,
}


@dataclass(frozen=True)
class DataGovernanceControlSummary:
    governance_id: str
    generated_at: str
    governance_state: str
    classifications: list[dict[str, Any]] = field(default_factory=list)
    privacy_boundary_summary: dict[str, Any] = field(default_factory=dict)
    retention_control_summary: dict[str, Any] = field(default_factory=dict)
    redaction_readiness: dict[str, Any] = field(default_factory=dict)
    export_governance_summary: dict[str, Any] = field(default_factory=dict)
    compliance_profile_summary: dict[str, Any] = field(default_factory=dict)
    audit_summary: dict[str, Any] = field(default_factory=dict)
    governance_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "data_governance_control_summary",
            "record_version": DATA_GOVERNANCE_RECORD_VERSION,
            "governance_id": sanitize_reference(self.governance_id) or "data-governance-unknown",
            "generated_at": str(self.generated_at or ""),
            "governance_state": normalize_data_governance_state(self.governance_state),
            "classifications": list(self.classifications),
            "classification_summary": summarize_classifications(self.classifications),
            "privacy_boundary_summary": dict(self.privacy_boundary_summary),
            "retention_control_summary": dict(self.retention_control_summary),
            "redaction_readiness": dict(self.redaction_readiness),
            "export_governance_summary": dict(self.export_governance_summary),
            "compliance_profile_summary": dict(self.compliance_profile_summary),
            "audit_summary": dict(self.audit_summary),
            "governance_recommendations": sanitize_notes(self.governance_recommendations),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS,
        }


def build_data_governance_summary(
    *,
    governance_id: Any = "",
    generated_at: Any = None,
    governance_state: Any = "",
    classifications: Iterable[DataClassificationRecord | dict[str, Any] | Any] | None = None,
    compliance_profiles: Iterable[ComplianceProfileRecord | dict[str, Any] | Any] | None = None,
    audit_summary: dict[str, Any] | None = None,
    governance_recommendations: Iterable[Any] | None = None,
) -> DataGovernanceControlSummary:
    timestamp = str(generated_at or now_timestamp())
    classification_rows = normalize_classification_rows(classifications)
    compliance_rows = [normalize_compliance_profile(profile).to_dict() for profile in list(compliance_profiles or [])[:16]]
    audit_row = sanitize_summary(audit_summary or {})
    privacy = build_privacy_boundary_summary(classification_rows, compliance_rows)
    retention = build_retention_control_summary(classification_rows, compliance_rows)
    redaction = build_redaction_readiness(classification_rows)
    export = build_export_governance_summary(classification_rows, compliance_rows)
    compliance = summarize_compliance_profiles(compliance_rows)
    recommendations = sanitize_notes(
        governance_recommendations
        or build_governance_recommendations(
            classifications=classification_rows,
            privacy_boundary_summary=privacy,
            redaction_readiness=redaction,
            export_governance_summary=export,
        )
    )
    state = normalize_data_governance_state(governance_state) if governance_state else infer_governance_state(classification_rows)
    safe_id = sanitize_reference(governance_id)
    if not safe_id:
        safe_id = "data-governance-" + digest(
            {
                "generated_at": timestamp,
                "classification_count": len(classification_rows),
                "compliance_profile_count": len(compliance_rows),
                "governance_state": state,
            }
        )[:16]
    return DataGovernanceControlSummary(
        governance_id=safe_id,
        generated_at=timestamp,
        governance_state=state,
        classifications=classification_rows,
        privacy_boundary_summary=privacy,
        retention_control_summary=retention,
        redaction_readiness=redaction,
        export_governance_summary=export,
        compliance_profile_summary=compliance,
        audit_summary=audit_row,
        governance_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_data_governance_summary(*, generated_at: Any = None) -> DataGovernanceControlSummary:
    return build_data_governance_summary(
        generated_at=generated_at,
        governance_state="unavailable",
        classifications=[],
        compliance_profiles=[],
        audit_summary={},
        governance_recommendations=["no data governance inputs supplied"],
    )


def normalize_classification_rows(values: Iterable[DataClassificationRecord | dict[str, Any] | Any] | None) -> list[dict[str, Any]]:
    records = default_classifications() if values is None else list(values)
    return [normalize_data_classification(record).to_dict() for record in records[:64]]


def default_classifications() -> list[DataClassificationRecord]:
    return [
        build_data_classification(data_category="runtime_metadata", source_mode="unknown"),
        build_data_classification(data_category="audit_metadata", source_mode="unknown"),
        build_data_classification(data_category="export_metadata", source_mode="unknown"),
        build_data_classification(data_category="configuration_metadata", source_mode="unknown"),
    ]


def build_privacy_boundary_summary(classifications: list[dict[str, Any]], compliance_profiles: list[dict[str, Any]]) -> dict[str, Any]:
    restricted_count = sum(1 for row in classifications if row.get("handling_state") == "restricted")
    redaction_count = sum(1 for row in classifications if row.get("redaction_required"))
    return {
        "record_type": "privacy_boundary_summary",
        "classification_count": len(classifications),
        "restricted_count": restricted_count,
        "redaction_required_count": redaction_count,
        "compliance_profile_count": len(compliance_profiles),
        "private_identifier_export_allowed": False,
        "operator_review_required": redaction_count > 0 or restricted_count > 0,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS,
    }


def build_retention_control_summary(classifications: list[dict[str, Any]], compliance_profiles: list[dict[str, Any]]) -> dict[str, Any]:
    retention_count = sum(1 for row in classifications if row.get("retention_required"))
    profile_retention_days = [
        profile.get("retention_expectations", {}).get("retention_days")
        for profile in compliance_profiles
        if isinstance(profile.get("retention_expectations"), dict)
    ]
    days = [int(value) for value in profile_retention_days if isinstance(value, int)]
    return {
        "record_type": "retention_control_summary",
        "retention_required_count": retention_count,
        "recommended_retention_days": max(days) if days else 30,
        "deletion_allowed": False,
        "retention_preview_only": True,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS,
    }


def build_redaction_readiness(classifications: list[dict[str, Any]]) -> dict[str, Any]:
    required = [row for row in classifications if row.get("redaction_required")]
    expected_redactions = sorted({item for row in required for item in row.get("expected_redactions", [])})
    return {
        "record_type": "redaction_readiness_summary",
        "redaction_required_count": len(required),
        "expected_redactions": expected_redactions[:64],
        "redaction_ready": bool(required),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS,
    }


def build_export_governance_summary(classifications: list[dict[str, Any]], compliance_profiles: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = [row for row in classifications if not row.get("export_allowed")]
    export_requirements = [
        profile.get("export_requirements", {})
        for profile in compliance_profiles
        if isinstance(profile.get("export_requirements"), dict)
    ]
    return {
        "record_type": "export_governance_summary",
        "export_allowed_count": sum(1 for row in classifications if row.get("export_allowed")),
        "export_restricted_count": len(blocked),
        "sensitive_data_scan_expected": any(item.get("sensitive_data_scan_expected") for item in export_requirements) if export_requirements else True,
        "artifact_check_expected": any(item.get("artifact_check_expected") for item in export_requirements) if export_requirements else True,
        "private_export_read_by_default": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS,
    }


def summarize_compliance_profiles(compliance_profiles: list[dict[str, Any]]) -> dict[str, Any]:
    type_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in compliance_profiles:
        profile_type = sanitize_token(row.get("profile_type", "unknown")).lower() or "unknown"
        profile_state = sanitize_token(row.get("profile_state", "unknown")).lower() or "unknown"
        type_counts[profile_type] = type_counts.get(profile_type, 0) + 1
        state_counts[profile_state] = state_counts.get(profile_state, 0) + 1
    return {
        "record_type": "compliance_profile_summary",
        "profile_count": len(compliance_profiles),
        "type_counts": dict(sorted(type_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "certification_claimed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS,
    }


def build_governance_recommendations(
    *,
    classifications: list[dict[str, Any]],
    privacy_boundary_summary: dict[str, Any],
    redaction_readiness: dict[str, Any],
    export_governance_summary: dict[str, Any],
) -> list[str]:
    recommendations = ["review data classifications before sharing governance exports"]
    if privacy_boundary_summary.get("operator_review_required"):
        recommendations.append("perform operator review for redaction and privacy boundaries")
    if redaction_readiness.get("redaction_required_count", 0):
        recommendations.append("verify expected redactions before export")
    if export_governance_summary.get("export_restricted_count", 0):
        recommendations.append("keep restricted categories out of export bundles unless separately approved")
    if any(row.get("handling_state") == "unknown" for row in classifications):
        recommendations.append("complete unknown classification handling before relying on summary")
    return recommendations


def infer_governance_state(classifications: list[dict[str, Any]]) -> str:
    if not classifications:
        return "unavailable"
    states = {row.get("handling_state", "unknown") for row in classifications}
    if "restricted" in states:
        return "restricted"
    if "unknown" in states:
        return "degraded"
    if "review_required" in states or "redaction_required" in states:
        return "review_recommended"
    return "ready"


def sanitize_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, raw_value in list(value.items())[:48]:
        safe_key = sanitize_token(key).lower()
        if not safe_key:
            continue
        if isinstance(raw_value, bool):
            safe[safe_key] = raw_value
        elif isinstance(raw_value, (int, float)):
            safe[safe_key] = raw_value
        elif isinstance(raw_value, dict):
            safe[safe_key] = sanitize_summary(raw_value)
        elif isinstance(raw_value, (list, tuple, set)):
            safe[safe_key] = [sanitize_token(item) for item in list(raw_value)[:32]]
        else:
            safe[safe_key] = sanitize_token(raw_value)[:120]
    safe.setdefault("preview_only", True)
    safe.setdefault("destructive_action", False)
    safe.setdefault("export_safe", True)
    return safe


def normalize_data_governance_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in DATA_GOVERNANCE_STATES else "unknown"


def deterministic_data_governance_json(record: DataGovernanceControlSummary | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, DataGovernanceControlSummary) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "DATA_GOVERNANCE_STATES",
    "DATA_GOVERNANCE_SUMMARY_SAFETY_FLAGS",
    "DataGovernanceControlSummary",
    "build_data_governance_summary",
    "deterministic_data_governance_json",
    "empty_data_governance_summary",
    "normalize_data_governance_state",
]
