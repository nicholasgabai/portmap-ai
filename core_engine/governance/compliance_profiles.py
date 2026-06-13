from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes
from core_engine.governance.evidence_profiles import (
    EVIDENCE_PROFILE_SAFETY_FLAGS,
    EvidenceExpectationRecord,
    build_evidence_expectation,
    normalize_evidence_expectation,
    sanitize_text_map,
    summarize_evidence_expectations,
)
from core_engine.scaling.bus_envelopes import digest, sanitize_reference, sanitize_text, sanitize_token


COMPLIANCE_PROFILE_RECORD_VERSION = 1
COMPLIANCE_PROFILE_TYPES = {
    "internal_audit",
    "privacy_review",
    "security_review",
    "incident_review",
    "enterprise_readiness",
    "custom",
    "unknown",
}
COMPLIANCE_PROFILE_STATES = {"ready", "advisory", "incomplete", "degraded", "unavailable", "unknown"}
COMPLIANCE_PROFILE_SAFETY_FLAGS = {
    **GOVERNANCE_SAFETY_FLAGS,
    **EVIDENCE_PROFILE_SAFETY_FLAGS,
    "control_enforced": False,
    "runtime_behavior_changed": False,
    "legal_analysis_performed": False,
    "legal_claim_created": False,
    "certification_claimed": False,
}


@dataclass(frozen=True)
class ComplianceProfileRecord:
    profile_id: str
    profile_name: str
    profile_type: str
    profile_state: str
    evidence_expectations: list[dict[str, Any]] = field(default_factory=list)
    audit_requirements: dict[str, Any] = field(default_factory=dict)
    retention_expectations: dict[str, Any] = field(default_factory=dict)
    privacy_requirements: dict[str, Any] = field(default_factory=dict)
    export_requirements: dict[str, Any] = field(default_factory=dict)
    operator_responsibilities: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    certification_claimed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "compliance_profile",
            "record_version": COMPLIANCE_PROFILE_RECORD_VERSION,
            "profile_id": sanitize_reference(self.profile_id) or "compliance-profile-unknown",
            "profile_name": sanitize_text(self.profile_name) or "Compliance profile",
            "profile_type": normalize_compliance_profile_type(self.profile_type),
            "profile_state": normalize_compliance_profile_state(self.profile_state),
            "evidence_expectations": list(self.evidence_expectations),
            "evidence_summary": summarize_evidence_expectations(self.evidence_expectations),
            "audit_requirements": dict(self.audit_requirements),
            "retention_expectations": dict(self.retention_expectations),
            "privacy_requirements": dict(self.privacy_requirements),
            "export_requirements": dict(self.export_requirements),
            "operator_responsibilities": sanitize_notes(self.operator_responsibilities),
            "advisory_notes": sanitize_notes(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "certification_claimed": False,
            "export_safe": True,
            **COMPLIANCE_PROFILE_SAFETY_FLAGS,
        }


def build_compliance_profile(
    *,
    profile_id: Any = "",
    profile_name: Any = "",
    profile_type: Any = "unknown",
    profile_state: Any = "",
    evidence_expectations: Iterable[EvidenceExpectationRecord | dict[str, Any] | Any] | None = None,
    audit_requirements: dict[str, Any] | None = None,
    retention_expectations: dict[str, Any] | None = None,
    privacy_requirements: dict[str, Any] | None = None,
    export_requirements: dict[str, Any] | None = None,
    operator_responsibilities: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> ComplianceProfileRecord:
    normalized_type = normalize_compliance_profile_type(profile_type)
    evidence_rows = normalize_evidence_rows(evidence_expectations, profile_type=normalized_type)
    audit = sanitize_text_map(audit_requirements or default_audit_requirements(normalized_type))
    retention = sanitize_text_map(retention_expectations or default_retention_expectations(normalized_type))
    privacy = sanitize_text_map(privacy_requirements or default_privacy_requirements(normalized_type))
    export = sanitize_text_map(export_requirements or default_export_requirements(normalized_type))
    responsibilities = sanitize_notes(
        operator_responsibilities
        or [
            "review evidence expectations before sharing exports",
            "confirm local policy fit with responsible governance stakeholders",
            "treat this profile as advisory readiness guidance",
        ]
    )
    notes = sanitize_notes(advisory_notes or ["metadata-only compliance profile; no certification or control enforcement is claimed"])
    state = normalize_compliance_profile_state(profile_state) if profile_state else infer_compliance_profile_state(evidence_rows)
    name = sanitize_text(profile_name) or default_profile_name(normalized_type)
    safe_id = sanitize_reference(profile_id)
    if not safe_id:
        safe_id = "compliance-profile-" + digest(
            {
                "profile_name": name,
                "profile_type": normalized_type,
                "evidence_count": len(evidence_rows),
            }
        )[:16]
    return ComplianceProfileRecord(
        profile_id=safe_id,
        profile_name=name,
        profile_type=normalized_type,
        profile_state=state,
        evidence_expectations=evidence_rows,
        audit_requirements=audit,
        retention_expectations=retention,
        privacy_requirements=privacy,
        export_requirements=export,
        operator_responsibilities=responsibilities,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
        certification_claimed=False,
    )


def normalize_compliance_profile(value: Any) -> ComplianceProfileRecord:
    if isinstance(value, ComplianceProfileRecord):
        return value
    if not isinstance(value, dict):
        return build_compliance_profile(
            profile_type="unknown",
            profile_state="degraded",
            advisory_notes=["invalid compliance profile generated from malformed input"],
        )
    try:
        return build_compliance_profile(
            profile_id=value.get("profile_id", ""),
            profile_name=value.get("profile_name", value.get("name", "")),
            profile_type=value.get("profile_type", value.get("type", "unknown")),
            profile_state=value.get("profile_state", value.get("state", "")),
            evidence_expectations=value.get("evidence_expectations") if isinstance(value.get("evidence_expectations"), list) else None,
            audit_requirements=value.get("audit_requirements") if isinstance(value.get("audit_requirements"), dict) else None,
            retention_expectations=value.get("retention_expectations") if isinstance(value.get("retention_expectations"), dict) else None,
            privacy_requirements=value.get("privacy_requirements") if isinstance(value.get("privacy_requirements"), dict) else None,
            export_requirements=value.get("export_requirements") if isinstance(value.get("export_requirements"), dict) else None,
            operator_responsibilities=value.get("operator_responsibilities") if isinstance(value.get("operator_responsibilities"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_compliance_profile(profile_state="degraded", advisory_notes=[str(exc)])


def normalize_evidence_rows(
    evidence_expectations: Iterable[EvidenceExpectationRecord | dict[str, Any] | Any] | None,
    *,
    profile_type: str,
) -> list[dict[str, Any]]:
    records = list(evidence_expectations or default_evidence_expectations(profile_type))
    return [normalize_evidence_expectation(record).to_dict() for record in records[:32]]


def default_evidence_expectations(profile_type: str) -> list[EvidenceExpectationRecord]:
    type_map = {
        "internal_audit": ["audit_events", "export_summaries", "runtime_logs"],
        "privacy_review": ["export_summaries", "configuration_snapshots", "audit_events"],
        "security_review": ["security_reviews", "configuration_snapshots", "policy_reviews"],
        "incident_review": ["audit_events", "runtime_logs", "remediation_previews"],
        "enterprise_readiness": ["audit_events", "export_summaries", "security_reviews", "policy_reviews"],
        "custom": ["audit_events"],
        "unknown": ["audit_events"],
    }
    return [
        build_evidence_expectation(
            evidence_type=evidence_type,
            export_required=evidence_type in {"audit_events", "export_summaries", "security_reviews"},
        )
        for evidence_type in type_map.get(profile_type, ["audit_events"])
    ]


def default_audit_requirements(profile_type: str) -> dict[str, Any]:
    return {
        "audit_events_expected": True,
        "last_export_summary_expected": profile_type in {"internal_audit", "privacy_review", "enterprise_readiness"},
        "daily_rotation_readiness_expected": True,
    }


def default_retention_expectations(profile_type: str) -> dict[str, Any]:
    return {
        "retention_days": 90 if profile_type == "enterprise_readiness" else 30,
        "retention_preview_only": True,
        "destructive_deletion_allowed": False,
    }


def default_privacy_requirements(profile_type: str) -> dict[str, Any]:
    return {
        "redaction_required": True,
        "private_identifier_export_allowed": False,
        "operator_review_required": True,
    }


def default_export_requirements(profile_type: str) -> dict[str, Any]:
    return {
        "export_validation_summary_expected": True,
        "sensitive_data_scan_expected": True,
        "artifact_check_expected": True,
        "private_export_read_by_default": False,
    }


def infer_compliance_profile_state(evidence_rows: list[dict[str, Any]]) -> str:
    states = {row.get("evidence_state", "unknown") for row in evidence_rows}
    if not evidence_rows:
        return "incomplete"
    if "degraded" in states:
        return "degraded"
    if "missing" in states:
        return "incomplete"
    if "partial" in states or "unknown" in states:
        return "advisory"
    return "ready"


def default_profile_name(profile_type: str) -> str:
    return {
        "internal_audit": "Internal audit readiness",
        "privacy_review": "Privacy review readiness",
        "security_review": "Security review readiness",
        "incident_review": "Incident review readiness",
        "enterprise_readiness": "Enterprise readiness",
        "custom": "Custom compliance readiness",
    }.get(profile_type, "Compliance profile")


def normalize_compliance_profile_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in COMPLIANCE_PROFILE_TYPES else "unknown"


def normalize_compliance_profile_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in COMPLIANCE_PROFILE_STATES else "unknown"


def deterministic_compliance_profile_json(record: ComplianceProfileRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, ComplianceProfileRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "COMPLIANCE_PROFILE_SAFETY_FLAGS",
    "COMPLIANCE_PROFILE_STATES",
    "COMPLIANCE_PROFILE_TYPES",
    "ComplianceProfileRecord",
    "build_compliance_profile",
    "deterministic_compliance_profile_json",
    "normalize_compliance_profile",
    "normalize_compliance_profile_state",
    "normalize_compliance_profile_type",
]
