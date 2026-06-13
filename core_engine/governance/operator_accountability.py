from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import sanitize_notes
from core_engine.governance.compliance_profiles import ComplianceProfileRecord, normalize_compliance_profile
from core_engine.governance.data_governance import DataGovernanceControlSummary, sanitize_summary
from core_engine.governance.operator_actions import (
    OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    OperatorActionRecord,
    normalize_operator_action,
    sanitize_operator_reference,
    summarize_operator_actions,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_token


OPERATOR_ACCOUNTABILITY_RECORD_VERSION = 1
ACCOUNTABILITY_STATES = {"ready", "review_recommended", "approval_required", "degraded", "unavailable", "unknown"}


@dataclass(frozen=True)
class OperatorAccountabilitySummary:
    accountability_id: str
    generated_at: str
    accountability_state: str
    operator_actions: list[dict[str, Any]] = field(default_factory=list)
    approval_summary: dict[str, Any] = field(default_factory=dict)
    reviewer_chain_summary: dict[str, Any] = field(default_factory=dict)
    role_mapping_summary: dict[str, Any] = field(default_factory=dict)
    governance_summary: dict[str, Any] = field(default_factory=dict)
    audit_summary: dict[str, Any] = field(default_factory=dict)
    compliance_summary: dict[str, Any] = field(default_factory=dict)
    evidence_summary: dict[str, Any] = field(default_factory=dict)
    accountability_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "operator_accountability_summary",
            "record_version": OPERATOR_ACCOUNTABILITY_RECORD_VERSION,
            "accountability_id": sanitize_reference(self.accountability_id) or "operator-accountability-unknown",
            "generated_at": str(self.generated_at or ""),
            "accountability_state": normalize_accountability_state(self.accountability_state),
            "operator_actions": list(self.operator_actions),
            "operator_action_summary": summarize_operator_actions(self.operator_actions),
            "approval_summary": dict(self.approval_summary),
            "reviewer_chain_summary": dict(self.reviewer_chain_summary),
            "role_mapping_summary": dict(self.role_mapping_summary),
            "governance_summary": dict(self.governance_summary),
            "audit_summary": dict(self.audit_summary),
            "compliance_summary": dict(self.compliance_summary),
            "evidence_summary": dict(self.evidence_summary),
            "accountability_recommendations": sanitize_notes(self.accountability_recommendations),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
        }


def build_operator_accountability_summary(
    *,
    accountability_id: Any = "",
    generated_at: Any = None,
    accountability_state: Any = "",
    operator_actions: Iterable[OperatorActionRecord | dict[str, Any] | Any] | None = None,
    audit_summary: dict[str, Any] | None = None,
    compliance_profiles: Iterable[ComplianceProfileRecord | dict[str, Any] | Any] | None = None,
    governance_summaries: Iterable[DataGovernanceControlSummary | dict[str, Any] | Any] | None = None,
    evidence_summary: dict[str, Any] | None = None,
    accountability_recommendations: Iterable[Any] | None = None,
) -> OperatorAccountabilitySummary:
    timestamp = str(generated_at or now_timestamp())
    action_rows = normalize_operator_action_rows(operator_actions)
    audit_row = sanitize_summary(audit_summary or {})
    compliance_rows = [normalize_compliance_profile(profile).to_dict() for profile in list(compliance_profiles or [])[:16]]
    governance_rows = normalize_governance_summary_rows(governance_summaries)
    evidence_row = sanitize_summary(evidence_summary or build_accountability_evidence_summary(action_rows, audit_row, compliance_rows, governance_rows))
    approval = build_approval_summary(action_rows)
    reviewers = build_reviewer_chain_summary(action_rows)
    roles = build_role_mapping_summary(action_rows)
    governance = build_governance_link_summary(governance_rows)
    audit = build_audit_link_summary(audit_row)
    compliance = build_compliance_link_summary(compliance_rows)
    recommendations = sanitize_notes(
        accountability_recommendations
        or build_accountability_recommendations(
            action_rows=action_rows,
            approval_summary=approval,
            reviewer_chain_summary=reviewers,
            governance_summary=governance,
        )
    )
    state = (
        normalize_accountability_state(accountability_state)
        if accountability_state
        else infer_accountability_state(action_rows, approval, reviewers)
    )
    safe_id = sanitize_reference(accountability_id)
    if not safe_id:
        safe_id = "operator-accountability-" + digest(
            {
                "generated_at": timestamp,
                "action_count": len(action_rows),
                "approval_state": state,
                "governance_count": len(governance_rows),
                "compliance_count": len(compliance_rows),
            }
        )[:16]
    return OperatorAccountabilitySummary(
        accountability_id=safe_id,
        generated_at=timestamp,
        accountability_state=state,
        operator_actions=action_rows,
        approval_summary=approval,
        reviewer_chain_summary=reviewers,
        role_mapping_summary=roles,
        governance_summary=governance,
        audit_summary=audit,
        compliance_summary=compliance,
        evidence_summary=evidence_row,
        accountability_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_operator_accountability_summary(*, generated_at: Any = None) -> OperatorAccountabilitySummary:
    return build_operator_accountability_summary(
        generated_at=generated_at,
        accountability_state="unavailable",
        operator_actions=[],
        audit_summary={},
        compliance_profiles=[],
        governance_summaries=[],
        evidence_summary={"record_type": "accountability_evidence_summary", "evidence_reference_count": 0},
        accountability_recommendations=["no operator accountability inputs supplied"],
    )


def normalize_operator_action_rows(values: Iterable[OperatorActionRecord | dict[str, Any] | Any] | None) -> list[dict[str, Any]]:
    records = [] if values is None else list(values)
    return [normalize_operator_action(record).to_dict() for record in records[:64]]


def normalize_governance_summary_rows(
    values: Iterable[DataGovernanceControlSummary | dict[str, Any] | Any] | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in list(values or [])[:16]:
        if isinstance(value, DataGovernanceControlSummary):
            rows.append(value.to_dict())
        elif isinstance(value, dict):
            rows.append(sanitize_summary(value))
        else:
            rows.append({"record_type": "governance_summary", "governance_state": "degraded", "preview_only": True, "destructive_action": False, "export_safe": True})
    return rows


def build_approval_summary(action_rows: list[dict[str, Any]]) -> dict[str, Any]:
    approval_counts: dict[str, int] = {}
    for row in action_rows:
        approval = sanitize_token(row.get("approval_state", "unknown")).lower() or "unknown"
        approval_counts[approval] = approval_counts.get(approval, 0) + 1
    return {
        "record_type": "approval_readiness_summary",
        "action_count": len(action_rows),
        "approval_counts": dict(sorted(approval_counts.items())),
        "approval_required_count": approval_counts.get("pending", 0) + approval_counts.get("review_required", 0),
        "rejected_count": approval_counts.get("rejected", 0),
        "authorization_performed": False,
        "permissions_enforced": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_reviewer_chain_summary(action_rows: list[dict[str, Any]]) -> dict[str, Any]:
    reviewers = [
        sanitize_operator_reference(row.get("reviewer_reference"), default="reviewer-unknown")
        for row in action_rows
    ]
    known = [reviewer for reviewer in reviewers if reviewer != "reviewer-unknown"]
    return {
        "record_type": "reviewer_chain_summary",
        "action_count": len(action_rows),
        "reviewer_reference_count": len(known),
        "unique_reviewer_reference_count": len(set(known)),
        "missing_reviewer_count": len(action_rows) - len(known),
        "reviewer_references": sorted(set(known))[:32],
        "identity_stored": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_role_mapping_summary(action_rows: list[dict[str, Any]]) -> dict[str, Any]:
    category_scopes: dict[str, str] = {
        "export": "export_reviewer",
        "policy_review": "policy_reviewer",
        "remediation_preview": "remediation_reviewer",
        "configuration_review": "configuration_reviewer",
        "packaging_review": "packaging_reviewer",
        "governance_review": "governance_reviewer",
        "security_review": "security_reviewer",
        "compliance_review": "compliance_reviewer",
        "unknown": "unknown",
    }
    mapped_scopes = sorted({category_scopes.get(row.get("action_category", "unknown"), "unknown") for row in action_rows})
    return {
        "record_type": "role_mapping_summary",
        "mapped_scope_count": len(mapped_scopes),
        "mapped_scopes": mapped_scopes[:32],
        "role_assignment_performed": False,
        "authorization_performed": False,
        "permissions_enforced": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_governance_link_summary(governance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    for row in governance_rows:
        state = sanitize_token(row.get("governance_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "accountability_governance_summary",
        "governance_summary_count": len(governance_rows),
        "state_counts": dict(sorted(state_counts.items())),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_audit_link_summary(audit_summary: dict[str, Any]) -> dict[str, Any]:
    row = sanitize_summary(audit_summary)
    return {
        "record_type": "accountability_audit_summary",
        "audit_event_count": int(row.get("event_count", 0)) if isinstance(row.get("event_count", 0), int) else 0,
        "category_counts": row.get("category_counts", {}) if isinstance(row.get("category_counts"), dict) else {},
        "state_counts": row.get("state_counts", {}) if isinstance(row.get("state_counts"), dict) else {},
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_compliance_link_summary(compliance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    type_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in compliance_rows:
        profile_type = sanitize_token(row.get("profile_type", "unknown")).lower() or "unknown"
        profile_state = sanitize_token(row.get("profile_state", "unknown")).lower() or "unknown"
        type_counts[profile_type] = type_counts.get(profile_type, 0) + 1
        state_counts[profile_state] = state_counts.get(profile_state, 0) + 1
    return {
        "record_type": "accountability_compliance_summary",
        "profile_count": len(compliance_rows),
        "type_counts": dict(sorted(type_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "certification_claimed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_accountability_evidence_summary(
    action_rows: list[dict[str, Any]],
    audit_summary: dict[str, Any],
    compliance_rows: list[dict[str, Any]],
    governance_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "record_type": "accountability_evidence_summary",
        "action_evidence_reference_count": sum(len(row.get("evidence_references", [])) for row in action_rows),
        "audit_reference_count": sum(len(row.get("audit_references", [])) for row in action_rows),
        "governance_reference_count": sum(len(row.get("governance_references", [])) for row in action_rows),
        "audit_event_count": int(audit_summary.get("event_count", 0)) if isinstance(audit_summary.get("event_count", 0), int) else 0,
        "compliance_profile_count": len(compliance_rows),
        "governance_summary_count": len(governance_rows),
        "identity_stored": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def build_accountability_recommendations(
    *,
    action_rows: list[dict[str, Any]],
    approval_summary: dict[str, Any],
    reviewer_chain_summary: dict[str, Any],
    governance_summary: dict[str, Any],
) -> list[str]:
    recommendations = ["review operator accountability summaries before sharing governance exports"]
    if approval_summary.get("approval_required_count", 0):
        recommendations.append("complete pending or review-required approvals before relying on accountability records")
    if reviewer_chain_summary.get("missing_reviewer_count", 0):
        recommendations.append("add reviewer references for actions that require review")
    if governance_summary.get("governance_summary_count", 0) == 0 and action_rows:
        recommendations.append("link operator actions to governance summaries where available")
    if any(row.get("action_state") in {"degraded", "unknown"} for row in action_rows):
        recommendations.append("resolve degraded or unknown operator action state")
    return recommendations


def infer_accountability_state(
    action_rows: list[dict[str, Any]],
    approval_summary: dict[str, Any],
    reviewer_chain_summary: dict[str, Any],
) -> str:
    if not action_rows:
        return "unavailable"
    states = {row.get("action_state", "unknown") for row in action_rows}
    if "degraded" in states or "unknown" in states:
        return "degraded"
    if approval_summary.get("approval_required_count", 0):
        return "approval_required"
    if approval_summary.get("rejected_count", 0) or reviewer_chain_summary.get("missing_reviewer_count", 0):
        return "review_recommended"
    return "ready"


def normalize_accountability_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in ACCOUNTABILITY_STATES else "unknown"


def deterministic_operator_accountability_json(record: OperatorAccountabilitySummary | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, OperatorAccountabilitySummary) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "ACCOUNTABILITY_STATES",
    "OPERATOR_ACCOUNTABILITY_RECORD_VERSION",
    "OperatorAccountabilitySummary",
    "build_operator_accountability_summary",
    "deterministic_operator_accountability_json",
    "empty_operator_accountability_summary",
    "normalize_accountability_state",
]
