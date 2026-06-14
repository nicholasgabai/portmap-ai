from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import sanitize_notes
from core_engine.governance.compliance_profiles import ComplianceProfileRecord, normalize_compliance_profile
from core_engine.governance.data_governance import DataGovernanceControlSummary, sanitize_summary
from core_engine.governance.operator_accountability import OperatorAccountabilitySummary
from core_engine.governance.security_reviews import (
    SECURITY_REVIEW_SAFETY_FLAGS,
    SecurityReviewRecord,
    normalize_security_review,
    summarize_security_reviews,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_token


SECURITY_FRAMEWORK_RECORD_VERSION = 1
SECURITY_FRAMEWORK_STATES = {"ready", "review_recommended", "incomplete", "degraded", "unavailable", "unknown"}


@dataclass(frozen=True)
class SecurityFrameworkSummary:
    framework_id: str
    generated_at: str
    framework_state: str
    security_reviews: list[dict[str, Any]] = field(default_factory=list)
    checklist_summary: dict[str, Any] = field(default_factory=dict)
    runtime_review_summary: dict[str, Any] = field(default_factory=dict)
    deployment_review_summary: dict[str, Any] = field(default_factory=dict)
    packaging_review_summary: dict[str, Any] = field(default_factory=dict)
    governance_review_summary: dict[str, Any] = field(default_factory=dict)
    accountability_review_summary: dict[str, Any] = field(default_factory=dict)
    compliance_review_summary: dict[str, Any] = field(default_factory=dict)
    review_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "security_framework_summary",
            "record_version": SECURITY_FRAMEWORK_RECORD_VERSION,
            "framework_id": sanitize_reference(self.framework_id) or "security-framework-unknown",
            "generated_at": str(self.generated_at or ""),
            "framework_state": normalize_security_framework_state(self.framework_state),
            "security_reviews": list(self.security_reviews),
            "security_review_summary": summarize_security_reviews(self.security_reviews),
            "checklist_summary": dict(self.checklist_summary),
            "runtime_review_summary": dict(self.runtime_review_summary),
            "deployment_review_summary": dict(self.deployment_review_summary),
            "packaging_review_summary": dict(self.packaging_review_summary),
            "governance_review_summary": dict(self.governance_review_summary),
            "accountability_review_summary": dict(self.accountability_review_summary),
            "compliance_review_summary": dict(self.compliance_review_summary),
            "review_recommendations": sanitize_notes(self.review_recommendations),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **SECURITY_REVIEW_SAFETY_FLAGS,
        }


def build_security_framework_summary(
    *,
    framework_id: Any = "",
    generated_at: Any = None,
    framework_state: Any = "",
    security_reviews: Iterable[SecurityReviewRecord | dict[str, Any] | Any] | None = None,
    audit_summary: dict[str, Any] | None = None,
    compliance_profiles: Iterable[ComplianceProfileRecord | dict[str, Any] | Any] | None = None,
    governance_summaries: Iterable[DataGovernanceControlSummary | dict[str, Any] | Any] | None = None,
    accountability_summaries: Iterable[OperatorAccountabilitySummary | dict[str, Any] | Any] | None = None,
    review_recommendations: Iterable[Any] | None = None,
) -> SecurityFrameworkSummary:
    timestamp = str(generated_at or now_timestamp())
    review_rows = normalize_security_review_rows(security_reviews)
    audit_row = sanitize_summary(audit_summary or {})
    compliance_rows = [normalize_compliance_profile(profile).to_dict() for profile in list(compliance_profiles or [])[:16]]
    governance_rows = normalize_governance_summary_rows(governance_summaries)
    accountability_rows = normalize_accountability_summary_rows(accountability_summaries)
    checklist = build_checklist_summary(review_rows)
    runtime = build_category_review_summary(review_rows, "runtime")
    deployment = build_category_review_summary(review_rows, "deployment")
    packaging = build_category_review_summary(review_rows, "packaging")
    governance = build_governance_review_summary(review_rows, governance_rows)
    accountability = build_accountability_review_summary(review_rows, accountability_rows)
    compliance = build_compliance_review_summary(review_rows, compliance_rows, audit_row)
    recommendations = sanitize_notes(
        review_recommendations
        or build_review_recommendations(
            review_rows=review_rows,
            checklist_summary=checklist,
            governance_review_summary=governance,
            accountability_review_summary=accountability,
            compliance_review_summary=compliance,
        )
    )
    state = normalize_security_framework_state(framework_state) if framework_state else infer_security_framework_state(review_rows, checklist)
    safe_id = sanitize_reference(framework_id)
    if not safe_id:
        safe_id = "security-framework-" + digest(
            {
                "generated_at": timestamp,
                "review_count": len(review_rows),
                "framework_state": state,
                "governance_count": len(governance_rows),
                "accountability_count": len(accountability_rows),
                "compliance_count": len(compliance_rows),
            }
        )[:16]
    return SecurityFrameworkSummary(
        framework_id=safe_id,
        generated_at=timestamp,
        framework_state=state,
        security_reviews=review_rows,
        checklist_summary=checklist,
        runtime_review_summary=runtime,
        deployment_review_summary=deployment,
        packaging_review_summary=packaging,
        governance_review_summary=governance,
        accountability_review_summary=accountability,
        compliance_review_summary=compliance,
        review_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_security_framework_summary(*, generated_at: Any = None) -> SecurityFrameworkSummary:
    return build_security_framework_summary(
        generated_at=generated_at,
        framework_state="unavailable",
        security_reviews=[],
        audit_summary={},
        compliance_profiles=[],
        governance_summaries=[],
        accountability_summaries=[],
        review_recommendations=["no security review inputs supplied"],
    )


def normalize_security_review_rows(values: Iterable[SecurityReviewRecord | dict[str, Any] | Any] | None) -> list[dict[str, Any]]:
    records = [] if values is None else list(values)
    return [normalize_security_review(record).to_dict() for record in records[:64]]


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


def normalize_accountability_summary_rows(
    values: Iterable[OperatorAccountabilitySummary | dict[str, Any] | Any] | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in list(values or [])[:16]:
        if isinstance(value, OperatorAccountabilitySummary):
            rows.append(value.to_dict())
        elif isinstance(value, dict):
            rows.append(sanitize_summary(value))
        else:
            rows.append({"record_type": "operator_accountability_summary", "accountability_state": "degraded", "preview_only": True, "destructive_action": False, "export_safe": True})
    return rows


def build_checklist_summary(review_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    total = 0
    required_count = 0
    for row in review_rows:
        for item in row.get("checklist_items", []):
            total += 1
            if item.get("required", True):
                required_count += 1
            state = sanitize_token(item.get("item_state", "unknown")).lower() or "unknown"
            state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "security_checklist_summary",
        "checklist_item_count": total,
        "required_item_count": required_count,
        "state_counts": dict(sorted(state_counts.items())),
        "review_required_count": state_counts.get("review_required", 0),
        "incomplete_count": state_counts.get("incomplete", 0),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **SECURITY_REVIEW_SAFETY_FLAGS,
    }


def build_category_review_summary(review_rows: list[dict[str, Any]], category: str) -> dict[str, Any]:
    matching = [row for row in review_rows if row.get("review_category") == category]
    state_counts: dict[str, int] = {}
    for row in matching:
        state = sanitize_token(row.get("review_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": f"{category}_security_review_summary",
        "review_category": category,
        "review_count": len(matching),
        "state_counts": dict(sorted(state_counts.items())),
        "checklist_item_count": sum(len(row.get("checklist_items", [])) for row in matching),
        "evidence_reference_count": sum(len(row.get("evidence_references", [])) for row in matching),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **SECURITY_REVIEW_SAFETY_FLAGS,
    }


def build_governance_review_summary(review_rows: list[dict[str, Any]], governance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    base = build_category_review_summary(review_rows, "governance")
    state_counts: dict[str, int] = {}
    for row in governance_rows:
        state = sanitize_token(row.get("governance_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        **base,
        "record_type": "governance_security_review_summary",
        "governance_summary_count": len(governance_rows),
        "governance_state_counts": dict(sorted(state_counts.items())),
    }


def build_accountability_review_summary(review_rows: list[dict[str, Any]], accountability_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    for row in accountability_rows:
        state = sanitize_token(row.get("accountability_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "accountability_security_review_summary",
        "accountability_summary_count": len(accountability_rows),
        "accountability_state_counts": dict(sorted(state_counts.items())),
        "accountability_reference_count": sum(len(row.get("accountability_references", [])) for row in review_rows),
        "authorization_performed": False,
        "permissions_enforced": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **SECURITY_REVIEW_SAFETY_FLAGS,
    }


def build_compliance_review_summary(
    review_rows: list[dict[str, Any]],
    compliance_rows: list[dict[str, Any]],
    audit_summary: dict[str, Any],
) -> dict[str, Any]:
    type_counts: dict[str, int] = {}
    for row in compliance_rows:
        profile_type = sanitize_token(row.get("profile_type", "unknown")).lower() or "unknown"
        type_counts[profile_type] = type_counts.get(profile_type, 0) + 1
    compliance_reviews = [row for row in review_rows if row.get("review_category") == "compliance"]
    return {
        "record_type": "compliance_security_review_summary",
        "review_count": len(compliance_reviews),
        "profile_count": len(compliance_rows),
        "profile_type_counts": dict(sorted(type_counts.items())),
        "audit_event_count": int(audit_summary.get("event_count", 0)) if isinstance(audit_summary.get("event_count", 0), int) else 0,
        "certification_claimed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **SECURITY_REVIEW_SAFETY_FLAGS,
    }


def build_review_recommendations(
    *,
    review_rows: list[dict[str, Any]],
    checklist_summary: dict[str, Any],
    governance_review_summary: dict[str, Any],
    accountability_review_summary: dict[str, Any],
    compliance_review_summary: dict[str, Any],
) -> list[str]:
    recommendations = ["review security framework summaries before deployment decisions"]
    if checklist_summary.get("review_required_count", 0):
        recommendations.append("complete review-required checklist items")
    if checklist_summary.get("incomplete_count", 0):
        recommendations.append("resolve incomplete checklist items")
    if governance_review_summary.get("governance_summary_count", 0) == 0 and review_rows:
        recommendations.append("link governance summaries to security reviews where available")
    if accountability_review_summary.get("accountability_summary_count", 0) == 0 and review_rows:
        recommendations.append("link accountability summaries to security reviews where available")
    if compliance_review_summary.get("profile_count", 0) == 0 and any(row.get("review_category") == "compliance" for row in review_rows):
        recommendations.append("link compliance profiles for compliance review scope")
    if any(row.get("review_state") in {"degraded", "unknown"} for row in review_rows):
        recommendations.append("resolve degraded or unknown security review state")
    return recommendations


def infer_security_framework_state(review_rows: list[dict[str, Any]], checklist_summary: dict[str, Any]) -> str:
    if not review_rows:
        return "unavailable"
    states = {row.get("review_state", "unknown") for row in review_rows}
    if "degraded" in states or "unknown" in states:
        return "degraded"
    if "incomplete" in states or checklist_summary.get("incomplete_count", 0):
        return "incomplete"
    if "review_required" in states or checklist_summary.get("review_required_count", 0):
        return "review_recommended"
    return "ready"


def normalize_security_framework_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in SECURITY_FRAMEWORK_STATES else "unknown"


def deterministic_security_framework_json(record: SecurityFrameworkSummary | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, SecurityFrameworkSummary) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "SECURITY_FRAMEWORK_STATES",
    "SecurityFrameworkSummary",
    "build_security_framework_summary",
    "deterministic_security_framework_json",
    "empty_security_framework_summary",
    "normalize_security_framework_state",
]
