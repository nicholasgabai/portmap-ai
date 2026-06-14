from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from core_engine.governance.audit_events import sanitize_notes
from core_engine.governance.compliance_profiles import ComplianceProfileRecord, normalize_compliance_profile
from core_engine.governance.data_governance import DataGovernanceControlSummary, sanitize_summary
from core_engine.governance.operator_accountability import OperatorAccountabilitySummary
from core_engine.governance.privacy_reviews import (
    PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    PrivacyReviewRecord,
    normalize_privacy_review,
    summarize_privacy_reviews,
)
from core_engine.governance.security_framework import SecurityFrameworkSummary
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_token


PRIVACY_SAFEGUARD_RECORD_VERSION = 1
PRIVACY_SAFEGUARD_STATES = {"ready", "review_recommended", "restricted", "degraded", "unavailable", "unknown"}


@dataclass(frozen=True)
class PrivacySafeguardSummary:
    safeguard_id: str
    generated_at: str
    safeguard_state: str
    privacy_reviews: list[dict[str, Any]] = field(default_factory=list)
    privacy_summary: dict[str, Any] = field(default_factory=dict)
    redaction_summary: dict[str, Any] = field(default_factory=dict)
    export_privacy_summary: dict[str, Any] = field(default_factory=dict)
    consent_notice_summary: dict[str, Any] = field(default_factory=dict)
    governance_summary: dict[str, Any] = field(default_factory=dict)
    accountability_summary: dict[str, Any] = field(default_factory=dict)
    security_review_summary: dict[str, Any] = field(default_factory=dict)
    legal_safeguard_notes: list[str] = field(default_factory=list)
    privacy_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True
    certification_claimed: bool = False
    legal_advice_provided: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "privacy_safeguard_summary",
            "record_version": PRIVACY_SAFEGUARD_RECORD_VERSION,
            "safeguard_id": sanitize_reference(self.safeguard_id) or "privacy-safeguard-unknown",
            "generated_at": str(self.generated_at or ""),
            "safeguard_state": normalize_privacy_safeguard_state(self.safeguard_state),
            "privacy_reviews": list(self.privacy_reviews),
            "privacy_review_summary": summarize_privacy_reviews(self.privacy_reviews),
            "privacy_summary": dict(self.privacy_summary),
            "redaction_summary": dict(self.redaction_summary),
            "export_privacy_summary": dict(self.export_privacy_summary),
            "consent_notice_summary": dict(self.consent_notice_summary),
            "governance_summary": dict(self.governance_summary),
            "accountability_summary": dict(self.accountability_summary),
            "security_review_summary": dict(self.security_review_summary),
            "legal_safeguard_notes": sanitize_notes(self.legal_safeguard_notes),
            "privacy_recommendations": sanitize_notes(self.privacy_recommendations),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            "certification_claimed": False,
            "legal_advice_provided": False,
            **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
        }


def build_privacy_safeguard_summary(
    *,
    safeguard_id: Any = "",
    generated_at: Any = None,
    safeguard_state: Any = "",
    privacy_reviews: list[PrivacyReviewRecord | dict[str, Any] | Any] | None = None,
    audit_summary: dict[str, Any] | None = None,
    compliance_profiles: list[ComplianceProfileRecord | dict[str, Any] | Any] | None = None,
    governance_summaries: list[DataGovernanceControlSummary | dict[str, Any] | Any] | None = None,
    accountability_summaries: list[OperatorAccountabilitySummary | dict[str, Any] | Any] | None = None,
    security_framework_summaries: list[SecurityFrameworkSummary | dict[str, Any] | Any] | None = None,
    legal_safeguard_notes: list[Any] | None = None,
    privacy_recommendations: list[Any] | None = None,
) -> PrivacySafeguardSummary:
    timestamp = str(generated_at or now_timestamp())
    review_rows = normalize_privacy_review_rows(privacy_reviews)
    audit_row = sanitize_summary(audit_summary or {})
    compliance_rows = [normalize_compliance_profile(profile).to_dict() for profile in list(compliance_profiles or [])[:16]]
    governance_rows = normalize_summary_rows(governance_summaries, object_type=DataGovernanceControlSummary, fallback_state_key="governance_state")
    accountability_rows = normalize_summary_rows(accountability_summaries, object_type=OperatorAccountabilitySummary, fallback_state_key="accountability_state")
    security_rows = normalize_summary_rows(security_framework_summaries, object_type=SecurityFrameworkSummary, fallback_state_key="framework_state")
    privacy = build_privacy_readiness_summary(review_rows, audit_row, compliance_rows)
    redaction = build_redaction_summary(review_rows, governance_rows)
    export_privacy = build_export_privacy_summary(review_rows, governance_rows)
    consent_notice = build_consent_notice_summary(review_rows)
    governance = build_governance_privacy_summary(governance_rows)
    accountability = build_accountability_privacy_summary(accountability_rows)
    security = build_security_privacy_summary(security_rows)
    notes = sanitize_notes(
        legal_safeguard_notes
        or [
            "privacy safeguard notes are advisory readiness metadata",
            "no legal advice or certification claim is provided",
        ]
    )
    recommendations = sanitize_notes(
        privacy_recommendations
        or build_privacy_recommendations(
            review_rows=review_rows,
            privacy_summary=privacy,
            redaction_summary=redaction,
            export_privacy_summary=export_privacy,
            consent_notice_summary=consent_notice,
            governance_summary=governance,
            security_review_summary=security,
        )
    )
    state = normalize_privacy_safeguard_state(safeguard_state) if safeguard_state else infer_privacy_safeguard_state(review_rows, redaction, export_privacy, consent_notice, governance)
    safe_id = sanitize_reference(safeguard_id)
    if not safe_id:
        safe_id = "privacy-safeguard-" + digest(
            {
                "generated_at": timestamp,
                "review_count": len(review_rows),
                "safeguard_state": state,
                "governance_count": len(governance_rows),
                "accountability_count": len(accountability_rows),
                "security_count": len(security_rows),
            }
        )[:16]
    return PrivacySafeguardSummary(
        safeguard_id=safe_id,
        generated_at=timestamp,
        safeguard_state=state,
        privacy_reviews=review_rows,
        privacy_summary=privacy,
        redaction_summary=redaction,
        export_privacy_summary=export_privacy,
        consent_notice_summary=consent_notice,
        governance_summary=governance,
        accountability_summary=accountability,
        security_review_summary=security,
        legal_safeguard_notes=notes,
        privacy_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
        certification_claimed=False,
        legal_advice_provided=False,
    )


def empty_privacy_safeguard_summary(*, generated_at: Any = None) -> PrivacySafeguardSummary:
    return build_privacy_safeguard_summary(
        generated_at=generated_at,
        safeguard_state="unavailable",
        privacy_reviews=[],
        audit_summary={},
        compliance_profiles=[],
        governance_summaries=[],
        accountability_summaries=[],
        security_framework_summaries=[],
        legal_safeguard_notes=["no privacy safeguard inputs supplied"],
        privacy_recommendations=["collect privacy review inputs before relying on safeguard summaries"],
    )


def normalize_privacy_review_rows(values: list[PrivacyReviewRecord | dict[str, Any] | Any] | None) -> list[dict[str, Any]]:
    records = [] if values is None else list(values)
    return [normalize_privacy_review(record).to_dict() for record in records[:64]]


def normalize_summary_rows(values: list[Any] | None, *, object_type: type, fallback_state_key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in list(values or [])[:16]:
        if isinstance(value, object_type):
            rows.append(value.to_dict())
        elif isinstance(value, dict):
            rows.append(sanitize_summary(value))
        else:
            rows.append({"record_type": "privacy_input_summary", fallback_state_key: "degraded", "preview_only": True, "destructive_action": False, "export_safe": True})
    return rows


def build_privacy_readiness_summary(review_rows: list[dict[str, Any]], audit_summary: dict[str, Any], compliance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    for row in review_rows:
        state = sanitize_token(row.get("review_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "privacy_readiness_summary",
        "review_count": len(review_rows),
        "state_counts": dict(sorted(state_counts.items())),
        "audit_event_count": int(audit_summary.get("event_count", 0)) if isinstance(audit_summary.get("event_count", 0), int) else 0,
        "compliance_profile_count": len(compliance_rows),
        "certification_claimed": False,
        "legal_advice_provided": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_redaction_summary(review_rows: list[dict[str, Any]], governance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    review_redaction_count = sum(1 for row in review_rows if row.get("redaction_requirements", {}).get("redaction_required"))
    governance_redaction_count = sum(int(row.get("redaction_readiness", {}).get("redaction_required_count", 0)) for row in governance_rows if isinstance(row.get("redaction_readiness"), dict))
    return {
        "record_type": "privacy_redaction_summary",
        "review_redaction_required_count": review_redaction_count,
        "governance_redaction_required_count": governance_redaction_count,
        "redaction_review_recommended": review_redaction_count > 0 or governance_redaction_count > 0,
        "private_identifier_export_allowed": False,
        "raw_payload_allowed": False,
        "raw_dns_history_allowed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_export_privacy_summary(review_rows: list[dict[str, Any]], governance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    export_review_count = sum(1 for row in review_rows if row.get("export_requirements", {}).get("export_review_required"))
    restricted_export_count = sum(int(row.get("export_governance_summary", {}).get("export_restricted_count", 0)) for row in governance_rows if isinstance(row.get("export_governance_summary"), dict))
    return {
        "record_type": "export_privacy_summary",
        "export_review_required_count": export_review_count,
        "governance_export_restricted_count": restricted_export_count,
        "private_export_read_by_default": False,
        "private_identifier_export_allowed": False,
        "sensitive_data_scan_expected": True,
        "artifact_check_expected": True,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_consent_notice_summary(review_rows: list[dict[str, Any]]) -> dict[str, Any]:
    notice_count = sum(1 for row in review_rows if row.get("notice_requirements", {}).get("notice_required"))
    consent_count = sum(1 for row in review_rows if row.get("consent_requirements", {}).get("consent_review_required"))
    return {
        "record_type": "consent_notice_readiness_summary",
        "notice_required_count": notice_count,
        "consent_review_required_count": consent_count,
        "notice_records_created": False,
        "consent_records_created": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_governance_privacy_summary(governance_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    for row in governance_rows:
        state = sanitize_token(row.get("governance_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "privacy_governance_summary",
        "governance_summary_count": len(governance_rows),
        "state_counts": dict(sorted(state_counts.items())),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_accountability_privacy_summary(accountability_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    for row in accountability_rows:
        state = sanitize_token(row.get("accountability_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "privacy_accountability_summary",
        "accountability_summary_count": len(accountability_rows),
        "state_counts": dict(sorted(state_counts.items())),
        "identity_stored": False,
        "authorization_performed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_security_privacy_summary(security_rows: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    for row in security_rows:
        state = sanitize_token(row.get("framework_state", "unknown")).lower() or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "record_type": "privacy_security_review_summary",
        "security_framework_summary_count": len(security_rows),
        "state_counts": dict(sorted(state_counts.items())),
        "security_scan_performed": False,
        "vulnerability_detection_performed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def build_privacy_recommendations(
    *,
    review_rows: list[dict[str, Any]],
    privacy_summary: dict[str, Any],
    redaction_summary: dict[str, Any],
    export_privacy_summary: dict[str, Any],
    consent_notice_summary: dict[str, Any],
    governance_summary: dict[str, Any],
    security_review_summary: dict[str, Any],
) -> list[str]:
    recommendations = ["review privacy safeguard summaries before sharing governance exports"]
    if redaction_summary.get("redaction_review_recommended"):
        recommendations.append("complete redaction review before export sharing")
    if export_privacy_summary.get("export_review_required_count", 0) or export_privacy_summary.get("governance_export_restricted_count", 0):
        recommendations.append("perform export privacy review before publishing bundles")
    if consent_notice_summary.get("notice_required_count", 0) or consent_notice_summary.get("consent_review_required_count", 0):
        recommendations.append("review operator notice and consent readiness with responsible stakeholders")
    if governance_summary.get("governance_summary_count", 0) == 0 and review_rows:
        recommendations.append("link data governance summaries to privacy reviews where available")
    if security_review_summary.get("security_framework_summary_count", 0) == 0 and review_rows:
        recommendations.append("link security framework summaries to privacy safeguards where available")
    if any(row.get("review_state") in {"degraded", "unknown"} for row in review_rows):
        recommendations.append("resolve degraded or unknown privacy review state")
    if not review_rows and privacy_summary.get("review_count", 0) == 0:
        recommendations.append("create privacy review records before relying on safeguard summary")
    return recommendations


def infer_privacy_safeguard_state(
    review_rows: list[dict[str, Any]],
    redaction_summary: dict[str, Any],
    export_privacy_summary: dict[str, Any],
    consent_notice_summary: dict[str, Any],
    governance_summary: dict[str, Any],
) -> str:
    if not review_rows:
        return "unavailable"
    states = {row.get("review_state", "unknown") for row in review_rows}
    if "degraded" in states or "unknown" in states:
        return "degraded"
    if "incomplete" in states:
        return "degraded"
    if governance_summary.get("state_counts", {}).get("restricted", 0):
        return "restricted"
    if (
        redaction_summary.get("redaction_review_recommended")
        or export_privacy_summary.get("export_review_required_count", 0)
        or consent_notice_summary.get("notice_required_count", 0)
        or consent_notice_summary.get("consent_review_required_count", 0)
        or "review_required" in states
    ):
        return "review_recommended"
    return "ready"


def normalize_privacy_safeguard_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in PRIVACY_SAFEGUARD_STATES else "unknown"


def deterministic_privacy_safeguard_json(record: PrivacySafeguardSummary | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, PrivacySafeguardSummary) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "PRIVACY_SAFEGUARD_STATES",
    "PrivacySafeguardSummary",
    "build_privacy_safeguard_summary",
    "deterministic_privacy_safeguard_json",
    "empty_privacy_safeguard_summary",
    "normalize_privacy_safeguard_state",
]
