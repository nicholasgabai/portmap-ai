from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from core_engine.governance.audit_events import sanitize_notes
from core_engine.governance.data_governance import sanitize_summary
from core_engine.governance.security_reviews import SECURITY_REVIEW_SAFETY_FLAGS
from core_engine.scaling.bus_envelopes import digest, normalize_source_mode, sanitize_reference, sanitize_token


PRIVACY_REVIEW_RECORD_VERSION = 1
PRIVACY_REVIEW_CATEGORIES = {
    "export_privacy",
    "audit_privacy",
    "governance_privacy",
    "operator_privacy",
    "deployment_privacy",
    "runtime_privacy",
    "documentation_privacy",
    "unknown",
}
PRIVACY_REVIEW_STATES = {"ready", "review_required", "incomplete", "degraded", "unavailable", "unknown"}
PRIVACY_SAFEGUARD_SAFETY_FLAGS = {
    **SECURITY_REVIEW_SAFETY_FLAGS,
    "legal_analysis_performed": False,
    "legal_advice_provided": False,
    "certification_claimed": False,
    "privacy_control_enforced": False,
    "data_deleted": False,
}


@dataclass(frozen=True)
class PrivacyReviewRecord:
    review_id: str
    review_type: str
    review_category: str
    review_state: str
    privacy_scope: str
    redaction_requirements: dict[str, Any] = field(default_factory=dict)
    notice_requirements: dict[str, Any] = field(default_factory=dict)
    consent_requirements: dict[str, Any] = field(default_factory=dict)
    export_requirements: dict[str, Any] = field(default_factory=dict)
    governance_references: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False
    legal_advice_provided: bool = False

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "privacy_review_record",
            "record_version": PRIVACY_REVIEW_RECORD_VERSION,
            "review_id": sanitize_reference(self.review_id) or "privacy-review-unknown",
            "review_type": sanitize_token(self.review_type).lower() or "unknown",
            "review_category": normalize_privacy_review_category(self.review_category),
            "review_state": normalize_privacy_review_state(self.review_state),
            "privacy_scope": sanitize_token(self.privacy_scope).lower() or "unknown",
            "redaction_requirements": sanitize_summary(self.redaction_requirements),
            "notice_requirements": sanitize_summary(self.notice_requirements),
            "consent_requirements": sanitize_summary(self.consent_requirements),
            "export_requirements": sanitize_summary(self.export_requirements),
            "governance_references": sanitize_reference_list(self.governance_references),
            "advisory_notes": sanitize_notes(self.advisory_notes),
            "source_mode": mode,
            "data_source": mode,
            "preview_only": True,
            "destructive_action": False,
            "legal_advice_provided": False,
            "export_safe": True,
            **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
        }


def build_privacy_review(
    *,
    review_id: Any = "",
    review_type: Any = "unknown",
    review_category: Any = "unknown",
    review_state: Any = "",
    privacy_scope: Any = "",
    redaction_requirements: dict[str, Any] | None = None,
    notice_requirements: dict[str, Any] | None = None,
    consent_requirements: dict[str, Any] | None = None,
    export_requirements: dict[str, Any] | None = None,
    governance_references: list[Any] | None = None,
    advisory_notes: list[Any] | None = None,
    source_mode: Any = "unknown",
) -> PrivacyReviewRecord:
    category = normalize_privacy_review_category(review_category)
    redaction = sanitize_summary(redaction_requirements or default_redaction_requirements(category))
    notice = sanitize_summary(notice_requirements or default_notice_requirements(category))
    consent = sanitize_summary(consent_requirements or default_consent_requirements(category))
    export = sanitize_summary(export_requirements or default_export_requirements(category))
    state = normalize_privacy_review_state(review_state) if review_state else infer_privacy_review_state(redaction, notice, consent, export)
    scope = sanitize_token(privacy_scope).lower() or category
    governance = sanitize_reference_list(governance_references or [])
    notes = sanitize_notes(advisory_notes or ["privacy review is metadata-only and advisory"])
    safe_id = sanitize_reference(review_id)
    if not safe_id:
        safe_id = "privacy-review-" + digest(
            {
                "review_type": sanitize_token(review_type).lower(),
                "review_category": category,
                "review_state": state,
                "privacy_scope": scope,
                "source_mode": normalize_source_mode(source_mode),
            }
        )[:16]
    return PrivacyReviewRecord(
        review_id=safe_id,
        review_type=sanitize_token(review_type).lower() or "unknown",
        review_category=category,
        review_state=state,
        privacy_scope=scope,
        redaction_requirements=redaction,
        notice_requirements=notice,
        consent_requirements=consent,
        export_requirements=export,
        governance_references=governance,
        advisory_notes=notes,
        source_mode=normalize_source_mode(source_mode),
        preview_only=True,
        destructive_action=False,
        legal_advice_provided=False,
    )


def normalize_privacy_review(value: Any) -> PrivacyReviewRecord:
    if isinstance(value, PrivacyReviewRecord):
        return value
    if not isinstance(value, dict):
        return build_privacy_review(
            review_type="invalid",
            review_state="degraded",
            advisory_notes=["invalid privacy review generated from malformed input"],
        )
    try:
        return build_privacy_review(
            review_id=value.get("review_id", ""),
            review_type=value.get("review_type", value.get("type", "unknown")),
            review_category=value.get("review_category", value.get("category", "unknown")),
            review_state=value.get("review_state", value.get("state", "")),
            privacy_scope=value.get("privacy_scope", value.get("scope", "")),
            redaction_requirements=value.get("redaction_requirements") if isinstance(value.get("redaction_requirements"), dict) else None,
            notice_requirements=value.get("notice_requirements") if isinstance(value.get("notice_requirements"), dict) else None,
            consent_requirements=value.get("consent_requirements") if isinstance(value.get("consent_requirements"), dict) else None,
            export_requirements=value.get("export_requirements") if isinstance(value.get("export_requirements"), dict) else None,
            governance_references=value.get("governance_references") if isinstance(value.get("governance_references"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
            source_mode=value.get("source_mode", value.get("data_source", "unknown")),
        )
    except Exception as exc:
        return build_privacy_review(review_state="degraded", advisory_notes=[str(exc)])


def summarize_privacy_reviews(reviews: list[PrivacyReviewRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_privacy_review(review).to_dict() for review in list(reviews or [])]
    category_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in rows:
        category_counts[row["review_category"]] = category_counts.get(row["review_category"], 0) + 1
        state_counts[row["review_state"]] = state_counts.get(row["review_state"], 0) + 1
    return {
        "record_type": "privacy_review_summary",
        "review_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "redaction_required_count": sum(1 for row in rows if row.get("redaction_requirements", {}).get("redaction_required")),
        "notice_required_count": sum(1 for row in rows if row.get("notice_requirements", {}).get("notice_required")),
        "consent_review_required_count": sum(1 for row in rows if row.get("consent_requirements", {}).get("consent_review_required")),
        "export_review_required_count": sum(1 for row in rows if row.get("export_requirements", {}).get("export_review_required")),
        "preview_only": True,
        "destructive_action": False,
        "legal_advice_provided": False,
        "certification_claimed": False,
        "export_safe": True,
        **PRIVACY_SAFEGUARD_SAFETY_FLAGS,
    }


def default_redaction_requirements(category: str) -> dict[str, Any]:
    return {
        "redaction_required": category in {"export_privacy", "audit_privacy", "governance_privacy", "operator_privacy"},
        "private_identifier_export_allowed": False,
        "raw_payload_allowed": False,
        "raw_dns_history_allowed": False,
    }


def default_notice_requirements(category: str) -> dict[str, Any]:
    return {
        "notice_required": category in {"deployment_privacy", "runtime_privacy", "documentation_privacy", "export_privacy"},
        "operator_notice_preview_only": True,
    }


def default_consent_requirements(category: str) -> dict[str, Any]:
    return {
        "consent_review_required": category in {"deployment_privacy", "runtime_privacy", "operator_privacy"},
        "consent_record_created": False,
    }


def default_export_requirements(category: str) -> dict[str, Any]:
    return {
        "export_review_required": category in {"export_privacy", "audit_privacy", "governance_privacy"},
        "sensitive_data_scan_expected": True,
        "artifact_check_expected": True,
        "private_export_read_by_default": False,
    }


def infer_privacy_review_state(*requirements: dict[str, Any]) -> str:
    if any(requirement.get("redaction_required") or requirement.get("notice_required") or requirement.get("consent_review_required") or requirement.get("export_review_required") for requirement in requirements):
        return "review_required"
    return "ready"


def sanitize_reference_list(values: list[Any]) -> list[str]:
    return [item for item in (sanitize_reference(value) for value in values) if item][:32]


def normalize_privacy_review_category(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in PRIVACY_REVIEW_CATEGORIES else "unknown"


def normalize_privacy_review_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in PRIVACY_REVIEW_STATES else "unknown"


def deterministic_privacy_review_json(record: PrivacyReviewRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, PrivacyReviewRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "PRIVACY_REVIEW_CATEGORIES",
    "PRIVACY_REVIEW_STATES",
    "PRIVACY_SAFEGUARD_SAFETY_FLAGS",
    "PrivacyReviewRecord",
    "build_privacy_review",
    "deterministic_privacy_review_json",
    "normalize_privacy_review",
    "normalize_privacy_review_category",
    "normalize_privacy_review_state",
    "summarize_privacy_reviews",
]
