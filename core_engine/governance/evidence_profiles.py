from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes, sanitize_references
from core_engine.scaling.bus_envelopes import digest, safe_int, sanitize_text, sanitize_token


EVIDENCE_PROFILE_RECORD_VERSION = 1
EVIDENCE_TYPES = {
    "audit_events",
    "runtime_logs",
    "export_summaries",
    "policy_reviews",
    "remediation_previews",
    "configuration_snapshots",
    "security_reviews",
    "unknown",
}
EVIDENCE_STATES = {"ready", "partial", "missing", "degraded", "unknown"}
EVIDENCE_PROFILE_SAFETY_FLAGS = {
    **GOVERNANCE_SAFETY_FLAGS,
    "file_read_performed": False,
    "control_enforced": False,
    "legal_claim_created": False,
    "certification_claimed": False,
}


@dataclass(frozen=True)
class EvidenceExpectationRecord:
    evidence_profile_id: str
    evidence_type: str
    evidence_state: str
    expected_sources: list[str] = field(default_factory=list)
    required_fields: list[str] = field(default_factory=list)
    retention_expectation_days: int = 0
    redaction_required: bool = True
    export_required: bool = False
    validation_recommendations: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "evidence_expectation",
            "record_version": EVIDENCE_PROFILE_RECORD_VERSION,
            "evidence_profile_id": sanitize_token(self.evidence_profile_id) or "evidence-profile-unknown",
            "evidence_type": normalize_evidence_type(self.evidence_type),
            "evidence_state": normalize_evidence_state(self.evidence_state),
            "expected_sources": sanitize_references(self.expected_sources),
            "required_fields": sanitize_references(self.required_fields),
            "retention_expectation_days": max(0, int(self.retention_expectation_days or 0)),
            "redaction_required": bool(self.redaction_required),
            "export_required": bool(self.export_required),
            "validation_recommendations": sanitize_notes(self.validation_recommendations),
            "advisory_notes": sanitize_notes(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **EVIDENCE_PROFILE_SAFETY_FLAGS,
        }


def build_evidence_expectation(
    *,
    evidence_profile_id: Any = "",
    evidence_type: Any = "unknown",
    evidence_state: Any = "",
    expected_sources: Iterable[Any] | None = None,
    required_fields: Iterable[Any] | None = None,
    retention_expectation_days: Any = 30,
    redaction_required: Any = True,
    export_required: Any = False,
    validation_recommendations: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> EvidenceExpectationRecord:
    normalized_type = normalize_evidence_type(evidence_type)
    sources = sanitize_references(expected_sources or default_sources_for_evidence(normalized_type))
    fields = sanitize_references(required_fields or default_fields_for_evidence(normalized_type))
    retention_days = safe_int(retention_expectation_days)
    state = normalize_evidence_state(evidence_state) if evidence_state else infer_evidence_state(sources, fields)
    recommendations = sanitize_notes(
        validation_recommendations
        or [
            "confirm required evidence fields before sharing exports",
            "apply redaction before evidence leaves the local operator boundary",
        ]
    )
    notes = sanitize_notes(advisory_notes or ["evidence expectation is metadata-only and does not read files by default"])
    safe_id = sanitize_token(evidence_profile_id)
    if not safe_id:
        safe_id = "evidence-profile-" + digest(
            {
                "evidence_type": normalized_type,
                "expected_sources": sources,
                "required_fields": fields,
                "retention_expectation_days": retention_days,
            }
        )[:16]
    return EvidenceExpectationRecord(
        evidence_profile_id=safe_id,
        evidence_type=normalized_type,
        evidence_state=state,
        expected_sources=sources,
        required_fields=fields,
        retention_expectation_days=retention_days,
        redaction_required=bool(redaction_required),
        export_required=bool(export_required),
        validation_recommendations=recommendations,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_evidence_expectation(value: Any) -> EvidenceExpectationRecord:
    if isinstance(value, EvidenceExpectationRecord):
        return value
    if not isinstance(value, dict):
        return build_evidence_expectation(
            evidence_type="unknown",
            evidence_state="degraded",
            advisory_notes=["invalid evidence expectation generated from malformed input"],
        )
    try:
        return build_evidence_expectation(
            evidence_profile_id=value.get("evidence_profile_id", ""),
            evidence_type=value.get("evidence_type", value.get("type", "unknown")),
            evidence_state=value.get("evidence_state", value.get("state", "")),
            expected_sources=value.get("expected_sources") if isinstance(value.get("expected_sources"), list) else None,
            required_fields=value.get("required_fields") if isinstance(value.get("required_fields"), list) else None,
            retention_expectation_days=value.get("retention_expectation_days", 30),
            redaction_required=value.get("redaction_required", True),
            export_required=value.get("export_required", False),
            validation_recommendations=value.get("validation_recommendations") if isinstance(value.get("validation_recommendations"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_evidence_expectation(evidence_state="degraded", advisory_notes=[str(exc)])


def summarize_evidence_expectations(records: Iterable[EvidenceExpectationRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_evidence_expectation(record).to_dict() for record in list(records or [])]
    type_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["evidence_type"]] = type_counts.get(row["evidence_type"], 0) + 1
        state_counts[row["evidence_state"]] = state_counts.get(row["evidence_state"], 0) + 1
    return {
        "record_type": "evidence_expectation_summary",
        "evidence_profile_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "redaction_required_count": sum(1 for row in rows if row.get("redaction_required")),
        "export_required_count": sum(1 for row in rows if row.get("export_required")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **EVIDENCE_PROFILE_SAFETY_FLAGS,
    }


def default_sources_for_evidence(evidence_type: str) -> list[str]:
    return {
        "audit_events": ["audit_event_records", "audit_event_summaries"],
        "runtime_logs": ["runtime_log_summaries", "daily_rotation_readiness"],
        "export_summaries": ["last_export_summary", "export_validation_summary"],
        "policy_reviews": ["policy_review_records", "approval_summaries"],
        "remediation_previews": ["remediation_preview_records", "guardrail_summaries"],
        "configuration_snapshots": ["configuration_summary", "redacted_config_preview"],
        "security_reviews": ["security_review_summary", "package_review_summary"],
    }.get(evidence_type, ["operator_supplied_summary"])


def default_fields_for_evidence(evidence_type: str) -> list[str]:
    return {
        "audit_events": ["event_category", "event_state", "created_at"],
        "runtime_logs": ["log_family", "rotation_state", "retention_preview"],
        "export_summaries": ["export_state", "expected_files", "observed_files"],
        "policy_reviews": ["policy_id", "review_state", "approval_state"],
        "remediation_previews": ["recommendation_id", "approval_required", "rollback_available"],
        "configuration_snapshots": ["configuration_scope", "redaction_state", "source_mode"],
        "security_reviews": ["checklist_id", "review_state", "recommendations"],
    }.get(evidence_type, ["summary_state"])


def infer_evidence_state(expected_sources: list[str], required_fields: list[str]) -> str:
    if not expected_sources and not required_fields:
        return "missing"
    if not expected_sources or not required_fields:
        return "partial"
    return "ready"


def normalize_evidence_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in EVIDENCE_TYPES else "unknown"


def normalize_evidence_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in EVIDENCE_STATES else "unknown"


def sanitize_text_map(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, raw_value in list(value.items())[:32]:
        safe_key = sanitize_token(key).lower()
        if not safe_key:
            continue
        if isinstance(raw_value, bool):
            safe[safe_key] = raw_value
        elif isinstance(raw_value, (int, float)):
            safe[safe_key] = raw_value
        elif isinstance(raw_value, (list, tuple, set)):
            safe[safe_key] = [sanitize_text(item) for item in list(raw_value)[:16]]
        else:
            safe[safe_key] = sanitize_text(raw_value)
    return safe


def deterministic_evidence_expectation_json(record: EvidenceExpectationRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, EvidenceExpectationRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "EVIDENCE_PROFILE_SAFETY_FLAGS",
    "EVIDENCE_STATES",
    "EVIDENCE_TYPES",
    "EvidenceExpectationRecord",
    "build_evidence_expectation",
    "deterministic_evidence_expectation_json",
    "normalize_evidence_expectation",
    "normalize_evidence_state",
    "normalize_evidence_type",
    "sanitize_text_map",
    "summarize_evidence_expectations",
]
