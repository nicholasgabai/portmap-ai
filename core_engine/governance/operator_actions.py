from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes, sanitize_references
from core_engine.scaling.bus_envelopes import digest, normalize_source_mode, sanitize_reference, sanitize_token


OPERATOR_ACTION_RECORD_VERSION = 1
OPERATOR_ACTION_CATEGORIES = {
    "export",
    "policy_review",
    "remediation_preview",
    "configuration_review",
    "packaging_review",
    "governance_review",
    "security_review",
    "compliance_review",
    "unknown",
}
APPROVAL_STATES = {"approved", "pending", "review_required", "rejected", "unknown"}
OPERATOR_ACTION_STATES = {"recorded", "advisory", "incomplete", "degraded", "unknown"}
OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS = {
    **GOVERNANCE_SAFETY_FLAGS,
    "authorization_performed": False,
    "permissions_enforced": False,
    "role_assigned": False,
    "identity_stored": False,
    "file_read_performed": False,
    "filesystem_written": False,
    "runtime_behavior_changed": False,
}


@dataclass(frozen=True)
class OperatorActionRecord:
    action_id: str
    action_type: str
    action_category: str
    actor_reference: str
    reviewer_reference: str
    approval_state: str
    action_state: str
    evidence_references: list[str] = field(default_factory=list)
    governance_references: list[str] = field(default_factory=list)
    audit_references: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "operator_action_record",
            "record_version": OPERATOR_ACTION_RECORD_VERSION,
            "action_id": sanitize_reference(self.action_id) or "operator-action-unknown",
            "action_type": sanitize_token(self.action_type).lower() or "unknown",
            "action_category": normalize_action_category(self.action_category),
            "actor_reference": sanitize_operator_reference(self.actor_reference, default="actor-unknown"),
            "reviewer_reference": sanitize_operator_reference(self.reviewer_reference, default="reviewer-unknown"),
            "approval_state": normalize_approval_state(self.approval_state),
            "action_state": normalize_operator_action_state(self.action_state),
            "evidence_references": sanitize_references(self.evidence_references),
            "governance_references": sanitize_references(self.governance_references),
            "audit_references": sanitize_references(self.audit_references),
            "advisory_notes": sanitize_notes(self.advisory_notes),
            "source_mode": mode,
            "data_source": mode,
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
        }


def build_operator_action(
    *,
    action_id: Any = "",
    action_type: Any = "unknown",
    action_category: Any = "unknown",
    actor_reference: Any = "actor-unknown",
    reviewer_reference: Any = "reviewer-unknown",
    approval_state: Any = "review_required",
    action_state: Any = "recorded",
    evidence_references: Iterable[Any] | None = None,
    governance_references: Iterable[Any] | None = None,
    audit_references: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
    source_mode: Any = "unknown",
) -> OperatorActionRecord:
    category = normalize_action_category(action_category)
    approval = normalize_approval_state(approval_state)
    state = normalize_operator_action_state(action_state)
    actor = sanitize_operator_reference(actor_reference, default="actor-unknown")
    reviewer = sanitize_operator_reference(reviewer_reference, default="reviewer-unknown")
    evidence = sanitize_references(evidence_references or [])
    governance = sanitize_references(governance_references or [])
    audit = sanitize_references(audit_references or [])
    notes = sanitize_notes(advisory_notes or ["operator action is metadata-only and advisory"])
    safe_id = sanitize_reference(action_id)
    if not safe_id:
        safe_id = "operator-action-" + digest(
            {
                "action_type": sanitize_token(action_type).lower(),
                "action_category": category,
                "actor_reference": actor,
                "reviewer_reference": reviewer,
                "approval_state": approval,
                "action_state": state,
                "source_mode": normalize_source_mode(source_mode),
            }
        )[:16]
    return OperatorActionRecord(
        action_id=safe_id,
        action_type=sanitize_token(action_type).lower() or "unknown",
        action_category=category,
        actor_reference=actor,
        reviewer_reference=reviewer,
        approval_state=approval,
        action_state=state,
        evidence_references=evidence,
        governance_references=governance,
        audit_references=audit,
        advisory_notes=notes,
        source_mode=normalize_source_mode(source_mode),
        preview_only=True,
        destructive_action=False,
    )


def normalize_operator_action(value: Any) -> OperatorActionRecord:
    if isinstance(value, OperatorActionRecord):
        return value
    if not isinstance(value, dict):
        return build_operator_action(
            action_type="invalid",
            action_state="degraded",
            approval_state="unknown",
            advisory_notes=["invalid operator action generated from malformed input"],
        )
    try:
        return build_operator_action(
            action_id=value.get("action_id", ""),
            action_type=value.get("action_type", value.get("type", "unknown")),
            action_category=value.get("action_category", value.get("category", "unknown")),
            actor_reference=value.get("actor_reference", value.get("actor", "actor-unknown")),
            reviewer_reference=value.get("reviewer_reference", value.get("reviewer", "reviewer-unknown")),
            approval_state=value.get("approval_state", value.get("approval", "review_required")),
            action_state=value.get("action_state", value.get("state", "recorded")),
            evidence_references=value.get("evidence_references") if isinstance(value.get("evidence_references"), list) else None,
            governance_references=value.get("governance_references") if isinstance(value.get("governance_references"), list) else None,
            audit_references=value.get("audit_references") if isinstance(value.get("audit_references"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
            source_mode=value.get("source_mode", value.get("data_source", "unknown")),
        )
    except Exception as exc:
        return build_operator_action(action_state="degraded", approval_state="unknown", advisory_notes=[str(exc)])


def summarize_operator_actions(actions: Iterable[OperatorActionRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_operator_action(action).to_dict() for action in list(actions or [])]
    category_counts: dict[str, int] = {}
    approval_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in rows:
        category_counts[row["action_category"]] = category_counts.get(row["action_category"], 0) + 1
        approval_counts[row["approval_state"]] = approval_counts.get(row["approval_state"], 0) + 1
        state_counts[row["action_state"]] = state_counts.get(row["action_state"], 0) + 1
    return {
        "record_type": "operator_action_summary",
        "action_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "approval_counts": dict(sorted(approval_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "evidence_reference_count": sum(len(row.get("evidence_references", [])) for row in rows),
        "governance_reference_count": sum(len(row.get("governance_references", [])) for row in rows),
        "audit_reference_count": sum(len(row.get("audit_references", [])) for row in rows),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS,
    }


def sanitize_operator_reference(value: Any, *, default: str) -> str:
    safe_value = sanitize_reference(value)
    if not safe_value:
        return default
    lowered = safe_value.lower()
    allowed_prefixes = ("actor-", "reviewer-", "role-", "group-", "team-", "service-", "workflow-")
    if lowered.startswith(allowed_prefixes):
        return safe_value[:96]
    return default.replace("unknown", "ref") + "-" + digest(str(value))[:12]


def normalize_action_category(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in OPERATOR_ACTION_CATEGORIES else "unknown"


def normalize_approval_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in APPROVAL_STATES else "unknown"


def normalize_operator_action_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in OPERATOR_ACTION_STATES else "unknown"


def deterministic_operator_action_json(record: OperatorActionRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, OperatorActionRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "APPROVAL_STATES",
    "OPERATOR_ACCOUNTABILITY_SAFETY_FLAGS",
    "OPERATOR_ACTION_CATEGORIES",
    "OPERATOR_ACTION_STATES",
    "OperatorActionRecord",
    "build_operator_action",
    "deterministic_operator_action_json",
    "normalize_action_category",
    "normalize_approval_state",
    "normalize_operator_action",
    "normalize_operator_action_state",
    "sanitize_operator_reference",
    "summarize_operator_actions",
]
