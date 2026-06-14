from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes, sanitize_references
from core_engine.scaling.bus_envelopes import digest, normalize_source_mode, sanitize_reference, sanitize_text, sanitize_token


SECURITY_REVIEW_RECORD_VERSION = 1
SECURITY_REVIEW_CATEGORIES = {
    "runtime",
    "packaging",
    "deployment",
    "governance",
    "compliance",
    "privacy",
    "export",
    "infrastructure",
    "unknown",
}
SECURITY_REVIEW_STATES = {"ready", "review_required", "incomplete", "degraded", "unavailable", "unknown"}
SECURITY_REVIEW_SAFETY_FLAGS = {
    **GOVERNANCE_SAFETY_FLAGS,
    "security_scan_performed": False,
    "vulnerability_detection_performed": False,
    "control_enforced": False,
    "authorization_performed": False,
    "permissions_enforced": False,
    "file_read_performed": False,
    "filesystem_written": False,
    "runtime_behavior_changed": False,
    "system_modified": False,
}


@dataclass(frozen=True)
class SecurityReviewRecord:
    review_id: str
    review_type: str
    review_category: str
    review_state: str
    review_scope: str
    checklist_items: list[dict[str, Any]] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    governance_references: list[str] = field(default_factory=list)
    accountability_references: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "security_review_record",
            "record_version": SECURITY_REVIEW_RECORD_VERSION,
            "review_id": sanitize_reference(self.review_id) or "security-review-unknown",
            "review_type": sanitize_token(self.review_type).lower() or "unknown",
            "review_category": normalize_security_review_category(self.review_category),
            "review_state": normalize_security_review_state(self.review_state),
            "review_scope": sanitize_token(self.review_scope).lower() or "unknown",
            "checklist_items": sanitize_checklist_items(self.checklist_items),
            "evidence_references": sanitize_references(self.evidence_references),
            "governance_references": sanitize_references(self.governance_references),
            "accountability_references": sanitize_references(self.accountability_references),
            "advisory_notes": sanitize_notes(self.advisory_notes),
            "source_mode": mode,
            "data_source": mode,
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **SECURITY_REVIEW_SAFETY_FLAGS,
        }


def build_security_review(
    *,
    review_id: Any = "",
    review_type: Any = "unknown",
    review_category: Any = "unknown",
    review_state: Any = "",
    review_scope: Any = "",
    checklist_items: Iterable[dict[str, Any] | Any] | None = None,
    evidence_references: Iterable[Any] | None = None,
    governance_references: Iterable[Any] | None = None,
    accountability_references: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
    source_mode: Any = "unknown",
) -> SecurityReviewRecord:
    category = normalize_security_review_category(review_category)
    checklist = sanitize_checklist_items(checklist_items or default_checklist_items(category))
    state = normalize_security_review_state(review_state) if review_state else infer_security_review_state(checklist)
    scope = sanitize_token(review_scope).lower() or category
    evidence = sanitize_references(evidence_references or [])
    governance = sanitize_references(governance_references or [])
    accountability = sanitize_references(accountability_references or [])
    notes = sanitize_notes(advisory_notes or ["security review is metadata-only and advisory"])
    safe_id = sanitize_reference(review_id)
    if not safe_id:
        safe_id = "security-review-" + digest(
            {
                "review_type": sanitize_token(review_type).lower(),
                "review_category": category,
                "review_state": state,
                "review_scope": scope,
                "checklist_count": len(checklist),
                "source_mode": normalize_source_mode(source_mode),
            }
        )[:16]
    return SecurityReviewRecord(
        review_id=safe_id,
        review_type=sanitize_token(review_type).lower() or "unknown",
        review_category=category,
        review_state=state,
        review_scope=scope,
        checklist_items=checklist,
        evidence_references=evidence,
        governance_references=governance,
        accountability_references=accountability,
        advisory_notes=notes,
        source_mode=normalize_source_mode(source_mode),
        preview_only=True,
        destructive_action=False,
    )


def normalize_security_review(value: Any) -> SecurityReviewRecord:
    if isinstance(value, SecurityReviewRecord):
        return value
    if not isinstance(value, dict):
        return build_security_review(
            review_type="invalid",
            review_state="degraded",
            advisory_notes=["invalid security review generated from malformed input"],
        )
    try:
        return build_security_review(
            review_id=value.get("review_id", ""),
            review_type=value.get("review_type", value.get("type", "unknown")),
            review_category=value.get("review_category", value.get("category", "unknown")),
            review_state=value.get("review_state", value.get("state", "")),
            review_scope=value.get("review_scope", value.get("scope", "")),
            checklist_items=value.get("checklist_items") if isinstance(value.get("checklist_items"), list) else None,
            evidence_references=value.get("evidence_references") if isinstance(value.get("evidence_references"), list) else None,
            governance_references=value.get("governance_references") if isinstance(value.get("governance_references"), list) else None,
            accountability_references=value.get("accountability_references") if isinstance(value.get("accountability_references"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
            source_mode=value.get("source_mode", value.get("data_source", "unknown")),
        )
    except Exception as exc:
        return build_security_review(review_state="degraded", advisory_notes=[str(exc)])


def summarize_security_reviews(reviews: Iterable[SecurityReviewRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_security_review(review).to_dict() for review in list(reviews or [])]
    category_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in rows:
        category_counts[row["review_category"]] = category_counts.get(row["review_category"], 0) + 1
        state_counts[row["review_state"]] = state_counts.get(row["review_state"], 0) + 1
    return {
        "record_type": "security_review_summary",
        "review_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "checklist_item_count": sum(len(row.get("checklist_items", [])) for row in rows),
        "evidence_reference_count": sum(len(row.get("evidence_references", [])) for row in rows),
        "governance_reference_count": sum(len(row.get("governance_references", [])) for row in rows),
        "accountability_reference_count": sum(len(row.get("accountability_references", [])) for row in rows),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **SECURITY_REVIEW_SAFETY_FLAGS,
    }


def default_checklist_items(category: str) -> list[dict[str, Any]]:
    category_map = {
        "runtime": ["runtime health reviewed", "safe mode boundaries reviewed"],
        "packaging": ["package previews reviewed", "rollback preview reviewed"],
        "deployment": ["deployment readiness reviewed", "operator approval boundary reviewed"],
        "governance": ["governance summaries reviewed", "redaction readiness reviewed"],
        "compliance": ["evidence expectations reviewed", "certification boundary reviewed"],
        "privacy": ["privacy boundary reviewed", "private export boundary reviewed"],
        "export": ["export validation reviewed", "artifact check reviewed"],
        "infrastructure": ["scaling readiness reviewed", "relay boundary reviewed"],
        "unknown": ["review scope requires clarification"],
    }
    return [{"item_id": f"{category}-check-{index + 1}", "item_label": label, "item_state": "review_required"} for index, label in enumerate(category_map.get(category, category_map["unknown"]))]


def sanitize_checklist_items(items: Iterable[dict[str, Any] | Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(list(items or [])[:64]):
        if isinstance(item, dict):
            item_id = sanitize_reference(item.get("item_id", item.get("id", f"check-{index + 1}"))) or f"check-{index + 1}"
            label = sanitize_text(item.get("item_label", item.get("label", item_id))) or item_id
            state = normalize_checklist_state(item.get("item_state", item.get("state", "review_required")))
            required = bool(item.get("required", True))
        else:
            item_id = f"check-{index + 1}"
            label = sanitize_text(item) or item_id
            state = "review_required"
            required = True
        rows.append(
            {
                "item_id": item_id,
                "item_label": label,
                "item_state": state,
                "required": required,
                "preview_only": True,
                "destructive_action": False,
                "export_safe": True,
            }
        )
    return rows


def infer_security_review_state(checklist_items: list[dict[str, Any]]) -> str:
    if not checklist_items:
        return "unavailable"
    states = {item.get("item_state", "unknown") for item in checklist_items}
    if "degraded" in states or "unknown" in states:
        return "degraded"
    if "incomplete" in states:
        return "incomplete"
    if "review_required" in states:
        return "review_required"
    return "ready"


def normalize_checklist_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in SECURITY_REVIEW_STATES else "unknown"


def normalize_security_review_category(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in SECURITY_REVIEW_CATEGORIES else "unknown"


def normalize_security_review_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in SECURITY_REVIEW_STATES else "unknown"


def deterministic_security_review_json(record: SecurityReviewRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, SecurityReviewRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "SECURITY_REVIEW_CATEGORIES",
    "SECURITY_REVIEW_SAFETY_FLAGS",
    "SECURITY_REVIEW_STATES",
    "SecurityReviewRecord",
    "build_security_review",
    "deterministic_security_review_json",
    "normalize_checklist_state",
    "normalize_security_review",
    "normalize_security_review_category",
    "normalize_security_review_state",
    "sanitize_checklist_items",
    "summarize_security_reviews",
]
