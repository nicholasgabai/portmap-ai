from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    normalize_source_mode,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)


AUDIT_EVENT_RECORD_VERSION = 1
AUDIT_EVENT_CATEGORIES = {
    "runtime",
    "export",
    "operator_action",
    "policy_review",
    "remediation_preview",
    "configuration",
    "packaging",
    "security_review",
    "unknown",
}
AUDIT_EVENT_STATES = {"recorded", "pending", "degraded", "invalid", "unknown"}
GOVERNANCE_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "audit_log_deleted": False,
    "log_file_rotated": False,
    "log_file_moved": False,
    "log_file_compressed": False,
    "filesystem_written": False,
    "zip_extracted": False,
    "private_export_read": False,
    "credential_stored": False,
    "private_identifier_exported": False,
    "legal_certification_claimed": False,
    "enforcement_action_created": False,
    "firewall_modified": False,
    "process_modified": False,
    "service_modified": False,
}


@dataclass(frozen=True)
class AuditEventRecord:
    audit_event_id: str
    event_type: str
    event_category: str
    actor_reference: str
    action_reference: str
    target_reference: str
    source_mode: str
    event_state: str
    created_at: str
    evidence_references: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "audit_event_record",
            "record_version": AUDIT_EVENT_RECORD_VERSION,
            "audit_event_id": sanitize_reference(self.audit_event_id),
            "event_type": sanitize_token(self.event_type).lower() or "unknown",
            "event_category": normalize_audit_event_category(self.event_category),
            "actor_reference": sanitize_reference(self.actor_reference) or "actor-unknown",
            "action_reference": sanitize_reference(self.action_reference) or "action-unknown",
            "target_reference": sanitize_reference(self.target_reference) or "target-unknown",
            "source_mode": mode,
            "data_source": mode,
            "event_state": normalize_audit_event_state(self.event_state),
            "created_at": str(self.created_at or ""),
            "evidence_references": sanitize_references(self.evidence_references),
            "advisory_notes": sanitize_notes(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **GOVERNANCE_SAFETY_FLAGS,
        }


def build_audit_event(
    *,
    audit_event_id: Any = "",
    event_type: Any = "unknown",
    event_category: Any = "unknown",
    actor_reference: Any = "actor-unknown",
    action_reference: Any = "action-unknown",
    target_reference: Any = "target-unknown",
    source_mode: Any = "unknown",
    event_state: Any = "recorded",
    created_at: Any = None,
    evidence_references: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> AuditEventRecord:
    timestamp = str(created_at or now_timestamp())
    category = normalize_audit_event_category(event_category)
    state = normalize_audit_event_state(event_state)
    actor = sanitize_reference(actor_reference) or "actor-unknown"
    action = sanitize_reference(action_reference) or "action-unknown"
    target = sanitize_reference(target_reference) or "target-unknown"
    evidence = sanitize_references(evidence_references or [])
    notes = sanitize_notes(advisory_notes or ["audit event is metadata-only and export-safe"])
    safe_id = sanitize_reference(audit_event_id)
    if not safe_id:
        safe_id = "audit-event-" + digest(
            {
                "event_type": sanitize_token(event_type).lower(),
                "event_category": category,
                "actor_reference": actor,
                "action_reference": action,
                "target_reference": target,
                "created_at": timestamp,
            }
        )[:16]
    return AuditEventRecord(
        audit_event_id=safe_id,
        event_type=sanitize_token(event_type).lower() or "unknown",
        event_category=category,
        actor_reference=actor,
        action_reference=action,
        target_reference=target,
        source_mode=normalize_source_mode(source_mode),
        event_state=state,
        created_at=timestamp,
        evidence_references=evidence,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_audit_event(value: Any) -> AuditEventRecord:
    if isinstance(value, AuditEventRecord):
        return value
    if not isinstance(value, dict):
        return build_audit_event(
            event_type="invalid",
            event_category="unknown",
            event_state="invalid",
            advisory_notes=["invalid audit event generated from malformed input"],
        )
    try:
        return build_audit_event(
            audit_event_id=value.get("audit_event_id", ""),
            event_type=value.get("event_type", value.get("type", "unknown")),
            event_category=value.get("event_category", value.get("category", "unknown")),
            actor_reference=value.get("actor_reference", value.get("actor", "actor-unknown")),
            action_reference=value.get("action_reference", value.get("action", "action-unknown")),
            target_reference=value.get("target_reference", value.get("target", "target-unknown")),
            source_mode=value.get("source_mode", value.get("data_source", "unknown")),
            event_state=value.get("event_state", value.get("state", "recorded")),
            created_at=value.get("created_at"),
            evidence_references=value.get("evidence_references") if isinstance(value.get("evidence_references"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_audit_event(event_type="invalid", event_state="invalid", advisory_notes=[str(exc)])


def summarize_audit_events(events: Iterable[AuditEventRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_audit_event(event).to_dict() for event in list(events or [])]
    category_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in rows:
        category_counts[row["event_category"]] = category_counts.get(row["event_category"], 0) + 1
        state_counts[row["event_state"]] = state_counts.get(row["event_state"], 0) + 1
    return {
        "record_type": "audit_event_summary",
        "event_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "evidence_reference_count": sum(len(row.get("evidence_references", [])) for row in rows),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **GOVERNANCE_SAFETY_FLAGS,
    }


def normalize_audit_event_category(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in AUDIT_EVENT_CATEGORIES else "unknown"


def normalize_audit_event_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in AUDIT_EVENT_STATES else "unknown"


def sanitize_references(values: Iterable[Any]) -> list[str]:
    return [item for item in (sanitize_reference(value) for value in values) if item][:32]


def sanitize_notes(values: Iterable[Any]) -> list[str]:
    return [item for item in (sanitize_text(value) for value in values) if item][:32]


def deterministic_audit_event_json(record: AuditEventRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, AuditEventRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "AUDIT_EVENT_CATEGORIES",
    "AUDIT_EVENT_STATES",
    "GOVERNANCE_SAFETY_FLAGS",
    "AuditEventRecord",
    "build_audit_event",
    "deterministic_audit_event_json",
    "normalize_audit_event",
    "normalize_audit_event_category",
    "normalize_audit_event_state",
    "sanitize_notes",
    "sanitize_references",
    "summarize_audit_events",
]
