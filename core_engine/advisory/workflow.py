from __future__ import annotations

import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from core_engine.enterprise_audit import build_enterprise_audit_event
from core_engine.rbac import has_permission, normalize_roles


REVIEW_STATES = {"draft", "pending_review", "approved", "rejected", "implemented", "archived"}
APPROVAL_PERMISSION = "approve:remediation"


@dataclass(frozen=True)
class AdvisoryRecommendation:
    title: str
    summary: str
    category: str = "configuration_review"
    target: str = "workspace"
    priority: str = "medium"
    actions: list[str] = field(default_factory=list)
    recommendation_id: str | None = None
    created_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        recommendation_id = self.recommendation_id or _recommendation_id(self.title, self.target, self.created_at)
        return {
            "recommendation_id": recommendation_id,
            "title": self.title,
            "summary": self.summary,
            "category": self.category,
            "target": self.target,
            "priority": self.priority,
            "actions": list(self.actions),
            "created_at": self.created_at,
            "automatic_execution": False,
            "admin_approval_required": True,
        }


class ReviewWorkflow:
    """In-memory administrator review workflow for advisory recommendations."""

    def __init__(self, recommendations: list[AdvisoryRecommendation | dict[str, Any]] | None = None):
        self._records: dict[str, dict[str, Any]] = {}
        for recommendation in recommendations or []:
            self.submit(recommendation)

    def submit(self, recommendation: AdvisoryRecommendation | dict[str, Any]) -> dict[str, Any]:
        data = recommendation.to_dict() if isinstance(recommendation, AdvisoryRecommendation) else dict(recommendation)
        errors = validate_recommendation(data)
        if errors:
            raise ValueError("; ".join(errors))
        record = {
            **data,
            "state": data.get("state", "pending_review"),
            "history": list(data.get("history") or []),
        }
        record["history"].append(_history("submitted", actor="system", note="recommendation submitted for administrator review"))
        self._records[record["recommendation_id"]] = record
        return dict(record)

    def transition(
        self,
        recommendation_id: str,
        *,
        new_state: str,
        actor: str,
        actor_roles: list[str] | tuple[str, ...] | str,
        note: str = "",
    ) -> dict[str, Any]:
        if new_state not in REVIEW_STATES:
            raise ValueError(f"new_state must be one of: {', '.join(sorted(REVIEW_STATES))}")
        record = self._records.get(recommendation_id)
        if record is None:
            raise KeyError(f"unknown recommendation_id: {recommendation_id}")
        roles = normalize_roles(actor_roles)
        if new_state in {"approved", "implemented"} and not has_permission(roles, APPROVAL_PERMISSION):
            raise PermissionError("administrator approval permission is required")
        previous = record["state"]
        record["state"] = new_state
        record["history"].append(_history(new_state, actor=actor, note=note, previous_state=previous))
        return dict(record)

    def list_records(self, *, state: str | None = None) -> list[dict[str, Any]]:
        rows = list(self._records.values())
        if state:
            rows = [row for row in rows if row.get("state") == state]
        return sorted((dict(row) for row in rows), key=lambda item: (item["state"], item["recommendation_id"]))

    def audit_events(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        events = []
        for record in self._records.values():
            for item in record.get("history") or []:
                events.append(
                    build_enterprise_audit_event(
                        actor=item.get("actor", "system"),
                        action=f"advisory.{item.get('event')}",
                        status="recorded",
                        resource=record["recommendation_id"],
                        roles=[],
                        tenant_id=tenant_id,
                        metadata={
                            "state": record.get("state"),
                            "target": record.get("target"),
                            "automatic_execution": False,
                        },
                    )
                )
        return events


def validate_recommendation(recommendation: dict[str, Any]) -> list[str]:
    if not isinstance(recommendation, dict):
        return ["recommendation must be an object"]
    errors: list[str] = []
    for field_name in ("title", "summary", "category", "target"):
        if not isinstance(recommendation.get(field_name), str) or not recommendation.get(field_name):
            errors.append(f"{field_name} must be a non-empty string")
    if recommendation.get("state", "pending_review") not in REVIEW_STATES:
        errors.append(f"state must be one of: {', '.join(sorted(REVIEW_STATES))}")
    if not isinstance(recommendation.get("actions", []), list):
        errors.append("actions must be a list")
    if recommendation.get("automatic_execution") is True:
        errors.append("advisory recommendations cannot enable automatic execution")
    return errors


def build_review_packet(recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    workflow = ReviewWorkflow(recommendations)
    return {
        "ok": True,
        "recommendation_count": len(workflow.list_records()),
        "records": workflow.list_records(),
        "automatic_execution": False,
        "administrator_controlled": True,
    }


def _history(event: str, *, actor: str, note: str = "", previous_state: str | None = None) -> dict[str, Any]:
    return {
        "event": event,
        "actor": actor,
        "note": note,
        "previous_state": previous_state,
        "timestamp": int(time.time()),
    }


def _recommendation_id(title: str, target: str, created_at: int) -> str:
    return "rec-" + sha256(f"{title}:{target}:{created_at}".encode("utf-8")).hexdigest()[:16]


__all__ = [
    "APPROVAL_PERMISSION",
    "REVIEW_STATES",
    "AdvisoryRecommendation",
    "ReviewWorkflow",
    "build_review_packet",
    "validate_recommendation",
]
