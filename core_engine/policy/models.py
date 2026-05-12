from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
REVIEW_STATES = frozenset({"open", "approved", "deferred", "dismissed", "resolved"})


class PolicyError(ValueError):
    """Raised when policy or review data is invalid."""


@dataclass(slots=True)
class Policy:
    policy_id: str
    name: str
    description: str
    enabled: bool = True
    severity_threshold: str = "medium"
    categories: list[str] = field(default_factory=list)
    required_review: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _now())
    updated_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.policy_id, "policy_id")
        _required_str(self.name, "name")
        _required_str(self.description, "description")
        if not isinstance(self.enabled, bool):
            raise PolicyError("enabled must be boolean")
        if self.severity_threshold not in SEVERITY_ORDER:
            raise PolicyError(f"unsupported severity_threshold: {self.severity_threshold}")
        if not isinstance(self.categories, list) or not all(isinstance(item, str) for item in self.categories):
            raise PolicyError("categories must be a list of strings")
        if not isinstance(self.required_review, bool):
            raise PolicyError("required_review must be boolean")
        if not isinstance(self.metadata, dict):
            raise PolicyError("metadata must be an object")
        _required_str(self.created_at, "created_at")
        _required_str(self.updated_at, "updated_at")

    def matches(self, *, category: str, severity: str) -> bool:
        if not self.enabled:
            return False
        if self.categories and category not in self.categories:
            return False
        return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER[self.severity_threshold]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "severity_threshold": self.severity_threshold,
            "categories": list(self.categories),
            "required_review": self.required_review,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "local_only": True,
            "automatic_changes": False,
        }


@dataclass(slots=True)
class ReviewRecord:
    review_id: str
    policy_id: str
    source_ref: str
    category: str
    severity: str
    title: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    recommended_action: str = "operator_review"
    status: str = "open"
    approval_required: bool = True
    automatic_changes: bool = False
    administrator_controlled: bool = True
    raw_payload_stored: bool = False
    created_at: str = field(default_factory=lambda: _now())
    updated_at: str = field(default_factory=lambda: _now())
    reviewed_by: str | None = None
    review_note: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("review_id", "policy_id", "source_ref", "category", "severity", "title", "summary"):
            _required_str(getattr(self, field_name), field_name)
        if self.severity not in SEVERITY_ORDER:
            raise PolicyError(f"unsupported severity: {self.severity}")
        if self.status not in REVIEW_STATES:
            raise PolicyError(f"unsupported review status: {self.status}")
        if not isinstance(self.evidence_refs, list) or not all(isinstance(item, str) for item in self.evidence_refs):
            raise PolicyError("evidence_refs must be a list of strings")
        for field_name in ("approval_required", "automatic_changes", "administrator_controlled", "raw_payload_stored"):
            if not isinstance(getattr(self, field_name), bool):
                raise PolicyError(f"{field_name} must be boolean")
        if self.automatic_changes:
            raise PolicyError("review records cannot enable automatic_changes")
        if not self.administrator_controlled:
            raise PolicyError("review records must remain administrator controlled")
        if self.raw_payload_stored:
            raise PolicyError("review records cannot store raw payloads")
        _required_str(self.created_at, "created_at")
        _required_str(self.updated_at, "updated_at")

    @property
    def local_only(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "policy_id": self.policy_id,
            "source_ref": self.source_ref,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
            "recommended_action": self.recommended_action,
            "status": self.status,
            "approval_required": self.approval_required,
            "automatic_changes": self.automatic_changes,
            "administrator_controlled": self.administrator_controlled,
            "raw_payload_stored": self.raw_payload_stored,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "reviewed_by": self.reviewed_by,
            "review_note": self.review_note,
            "local_only": self.local_only,
        }


def create_policy(
    *,
    policy_id: str | None = None,
    name: str,
    description: str,
    enabled: bool = True,
    severity_threshold: str = "medium",
    categories: list[str] | None = None,
    required_review: bool = True,
    metadata: dict[str, Any] | None = None,
    now: str | None = None,
) -> Policy:
    timestamp = now or _now()
    return Policy(
        policy_id=policy_id or _stable_id("policy", name, description),
        name=name,
        description=description,
        enabled=enabled,
        severity_threshold=severity_threshold,
        categories=categories or [],
        required_review=required_review,
        metadata=metadata or {},
        created_at=timestamp,
        updated_at=timestamp,
    )


def _stable_id(prefix: str, *parts: str) -> str:
    material = "|".join(parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{field_name} must be a non-empty string")
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
