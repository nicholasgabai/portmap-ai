from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


EVENT_TYPES = frozenset(
    {
        "asset_observed",
        "service_observed",
        "flow_observed",
        "snapshot_created",
        "baseline_delta_detected",
        "operator_review_created",
        "policy_review_required",
        "runtime_health",
        "system_notice",
    }
)

SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class EventValidationError(ValueError):
    """Raised when a local event payload is malformed."""


@dataclass(slots=True)
class LocalEvent:
    """Normalized local-only event object for visibility and operator workflows."""

    event_type: str
    severity: str
    source: str
    message: str
    event_id: str = field(default_factory=lambda: f"evt-{uuid4().hex}")
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    asset_ref: str | None = None
    service_ref: str | None = None
    flow_ref: str | None = None
    snapshot_ref: str | None = None
    finding_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_payload_stored: bool = False
    automatic_changes: bool = False
    administrator_controlled: bool = True

    def __post_init__(self) -> None:
        _validate_event(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "timestamp": self.timestamp,
            "message": self.message,
            "asset_ref": self.asset_ref,
            "service_ref": self.service_ref,
            "flow_ref": self.flow_ref,
            "snapshot_ref": self.snapshot_ref,
            "finding_ref": self.finding_ref,
            "metadata": dict(self.metadata),
            "raw_payload_stored": self.raw_payload_stored,
            "automatic_changes": self.automatic_changes,
            "administrator_controlled": self.administrator_controlled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LocalEvent":
        if not isinstance(payload, dict):
            raise EventValidationError("event payload must be an object")
        allowed = set(cls.__dataclass_fields__)
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise EventValidationError(f"unknown event fields: {', '.join(unknown)}")
        try:
            return cls(**payload)
        except TypeError as exc:
            raise EventValidationError(f"malformed event payload: {exc}") from exc


def create_event(
    event_type: str,
    *,
    severity: str = "info",
    source: str,
    message: str,
    asset_ref: str | None = None,
    service_ref: str | None = None,
    flow_ref: str | None = None,
    snapshot_ref: str | None = None,
    finding_ref: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> LocalEvent:
    """Create a validated local event with safety defaults."""
    return LocalEvent(
        event_type=event_type,
        severity=severity,
        source=source,
        message=message,
        asset_ref=asset_ref,
        service_ref=service_ref,
        flow_ref=flow_ref,
        snapshot_ref=snapshot_ref,
        finding_ref=finding_ref,
        metadata=metadata or {},
    )


def _validate_event(event: LocalEvent) -> None:
    if event.event_type not in EVENT_TYPES:
        raise EventValidationError(f"unsupported event_type: {event.event_type}")
    if event.severity not in SEVERITIES:
        raise EventValidationError(f"unsupported severity: {event.severity}")
    for field_name in ("event_id", "source", "timestamp", "message"):
        value = getattr(event, field_name)
        if not isinstance(value, str) or not value.strip():
            raise EventValidationError(f"{field_name} must be a non-empty string")
    for field_name in ("asset_ref", "service_ref", "flow_ref", "snapshot_ref", "finding_ref"):
        value = getattr(event, field_name)
        if value is not None and not isinstance(value, str):
            raise EventValidationError(f"{field_name} must be a string when provided")
    if not isinstance(event.metadata, dict):
        raise EventValidationError("metadata must be an object")
    for field_name in ("raw_payload_stored", "automatic_changes", "administrator_controlled"):
        if not isinstance(getattr(event, field_name), bool):
            raise EventValidationError(f"{field_name} must be boolean")
