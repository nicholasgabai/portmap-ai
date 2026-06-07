from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.remediation.isolation_providers import (
    IsolationProviderReadiness,
    READINESS_STATES,
    SUPPORTED_ACTIONS,
    build_provider_readiness,
    provider_readiness_to_dict,
)


PREVIEW_TYPES = frozenset(
    {
        "rate_limit_preview",
        "block_port_preview",
        "block_destination_preview",
        "quarantine_service_preview",
        "isolate_node_preview",
        "manual_review",
    }
)
TARGET_CLASSES = frozenset({"host", "port", "destination", "service", "process", "node", "flow", "unknown"})


class QuarantineReadinessError(ValueError):
    """Raised when quarantine readiness preview input is malformed or unsafe."""


@dataclass(slots=True)
class QuarantineIsolationPreview:
    preview_id: str
    preview_type: str
    target_class: str
    target_reference: str
    provider_name: str
    readiness_state: str
    approval_required: bool = True
    rollback_required: bool = True
    blast_radius_summary: str = "bounded preview only"
    safety_blockers: list[str] = field(default_factory=list)
    operator_steps: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.preview_id, "preview_id")
        if self.preview_type not in PREVIEW_TYPES:
            raise QuarantineReadinessError(f"unsupported preview_type: {self.preview_type}")
        if self.target_class not in TARGET_CLASSES:
            raise QuarantineReadinessError(f"unsupported target_class: {self.target_class}")
        self.target_reference = sanitize_target_reference(self.target_reference)
        _required_str(self.provider_name, "provider_name")
        if self.readiness_state not in READINESS_STATES:
            raise QuarantineReadinessError(f"unsupported readiness_state: {self.readiness_state}")
        if not isinstance(self.approval_required, bool):
            raise QuarantineReadinessError("approval_required must be boolean")
        if not isinstance(self.rollback_required, bool):
            raise QuarantineReadinessError("rollback_required must be boolean")
        _required_str(self.blast_radius_summary, "blast_radius_summary")
        if not _is_string_list(self.safety_blockers):
            raise QuarantineReadinessError("safety_blockers must be a list of strings")
        if not _is_string_list(self.operator_steps):
            raise QuarantineReadinessError("operator_steps must be a list of strings")
        if not self.preview_only:
            raise QuarantineReadinessError("quarantine previews must remain preview_only")
        if self.destructive_action:
            raise QuarantineReadinessError("quarantine previews cannot be destructive")


def build_quarantine_preview(
    *,
    preview_type: str,
    target_class: str = "unknown",
    target_reference: str = "target-unknown",
    provider: IsolationProviderReadiness | dict[str, Any] | None = None,
    provider_name: str = "generic_manual_operator",
    platform_family: str = "unknown",
    now: str | None = None,
) -> QuarantineIsolationPreview:
    provider_record = _provider_dict(provider) if provider is not None else provider_readiness_to_dict(
        build_provider_readiness(provider_name, platform_family=platform_family, now=now)
    )
    normalized_preview = preview_type if preview_type in PREVIEW_TYPES else "manual_review"
    provider_supported = normalized_preview in set(provider_record.get("supported_actions") or [])
    readiness = str(provider_record.get("readiness_state") or "unknown")
    blockers: list[str] = []
    if normalized_preview != preview_type:
        blockers.append("unsupported_preview_type")
    if readiness != "ready":
        blockers.append(f"provider_state:{readiness}")
    if not provider_supported and normalized_preview != "manual_review":
        blockers.append("provider_action_unavailable")
        readiness = "degraded" if readiness == "ready" else readiness
    if not bool(provider_record.get("dry_run_supported", True)):
        blockers.append("dry_run_not_supported")
        readiness = "unavailable"

    target_ref = sanitize_target_reference(target_reference)
    material = deterministic_quarantine_readiness_json(
        {
            "preview_type": normalized_preview,
            "target_class": target_class,
            "target_reference": target_ref,
            "provider_name": provider_record.get("provider_name"),
            "readiness": readiness,
            "created_at": now or _now(),
        }
    )
    return QuarantineIsolationPreview(
        preview_id="quarantine-preview-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        preview_type=normalized_preview,
        target_class=target_class if target_class in TARGET_CLASSES else "unknown",
        target_reference=target_ref,
        provider_name=str(provider_record.get("provider_name") or "generic_manual_operator"),
        readiness_state=readiness if readiness in READINESS_STATES else "unknown",
        approval_required=True,
        rollback_required=normalized_preview != "manual_review",
        blast_radius_summary=_blast_radius(normalized_preview, target_class),
        safety_blockers=blockers,
        operator_steps=_operator_steps(normalized_preview, blockers),
        preview_only=True,
        destructive_action=False,
        created_at=now or _now(),
    )


def quarantine_preview_to_dict(preview: QuarantineIsolationPreview) -> dict[str, Any]:
    return {
        "record_type": "quarantine_isolation_preview",
        "preview_id": preview.preview_id,
        "preview_type": preview.preview_type,
        "target_class": preview.target_class,
        "target_reference": preview.target_reference,
        "provider_name": preview.provider_name,
        "readiness_state": preview.readiness_state,
        "approval_required": preview.approval_required,
        "rollback_required": preview.rollback_required,
        "blast_radius_summary": preview.blast_radius_summary,
        "safety_blockers": list(preview.safety_blockers),
        "operator_steps": list(preview.operator_steps),
        "preview_only": preview.preview_only,
        "destructive_action": preview.destructive_action,
        "created_at": preview.created_at,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "node_isolation_performed": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_quarantine_readiness_summary(previews: list[QuarantineIsolationPreview]) -> dict[str, Any]:
    rows = list(previews or [])
    by_state: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for row in rows:
        by_state[row.readiness_state] = by_state.get(row.readiness_state, 0) + 1
        by_type[row.preview_type] = by_type.get(row.preview_type, 0) + 1
    return {
        "record_type": "quarantine_isolation_readiness_summary",
        "preview_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "by_type": dict(sorted(by_type.items())),
        "approval_required_count": sum(1 for row in rows if row.approval_required),
        "rollback_required_count": sum(1 for row in rows if row.rollback_required),
        "blocked_preview_count": sum(1 for row in rows if row.safety_blockers),
        "preview_only": True,
        "destructive_action": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "node_isolation_performed": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_quarantine_readiness_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def sanitize_target_reference(target_reference: str) -> str:
    value = str(target_reference or "target-unknown")
    sensitive = [
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",
        "/" + r"Users/[^ \n\t]+",
        r"[^@\s]+@[^@\s]+",
    ]
    if any(re.search(pattern, value) for pattern in sensitive):
        digest = sha256(value.encode("utf-8")).hexdigest()[:12]
        return f"redacted-target-{digest}"
    return re.sub(r"[^A-Za-z0-9_.:-]", "-", value)[:96] or "target-unknown"


def _provider_dict(provider: IsolationProviderReadiness | dict[str, Any]) -> dict[str, Any]:
    if isinstance(provider, IsolationProviderReadiness):
        return provider_readiness_to_dict(provider)
    if isinstance(provider, dict):
        return dict(provider)
    return {}


def _blast_radius(preview_type: str, target_class: str) -> str:
    if preview_type == "manual_review":
        return "No containment blast radius; manual operator review only."
    if target_class in {"port", "flow", "destination"}:
        return "Preview scope is limited to the referenced network metadata class."
    if target_class in {"service", "process"}:
        return "Preview could affect service availability in a future supervised mode."
    if target_class == "node":
        return "Preview could affect node connectivity in a future supervised mode."
    return "Preview blast radius is unknown until operator validates the target."


def _operator_steps(preview_type: str, blockers: list[str]) -> list[str]:
    steps = ["review_sanitized_target", "confirm_operator_approval", "confirm_rollback_plan"]
    if blockers:
        steps.append("resolve_safety_blockers")
    if preview_type == "manual_review":
        return ["review_evidence_manually", "choose_no_action_or_future_preview"]
    return steps


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise QuarantineReadinessError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, QuarantineIsolationPreview):
        return quarantine_preview_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
