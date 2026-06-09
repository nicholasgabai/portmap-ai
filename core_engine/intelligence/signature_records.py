from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_ioc_source_category,
    normalize_source_mode,
    now_timestamp,
    sanitize_metadata,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)


SIGNATURE_RECORD_VERSION = IOC_RECORD_VERSION
SIGNATURE_TYPES = {
    "ioc_match",
    "dns_pattern",
    "flow_behavior",
    "protocol_behavior",
    "application_attribution",
    "topology_relationship",
    "runtime_health",
    "composite",
    "unknown",
}
SEVERITY_LEVELS = {"none", "low", "medium", "high", "critical", "unknown"}
UNSAFE_CONDITION_KEYS = {
    "action",
    "actions",
    "command",
    "commands",
    "enforcement",
    "enforcement_mode",
    "firewall_rule",
    "quarantine",
    "block",
    "kill_process",
    "disable_service",
    "destructive_action",
}
UNSAFE_CONDITION_VALUES = {
    "enforce",
    "block",
    "quarantine",
    "isolate",
    "kill",
    "terminate",
    "disable",
    "delete",
    "overwrite",
    "firewall",
}


class SignatureRecordError(ValueError):
    """Raised when a local metadata-only signature cannot be safely created."""


@dataclass(frozen=True)
class SignatureRecord:
    signature_id: str
    signature_name: str
    signature_type: str
    enabled: bool
    severity_level: str
    confidence_score: float
    match_conditions: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    source_category: str = "manual"
    source_mode: str = "unknown"
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "signature_record",
            "record_version": SIGNATURE_RECORD_VERSION,
            "signature_id": sanitize_reference(self.signature_id),
            "signature_name": sanitize_text(self.signature_name),
            "signature_type": normalize_signature_type(self.signature_type),
            "enabled": bool(self.enabled),
            "severity_level": normalize_severity(self.severity_level),
            "confidence_score": clamp_score(self.confidence_score),
            "match_conditions": sanitize_signature_conditions(self.match_conditions),
            "tags": sorted({sanitize_token(tag) for tag in self.tags if sanitize_token(tag)}),
            "source_category": normalize_ioc_source_category(self.source_category),
            "source_mode": normalize_source_mode(self.source_mode),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_signature_record(
    *,
    signature_name: str,
    signature_type: str = "unknown",
    match_conditions: dict[str, Any] | None = None,
    enabled: bool = True,
    severity_level: str = "low",
    confidence_score: float = 0.5,
    tags: list[str] | None = None,
    source_category: str = "manual",
    source_mode: str = "unknown",
    advisory_notes: list[str] | None = None,
    signature_id: str | None = None,
) -> SignatureRecord:
    name = sanitize_text(signature_name)
    if not name:
        raise SignatureRecordError("signature_name is required")
    signature_type = normalize_signature_type(signature_type)
    conditions = validate_match_conditions(match_conditions or {})
    if not conditions:
        raise SignatureRecordError("match_conditions are required")
    record_id = signature_id or "signature-" + digest(
        {
            "signature_name": name,
            "signature_type": signature_type,
            "match_conditions": conditions,
        }
    )[:16]
    notes = list(advisory_notes or [])
    notes.append("metadata-only local signature; no feed lookup, verdict, blocking, or enforcement")
    return SignatureRecord(
        signature_id=record_id,
        signature_name=name,
        signature_type=signature_type,
        enabled=bool(enabled),
        severity_level=normalize_severity(severity_level),
        confidence_score=clamp_score(confidence_score),
        match_conditions=conditions,
        tags=[sanitize_token(tag) for tag in tags or [] if sanitize_token(tag)],
        source_category=normalize_ioc_source_category(source_category),
        source_mode=normalize_source_mode(source_mode),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def validate_match_conditions(match_conditions: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(match_conditions, dict):
        raise SignatureRecordError("match_conditions must be a dictionary")
    unsafe = find_unsafe_condition(match_conditions)
    if unsafe:
        raise SignatureRecordError(f"unsafe signature condition rejected: {unsafe}")
    return sanitize_signature_conditions(match_conditions)


def find_unsafe_condition(value: Any, *, key_path: str = "") -> str:
    if isinstance(value, dict):
        for key, item in value.items():
            token = sanitize_token(key).lower()
            path = f"{key_path}.{token}" if key_path else token
            if token in UNSAFE_CONDITION_KEYS:
                return path
            nested = find_unsafe_condition(item, key_path=path)
            if nested:
                return nested
    elif isinstance(value, (list, tuple, set)):
        for index, item in enumerate(value):
            nested = find_unsafe_condition(item, key_path=f"{key_path}.{index}" if key_path else str(index))
            if nested:
                return nested
    else:
        token = sanitize_token(value).lower()
        if token in UNSAFE_CONDITION_VALUES:
            return key_path or token
    return ""


def sanitize_signature_conditions(value: dict[str, Any]) -> dict[str, Any]:
    return sanitize_metadata(value if isinstance(value, dict) else {})


def normalize_signature_type(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in SIGNATURE_TYPES else "unknown"


def normalize_severity(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in SEVERITY_LEVELS else "unknown"


def empty_signature_record(*, generated_at: str | None = None) -> SignatureRecord:
    timestamp = generated_at or now_timestamp()
    return SignatureRecord(
        signature_id="signature-empty-" + digest(timestamp)[:16],
        signature_name="empty-signature",
        signature_type="unknown",
        enabled=False,
        severity_level="unknown",
        confidence_score=0.0,
        match_conditions={"empty": True},
        tags=[],
        source_category="unknown",
        source_mode="unknown",
        advisory_notes=["empty disabled signature placeholder"],
        preview_only=True,
        destructive_action=False,
    )
