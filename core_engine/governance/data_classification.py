from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes, sanitize_references
from core_engine.scaling.bus_envelopes import digest, normalize_source_mode, sanitize_token


DATA_CLASSIFICATION_RECORD_VERSION = 1
DATA_CATEGORIES = {
    "runtime_metadata",
    "audit_metadata",
    "export_metadata",
    "configuration_metadata",
    "operator_action_metadata",
    "topology_metadata",
    "intelligence_metadata",
    "unknown",
}
SENSITIVITY_LEVELS = {"public", "internal", "sensitive", "restricted", "unknown"}
HANDLING_STATES = {"allowed", "redaction_required", "review_required", "restricted", "unknown"}
DATA_GOVERNANCE_SAFETY_FLAGS = {
    **GOVERNANCE_SAFETY_FLAGS,
    "governance_control_enforced": False,
    "data_deleted": False,
    "file_read_performed": False,
    "runtime_behavior_changed": False,
}


@dataclass(frozen=True)
class DataClassificationRecord:
    classification_id: str
    data_category: str
    sensitivity_level: str
    handling_state: str
    redaction_required: bool
    retention_required: bool
    export_allowed: bool
    expected_redactions: list[str] = field(default_factory=list)
    governance_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "data_classification",
            "record_version": DATA_CLASSIFICATION_RECORD_VERSION,
            "classification_id": sanitize_token(self.classification_id) or "classification-unknown",
            "data_category": normalize_data_category(self.data_category),
            "sensitivity_level": normalize_sensitivity_level(self.sensitivity_level),
            "handling_state": normalize_handling_state(self.handling_state),
            "redaction_required": bool(self.redaction_required),
            "retention_required": bool(self.retention_required),
            "export_allowed": bool(self.export_allowed),
            "expected_redactions": sanitize_references(self.expected_redactions),
            "governance_notes": sanitize_notes(self.governance_notes),
            "source_mode": mode,
            "data_source": mode,
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **DATA_GOVERNANCE_SAFETY_FLAGS,
        }


def build_data_classification(
    *,
    classification_id: Any = "",
    data_category: Any = "unknown",
    sensitivity_level: Any = "",
    handling_state: Any = "",
    redaction_required: Any = None,
    retention_required: Any = True,
    export_allowed: Any = None,
    expected_redactions: Iterable[Any] | None = None,
    governance_notes: Iterable[Any] | None = None,
    source_mode: Any = "unknown",
) -> DataClassificationRecord:
    category = normalize_data_category(data_category)
    sensitivity = normalize_sensitivity_level(sensitivity_level) if sensitivity_level else default_sensitivity_for_category(category)
    handling = normalize_handling_state(handling_state) if handling_state else default_handling_for_sensitivity(sensitivity)
    redaction = bool(redaction_required) if redaction_required is not None else handling in {"redaction_required", "review_required", "restricted"}
    export_ok = bool(export_allowed) if export_allowed is not None else handling not in {"restricted", "unknown"}
    redactions = sanitize_references(expected_redactions or default_redactions_for_category(category, sensitivity))
    notes = sanitize_notes(governance_notes or ["data classification is metadata-only and advisory"])
    safe_id = sanitize_token(classification_id)
    if not safe_id:
        safe_id = "data-classification-" + digest(
            {
                "data_category": category,
                "sensitivity_level": sensitivity,
                "handling_state": handling,
                "source_mode": normalize_source_mode(source_mode),
            }
        )[:16]
    return DataClassificationRecord(
        classification_id=safe_id,
        data_category=category,
        sensitivity_level=sensitivity,
        handling_state=handling,
        redaction_required=redaction,
        retention_required=bool(retention_required),
        export_allowed=export_ok,
        expected_redactions=redactions,
        governance_notes=notes,
        source_mode=normalize_source_mode(source_mode),
        preview_only=True,
        destructive_action=False,
    )


def normalize_data_classification(value: Any) -> DataClassificationRecord:
    if isinstance(value, DataClassificationRecord):
        return value
    if not isinstance(value, dict):
        return build_data_classification(
            data_category="unknown",
            sensitivity_level="unknown",
            handling_state="unknown",
            governance_notes=["invalid classification generated from malformed input"],
        )
    try:
        return build_data_classification(
            classification_id=value.get("classification_id", ""),
            data_category=value.get("data_category", value.get("category", "unknown")),
            sensitivity_level=value.get("sensitivity_level", value.get("sensitivity", "")),
            handling_state=value.get("handling_state", value.get("state", "")),
            redaction_required=value.get("redaction_required") if "redaction_required" in value else None,
            retention_required=value.get("retention_required", True),
            export_allowed=value.get("export_allowed") if "export_allowed" in value else None,
            expected_redactions=value.get("expected_redactions") if isinstance(value.get("expected_redactions"), list) else None,
            governance_notes=value.get("governance_notes") if isinstance(value.get("governance_notes"), list) else None,
            source_mode=value.get("source_mode", value.get("data_source", "unknown")),
        )
    except Exception as exc:
        return build_data_classification(handling_state="unknown", governance_notes=[str(exc)])


def summarize_classifications(classifications: Iterable[DataClassificationRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_data_classification(classification).to_dict() for classification in list(classifications or [])]
    category_counts: dict[str, int] = {}
    sensitivity_counts: dict[str, int] = {}
    handling_counts: dict[str, int] = {}
    for row in rows:
        category_counts[row["data_category"]] = category_counts.get(row["data_category"], 0) + 1
        sensitivity_counts[row["sensitivity_level"]] = sensitivity_counts.get(row["sensitivity_level"], 0) + 1
        handling_counts[row["handling_state"]] = handling_counts.get(row["handling_state"], 0) + 1
    return {
        "record_type": "data_classification_summary",
        "classification_count": len(rows),
        "category_counts": dict(sorted(category_counts.items())),
        "sensitivity_counts": dict(sorted(sensitivity_counts.items())),
        "handling_counts": dict(sorted(handling_counts.items())),
        "redaction_required_count": sum(1 for row in rows if row.get("redaction_required")),
        "retention_required_count": sum(1 for row in rows if row.get("retention_required")),
        "export_allowed_count": sum(1 for row in rows if row.get("export_allowed")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DATA_GOVERNANCE_SAFETY_FLAGS,
    }


def default_sensitivity_for_category(category: str) -> str:
    return {
        "runtime_metadata": "internal",
        "audit_metadata": "sensitive",
        "export_metadata": "sensitive",
        "configuration_metadata": "restricted",
        "operator_action_metadata": "sensitive",
        "topology_metadata": "sensitive",
        "intelligence_metadata": "sensitive",
        "unknown": "unknown",
    }.get(category, "unknown")


def default_handling_for_sensitivity(sensitivity: str) -> str:
    return {
        "public": "allowed",
        "internal": "review_required",
        "sensitive": "redaction_required",
        "restricted": "restricted",
        "unknown": "unknown",
    }.get(sensitivity, "unknown")


def default_redactions_for_category(category: str, sensitivity: str) -> list[str]:
    if sensitivity in {"restricted", "sensitive"}:
        return {
            "configuration_metadata": ["credentials", "tokens", "private_paths", "operator_identifiers"],
            "operator_action_metadata": ["actor_reference", "target_reference"],
            "topology_metadata": ["private_addresses", "host_identifiers"],
            "intelligence_metadata": ["raw_indicators", "private_observations"],
        }.get(category, ["private_identifiers", "raw_values"])
    if sensitivity == "internal":
        return ["operator_context", "local_paths"]
    return []


def normalize_data_category(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in DATA_CATEGORIES else "unknown"


def normalize_sensitivity_level(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in SENSITIVITY_LEVELS else "unknown"


def normalize_handling_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in HANDLING_STATES else "unknown"


def deterministic_data_classification_json(record: DataClassificationRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, DataClassificationRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "DATA_CATEGORIES",
    "DATA_GOVERNANCE_SAFETY_FLAGS",
    "HANDLING_STATES",
    "SENSITIVITY_LEVELS",
    "DataClassificationRecord",
    "build_data_classification",
    "deterministic_data_classification_json",
    "normalize_data_category",
    "normalize_data_classification",
    "normalize_handling_state",
    "normalize_sensitivity_level",
    "summarize_classifications",
]
