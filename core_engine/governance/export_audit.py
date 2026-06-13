from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes, sanitize_references
from core_engine.scaling.bus_envelopes import digest, now_timestamp, safe_int, sanitize_reference, sanitize_token


EXPORT_AUDIT_RECORD_VERSION = 1
EXPORT_AUDIT_STATES = {"valid", "incomplete", "degraded", "missing", "invalid", "unknown"}
EXPORT_TYPES = {"logs", "topology", "flows", "risk", "runtime", "evidence_bundle", "unknown"}


@dataclass(frozen=True)
class ExportAuditRecord:
    export_audit_id: str
    generated_at: str
    export_state: str
    export_reference: str
    export_type: str
    file_count: int
    total_size_bytes: int
    expected_files: list[str] = field(default_factory=list)
    observed_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    schema_validation_state: str = "unknown"
    sensitive_data_scan_state: str = "unknown"
    artifact_check_state: str = "unknown"
    last_export_summary: dict[str, Any] = field(default_factory=dict)
    validation_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "export_audit_record",
            "record_version": EXPORT_AUDIT_RECORD_VERSION,
            "export_audit_id": sanitize_reference(self.export_audit_id),
            "generated_at": str(self.generated_at or ""),
            "export_state": normalize_export_audit_state(self.export_state),
            "export_reference": sanitize_reference(self.export_reference) or "export-unknown",
            "export_type": normalize_export_type(self.export_type),
            "file_count": max(0, int(self.file_count or 0)),
            "total_size_bytes": max(0, int(self.total_size_bytes or 0)),
            "expected_files": sanitize_references(self.expected_files),
            "observed_files": sanitize_references(self.observed_files),
            "missing_files": sanitize_references(self.missing_files),
            "schema_validation_state": normalize_export_audit_state(self.schema_validation_state),
            "sensitive_data_scan_state": normalize_export_audit_state(self.sensitive_data_scan_state),
            "artifact_check_state": normalize_export_audit_state(self.artifact_check_state),
            "last_export_summary": dict(self.last_export_summary),
            "validation_recommendations": sanitize_notes(self.validation_recommendations),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **GOVERNANCE_SAFETY_FLAGS,
        }


def build_export_audit(
    *,
    export_audit_id: Any = "",
    generated_at: Any = None,
    export_state: Any = "",
    export_reference: Any = "export-unknown",
    export_type: Any = "unknown",
    file_count: Any = None,
    total_size_bytes: Any = 0,
    expected_files: Iterable[Any] | None = None,
    observed_files: Iterable[Any] | None = None,
    missing_files: Iterable[Any] | None = None,
    schema_validation_state: Any = "unknown",
    sensitive_data_scan_state: Any = "unknown",
    artifact_check_state: Any = "unknown",
    last_export_summary: dict[str, Any] | None = None,
    validation_recommendations: Iterable[Any] | None = None,
) -> ExportAuditRecord:
    timestamp = str(generated_at or now_timestamp())
    expected = sanitize_references(expected_files or [])
    observed = sanitize_references(observed_files or [])
    missing = sanitize_references(missing_files if missing_files is not None else sorted(set(expected) - set(observed)))
    count = safe_int(len(observed) if file_count in (None, "") else file_count)
    size = safe_int(total_size_bytes)
    state = normalize_export_audit_state(export_state) if export_state else infer_export_state(
        expected_files=expected,
        observed_files=observed,
        missing_files=missing,
        schema_validation_state=schema_validation_state,
        sensitive_data_scan_state=sensitive_data_scan_state,
        artifact_check_state=artifact_check_state,
    )
    summary = last_export_summary or build_last_export_summary(
        export_reference=export_reference,
        export_type=export_type,
        file_count=count,
        total_size_bytes=size,
        generated_at=timestamp,
    )
    recommendations = sanitize_notes(
        validation_recommendations
        or build_validation_recommendations(
            export_state=state,
            missing_files=missing,
            schema_validation_state=schema_validation_state,
            sensitive_data_scan_state=sensitive_data_scan_state,
            artifact_check_state=artifact_check_state,
        )
    )
    safe_id = sanitize_reference(export_audit_id)
    if not safe_id:
        safe_id = "export-audit-" + digest(
            {
                "generated_at": timestamp,
                "export_reference": sanitize_reference(export_reference),
                "export_type": normalize_export_type(export_type),
                "expected_files": expected,
                "observed_files": observed,
            }
        )[:16]
    return ExportAuditRecord(
        export_audit_id=safe_id,
        generated_at=timestamp,
        export_state=state,
        export_reference=sanitize_reference(export_reference) or "export-unknown",
        export_type=normalize_export_type(export_type),
        file_count=count,
        total_size_bytes=size,
        expected_files=expected,
        observed_files=observed,
        missing_files=missing,
        schema_validation_state=normalize_export_audit_state(schema_validation_state),
        sensitive_data_scan_state=normalize_export_audit_state(sensitive_data_scan_state),
        artifact_check_state=normalize_export_audit_state(artifact_check_state),
        last_export_summary=summary,
        validation_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def normalize_export_audit(value: Any) -> ExportAuditRecord:
    if isinstance(value, ExportAuditRecord):
        return value
    if not isinstance(value, dict):
        return build_export_audit(export_state="invalid", validation_recommendations=["malformed export audit input"])
    try:
        return build_export_audit(
            export_audit_id=value.get("export_audit_id", ""),
            generated_at=value.get("generated_at"),
            export_state=value.get("export_state", ""),
            export_reference=value.get("export_reference", ""),
            export_type=value.get("export_type", "unknown"),
            file_count=value.get("file_count"),
            total_size_bytes=value.get("total_size_bytes", 0),
            expected_files=value.get("expected_files") if isinstance(value.get("expected_files"), list) else None,
            observed_files=value.get("observed_files") if isinstance(value.get("observed_files"), list) else None,
            missing_files=value.get("missing_files") if isinstance(value.get("missing_files"), list) else None,
            schema_validation_state=value.get("schema_validation_state", "unknown"),
            sensitive_data_scan_state=value.get("sensitive_data_scan_state", "unknown"),
            artifact_check_state=value.get("artifact_check_state", "unknown"),
            last_export_summary=value.get("last_export_summary") if isinstance(value.get("last_export_summary"), dict) else None,
            validation_recommendations=value.get("validation_recommendations") if isinstance(value.get("validation_recommendations"), list) else None,
        )
    except Exception as exc:
        return build_export_audit(export_state="invalid", validation_recommendations=[str(exc)])


def build_last_export_summary(
    *,
    export_reference: Any,
    export_type: Any,
    file_count: Any,
    total_size_bytes: Any,
    generated_at: Any = None,
) -> dict[str, Any]:
    return {
        "record_type": "last_export_summary",
        "generated_at": str(generated_at or now_timestamp()),
        "export_reference": sanitize_reference(export_reference) or "export-unknown",
        "export_type": normalize_export_type(export_type),
        "file_count": safe_int(file_count),
        "total_size_bytes": safe_int(total_size_bytes),
        "metadata_summary_only": True,
        "zip_extracted": False,
        "private_export_read": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **GOVERNANCE_SAFETY_FLAGS,
    }


def build_validation_recommendations(
    *,
    export_state: str,
    missing_files: list[str],
    schema_validation_state: Any,
    sensitive_data_scan_state: Any,
    artifact_check_state: Any,
) -> list[str]:
    recommendations = ["keep export validation metadata-only; do not extract archives by default"]
    if export_state in {"missing", "incomplete", "invalid"}:
        recommendations.append("review export manifest and regenerate export if operator-approved")
    if missing_files:
        recommendations.append("review missing expected file summaries")
    if normalize_export_audit_state(schema_validation_state) != "valid":
        recommendations.append("run schema validation before sharing export")
    if normalize_export_audit_state(sensitive_data_scan_state) != "valid":
        recommendations.append("run sensitive-data scan before sharing export")
    if normalize_export_audit_state(artifact_check_state) != "valid":
        recommendations.append("run artifact/private-file check before sharing export")
    return recommendations


def infer_export_state(
    *,
    expected_files: list[str],
    observed_files: list[str],
    missing_files: list[str],
    schema_validation_state: Any,
    sensitive_data_scan_state: Any,
    artifact_check_state: Any,
) -> str:
    if expected_files and not observed_files:
        return "missing"
    if missing_files:
        return "incomplete"
    states = {
        normalize_export_audit_state(schema_validation_state),
        normalize_export_audit_state(sensitive_data_scan_state),
        normalize_export_audit_state(artifact_check_state),
    }
    if "invalid" in states:
        return "invalid"
    if "degraded" in states or "unknown" in states:
        return "degraded"
    return "valid"


def normalize_export_audit_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in EXPORT_AUDIT_STATES else "unknown"


def normalize_export_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in EXPORT_TYPES else "unknown"


def deterministic_export_audit_json(record: ExportAuditRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, ExportAuditRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "EXPORT_AUDIT_STATES",
    "EXPORT_TYPES",
    "ExportAuditRecord",
    "build_export_audit",
    "build_last_export_summary",
    "deterministic_export_audit_json",
    "infer_export_state",
    "normalize_export_audit",
    "normalize_export_audit_state",
    "normalize_export_type",
]
