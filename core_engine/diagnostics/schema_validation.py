from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


SCHEMA_VALIDATION_RECORD_VERSION = 2
SUPPORTED_FIELD_TYPES = {"bytes", "dict", "float", "hex", "int", "list", "str", "bool"}
VALID_CLASSIFICATIONS = {"valid", "invalid", "malformed", "unsupported", "mutation_limited"}
CLASSIFICATION_SEVERITY = {
    "valid": "info",
    "invalid": "medium",
    "malformed": "high",
    "unsupported": "high",
    "mutation_limited": "low",
}
SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


class SchemaValidationError(ValueError):
    """Raised when a schema definition is not supported by the local validator."""


def validate_schema_definition(schema: dict[str, Any]) -> dict[str, Any]:
    errors = _schema_errors(schema)
    return {
        "ok": not errors,
        "status": "valid" if not errors else "invalid",
        "classification": "valid" if not errors else "malformed",
        "schema_id": _schema_id(schema) if isinstance(schema, dict) else "",
        "errors": errors,
        **SAFETY_FLAGS,
    }


def validate_fixture(
    schema: dict[str, Any],
    fixture: dict[str, Any],
    *,
    max_fields: int = 64,
    max_string_length: int = 4096,
    max_bytes_length: int = 4096,
) -> dict[str, Any]:
    schema_errors = _schema_errors(schema)
    if schema_errors:
        return _result("unsupported", schema, [], schema_errors, [], _bounds(max_fields, max_string_length, max_bytes_length))
    if not isinstance(fixture, dict):
        return _result("malformed", schema, [], ["fixture must be an object"], [], _bounds(max_fields, max_string_length, max_bytes_length))
    if len(fixture) > max_fields:
        return _result(
            "malformed",
            schema,
            [],
            [f"fixture exceeds max field count {max_fields}"],
            [],
            _bounds(max_fields, max_string_length, max_bytes_length),
        )

    field_defs = schema.get("fields") or {}
    errors: list[str] = []
    warnings: list[str] = []
    field_results: list[dict[str, Any]] = []

    for field_name, field_schema in field_defs.items():
        required = bool(field_schema.get("required", False))
        if field_name not in fixture:
            status = "missing_required" if required else "missing_optional"
            if required:
                errors.append(f"{field_name} is required")
            field_results.append(_field_result(field_name, status, field_schema, None))
            continue
        value = fixture[field_name]
        status, field_errors, field_warnings = _validate_field_value(
            field_name,
            value,
            field_schema,
            max_string_length=max_string_length,
            max_bytes_length=max_bytes_length,
        )
        errors.extend(field_errors)
        warnings.extend(field_warnings)
        field_results.append(_field_result(field_name, status, field_schema, value))

    unexpected = sorted(set(fixture) - set(field_defs))
    for field_name in unexpected:
        warnings.append(f"{field_name} is not defined by schema")
        field_results.append(
            {
                "field": field_name,
                "status": "unexpected",
                "expected_type": "unknown",
                "observed_type": type(fixture[field_name]).__name__,
                "length": _safe_length(fixture[field_name]),
            }
        )

    classification = "valid" if not errors else "invalid"
    return _result(classification, schema, field_results, errors, warnings, _bounds(max_fields, max_string_length, max_bytes_length))


def classify_exception(error: BaseException) -> dict[str, Any]:
    if isinstance(error, SchemaValidationError):
        classification = "unsupported"
    elif isinstance(error, (TypeError, ValueError, KeyError)):
        classification = "malformed"
    else:
        classification = "invalid"
    return {
        "ok": False,
        "status": classification,
        "classification": classification,
        "error_type": type(error).__name__,
        "message": str(error),
        **SAFETY_FLAGS,
    }


def summarize_validation_result(result: dict[str, Any]) -> dict[str, Any]:
    field_results = [row for row in result.get("field_results") or [] if isinstance(row, dict)]
    status_counts: dict[str, int] = {}
    for row in field_results:
        status = str(row.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    classification = str(result.get("classification") or "invalid")
    return {
        "schema_id": str(result.get("schema_id") or ""),
        "classification": classification,
        "severity": CLASSIFICATION_SEVERITY.get(classification, "medium"),
        "field_count": len(field_results),
        "status_counts": dict(sorted(status_counts.items())),
        "error_count": len(result.get("errors") or []),
        "warning_count": len(result.get("warnings") or []),
        "recommended_review": classification != "valid",
        **SAFETY_FLAGS,
    }


def build_validation_event(
    result: dict[str, Any],
    *,
    source: str = "diagnostics.schema_validation",
    timestamp: str | None = None,
) -> dict[str, Any]:
    summary = summarize_validation_result(result)
    severity = summary["severity"]
    event_type = "system_notice" if severity in {"info", "low"} else "policy_review_required"
    message = _operator_summary(summary)
    return {
        "event_id": _stable_id("evt", result.get("result_id"), event_type, message),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "timestamp": timestamp or _now(),
        "message": message,
        "asset_ref": None,
        "service_ref": None,
        "flow_ref": None,
        "snapshot_ref": None,
        "finding_ref": _stable_id("finding", result.get("result_id"), summary["classification"]),
        "metadata": {
            "diagnostic_type": "schema_validation",
            "schema_id": summary["schema_id"],
            "classification": summary["classification"],
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_validation_finding(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_validation_result(result)
    finding_id = _stable_id("finding", result.get("result_id"), summary["classification"], summary["schema_id"])
    return {
        "finding_id": finding_id,
        "finding_type": "schema_validation_result",
        "category": "diagnostic_validation",
        "severity": summary["severity"],
        "title": "Schema Validation Result",
        "summary": _operator_summary(summary),
        "evidence_refs": [summary["schema_id"]],
        "recommended_review": summary["recommended_review"],
        "source_refs": [source_ref or f"schema:{summary['schema_id']}"],
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def build_validation_timeline_entry(
    result: dict[str, Any],
    *,
    timestamp: str | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    summary = summarize_validation_result(result)
    text = _operator_summary(summary)
    return {
        "timeline_id": _stable_id("timeline", result.get("result_id"), text),
        "timestamp": timestamp or _now(),
        "category": "diagnostic_validation",
        "severity": summary["severity"],
        "title": "Schema Validation",
        "summary": text,
        "asset_ref": None,
        "service_ref": None,
        "snapshot_ref": None,
        "source_refs": [source_ref or f"schema:{summary['schema_id']}"],
        "recommended_review": summary["recommended_review"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_validation_correlation_record(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    finding = build_validation_finding(result, source_ref=source_ref)
    return {
        **finding,
        "correlation_key": f"schema_validation:{finding['category']}:{finding['severity']}",
        "score": 0.0,
        "confidence": 1.0 if result.get("ok") else 0.75,
    }


def _schema_errors(schema: Any) -> list[str]:
    if not isinstance(schema, dict):
        return ["schema must be an object"]
    fields = schema.get("fields")
    if not isinstance(fields, dict) or not fields:
        return ["schema fields must be a non-empty object"]
    errors: list[str] = []
    for field_name, field_schema in fields.items():
        if not isinstance(field_name, str) or not field_name:
            errors.append("field names must be non-empty strings")
            continue
        if not isinstance(field_schema, dict):
            errors.append(f"{field_name} definition must be an object")
            continue
        field_type = field_schema.get("type")
        if field_type not in SUPPORTED_FIELD_TYPES:
            errors.append(f"{field_name} has unsupported type {field_type!r}")
        if "min_length" in field_schema and "max_length" in field_schema:
            if int(field_schema["min_length"]) > int(field_schema["max_length"]):
                errors.append(f"{field_name} min_length exceeds max_length")
        if "min_value" in field_schema and "max_value" in field_schema:
            if float(field_schema["min_value"]) > float(field_schema["max_value"]):
                errors.append(f"{field_name} min_value exceeds max_value")
        allowed = field_schema.get("allowed_values")
        if allowed is not None and not isinstance(allowed, list):
            errors.append(f"{field_name} allowed_values must be a list")
    return errors


def _validate_field_value(
    field_name: str,
    value: Any,
    field_schema: dict[str, Any],
    *,
    max_string_length: int,
    max_bytes_length: int,
) -> tuple[str, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    field_type = str(field_schema.get("type"))
    if not _matches_type(value, field_type):
        return "invalid_type", [f"{field_name} expected {field_type}"], []

    length = _safe_length(value)
    if length is not None:
        if isinstance(value, str) and length > max_string_length:
            errors.append(f"{field_name} exceeds max string length {max_string_length}")
        if isinstance(value, (bytes, bytearray)) and length > max_bytes_length:
            errors.append(f"{field_name} exceeds max bytes length {max_bytes_length}")
        min_length = field_schema.get("min_length")
        max_length = field_schema.get("max_length")
        if min_length is not None and length < int(min_length):
            errors.append(f"{field_name} length below minimum {min_length}")
        if max_length is not None and length > int(max_length):
            errors.append(f"{field_name} length above maximum {max_length}")

    if field_type == "hex" and not _is_hex_string(value):
        errors.append(f"{field_name} must be a hex string")

    min_value = field_schema.get("min_value")
    max_value = field_schema.get("max_value")
    if min_value is not None and isinstance(value, (int, float)) and value < float(min_value):
        errors.append(f"{field_name} below minimum value {min_value}")
    if max_value is not None and isinstance(value, (int, float)) and value > float(max_value):
        errors.append(f"{field_name} above maximum value {max_value}")

    allowed = field_schema.get("allowed_values")
    if allowed is not None and value not in allowed:
        errors.append(f"{field_name} value is not allowed")

    status = "valid" if not errors else "invalid_value"
    return status, errors, warnings


def _matches_type(value: Any, field_type: str) -> bool:
    if field_type == "str":
        return isinstance(value, str)
    if field_type == "hex":
        return isinstance(value, str)
    if field_type == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type == "float":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if field_type == "bool":
        return isinstance(value, bool)
    if field_type == "bytes":
        return isinstance(value, (bytes, bytearray))
    if field_type == "dict":
        return isinstance(value, dict)
    if field_type == "list":
        return isinstance(value, list)
    return False


def _field_result(field_name: str, status: str, field_schema: dict[str, Any], value: Any) -> dict[str, Any]:
    return {
        "field": field_name,
        "status": status,
        "expected_type": str(field_schema.get("type") or "unknown"),
        "required": bool(field_schema.get("required", False)),
        "observed_type": type(value).__name__ if value is not None else "missing",
        "length": _safe_length(value),
    }


def _result(
    classification: str,
    schema: dict[str, Any],
    field_results: list[dict[str, Any]],
    errors: list[str],
    warnings: list[str],
    resource_bounds: dict[str, int],
) -> dict[str, Any]:
    if classification not in VALID_CLASSIFICATIONS:
        classification = "invalid"
    payload = {
        "ok": classification == "valid",
        "status": classification,
        "classification": classification,
        "record_version": SCHEMA_VALIDATION_RECORD_VERSION,
        "diagnostic_type": "schema_validation",
        "schema_id": _schema_id(schema),
        "field_results": field_results,
        "errors": errors,
        "warnings": warnings,
        "resource_bounds": resource_bounds,
        **SAFETY_FLAGS,
    }
    payload["summary"] = summarize_validation_result(payload)
    payload["integration_hooks"] = _integration_hooks(payload)
    payload["result_id"] = _stable_id("schema-result", payload["schema_id"], classification, payload["summary"])
    return payload


def _bounds(max_fields: int, max_string_length: int, max_bytes_length: int) -> dict[str, int]:
    return {
        "max_fields": max_fields,
        "max_string_length": max_string_length,
        "max_bytes_length": max_bytes_length,
    }


def _integration_hooks(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "event_pipeline_ready": True,
        "policy_review_ready": result.get("classification") != "valid",
        "timeline_ready": True,
        "correlation_ready": True,
        "storage_ready": True,
    }


def _schema_id(schema: Any) -> str:
    name = "schema"
    version = ""
    if isinstance(schema, dict):
        name = str(schema.get("schema_id") or schema.get("name") or "schema")
        version = str(schema.get("version") or "")
    digest = sha256(f"{name}:{version}".encode("utf-8")).hexdigest()[:12]
    return f"{name}-{digest}"


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _operator_summary(summary: dict[str, Any]) -> str:
    classification = str(summary.get("classification") or "unknown")
    schema_id = str(summary.get("schema_id") or "schema")
    error_count = int(summary.get("error_count") or 0)
    warning_count = int(summary.get("warning_count") or 0)
    if classification == "valid":
        return f"Schema {schema_id} validated successfully."
    return f"Schema {schema_id} classified as {classification} with {error_count} errors and {warning_count} warnings."


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_length(value: Any) -> int | None:
    if isinstance(value, (str, bytes, bytearray, list, dict)):
        return len(value)
    return None


def _is_hex_string(value: Any) -> bool:
    if not isinstance(value, str) or len(value) % 2:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True
