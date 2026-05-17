from __future__ import annotations

from hashlib import sha256
from typing import Any


SUPPORTED_FIELD_TYPES = {"bytes", "dict", "float", "hex", "int", "list", "str", "bool"}
VALID_CLASSIFICATIONS = {"valid", "invalid", "malformed", "unsupported", "mutation_limited"}
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
        return _result("unsupported", schema, [], schema_errors, [])
    if not isinstance(fixture, dict):
        return _result("malformed", schema, [], ["fixture must be an object"], [])
    if len(fixture) > max_fields:
        return _result("malformed", schema, [], [f"fixture exceeds max field count {max_fields}"], [])

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
    return _result(classification, schema, field_results, errors, warnings)


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
        "observed_type": type(value).__name__ if value is not None else "missing",
        "length": _safe_length(value),
    }


def _result(
    classification: str,
    schema: dict[str, Any],
    field_results: list[dict[str, Any]],
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    if classification not in VALID_CLASSIFICATIONS:
        classification = "invalid"
    return {
        "ok": classification == "valid",
        "status": classification,
        "classification": classification,
        "schema_id": _schema_id(schema),
        "field_results": field_results,
        "errors": errors,
        "warnings": warnings,
        **SAFETY_FLAGS,
    }


def _schema_id(schema: Any) -> str:
    name = "schema"
    version = ""
    if isinstance(schema, dict):
        name = str(schema.get("schema_id") or schema.get("name") or "schema")
        version = str(schema.get("version") or "")
    digest = sha256(f"{name}:{version}".encode("utf-8")).hexdigest()[:12]
    return f"{name}-{digest}"


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
