from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any

from core_engine.diagnostics.schema_validation import SAFETY_FLAGS, validate_fixture, validate_schema_definition


def mutate_fixture(
    schema: dict[str, Any],
    fixture: dict[str, Any],
    *,
    max_mutations: int = 16,
    max_fixture_size: int = 8192,
) -> dict[str, Any]:
    schema_result = validate_schema_definition(schema)
    if not schema_result["ok"]:
        return _mutation_result("unsupported", [], schema_result["errors"], [])
    if not isinstance(fixture, dict):
        return _mutation_result("malformed", [], ["fixture must be an object"], [])
    if _estimated_size(fixture) > max_fixture_size:
        return _mutation_result(
            "mutation_limited",
            [],
            [f"fixture estimate exceeds max size {max_fixture_size}"],
            [],
        )

    warnings: list[str] = []
    variants: list[dict[str, Any]] = []
    fields = schema.get("fields") or {}
    for field_name, field_schema in fields.items():
        if len(variants) >= max_mutations:
            warnings.append("mutation limit reached")
            break
        if field_schema.get("required", False) and field_name in fixture:
            variants.append(_variant(schema, fixture, field_name, "missing_required_field", None))
        if len(variants) >= max_mutations:
            warnings.append("mutation limit reached")
            break
        value = fixture.get(field_name)
        field_type = str(field_schema.get("type") or "")
        if field_type in {"str", "hex", "bytes", "list"}:
            min_length = int(field_schema.get("min_length", 1))
            max_length = int(field_schema.get("max_length", max(min_length, 1)))
            variants.append(_variant(schema, fixture, field_name, "field_length_below_minimum", _short_value(field_type, min_length)))
            if len(variants) >= max_mutations:
                warnings.append("mutation limit reached")
                break
            variants.append(_variant(schema, fixture, field_name, "field_length_above_maximum", _long_value(field_type, max_length)))
        elif field_type in {"int", "float"}:
            min_value = field_schema.get("min_value")
            max_value = field_schema.get("max_value")
            if min_value is not None:
                variants.append(_variant(schema, fixture, field_name, "value_below_minimum", float(min_value) - 1))
            elif max_value is not None:
                variants.append(_variant(schema, fixture, field_name, "value_above_maximum", float(max_value) + 1))
        elif field_type == "bool":
            variants.append(_variant(schema, fixture, field_name, "type_mismatch", "not-bool"))
        if len(variants) >= max_mutations:
            warnings.append("mutation limit reached")
            break
        if field_type == "bytes" and isinstance(value, (bytes, bytearray)):
            variants.append(_variant(schema, fixture, field_name, "byte_value_mutation", _flip_first_byte(bytes(value))))
        elif field_type == "hex" and isinstance(value, str) and len(value) >= 2:
            variants.append(_variant(schema, fixture, field_name, "byte_value_mutation", _flip_first_hex_byte(value)))

    if len(variants) < max_mutations:
        mutated = deepcopy(fixture)
        mutated["unexpected_sample_field"] = "unexpected-value"
        variants.append(_make_variant(schema, fixture, mutated, "unexpected_field", "unexpected_sample_field"))
    else:
        warnings.append("mutation limit reached")

    status = "ok" if variants else "mutation_limited"
    return _mutation_result(status, variants[:max_mutations], [], warnings)


def summarize_mutation_result(result: dict[str, Any]) -> dict[str, Any]:
    variants = [row for row in result.get("variants") or [] if isinstance(row, dict)]
    mutation_type_counts: dict[str, int] = {}
    validation_classification_counts: dict[str, int] = {}
    for variant in variants:
        mutation_type = str(variant.get("mutation_type") or "unknown")
        mutation_type_counts[mutation_type] = mutation_type_counts.get(mutation_type, 0) + 1
        validation = variant.get("validation") if isinstance(variant.get("validation"), dict) else {}
        classification = str(validation.get("classification") or "unknown")
        validation_classification_counts[classification] = validation_classification_counts.get(classification, 0) + 1
    return {
        "classification": str(result.get("classification") or "unknown"),
        "mutation_count": len(variants),
        "mutation_type_counts": dict(sorted(mutation_type_counts.items())),
        "validation_classification_counts": dict(sorted(validation_classification_counts.items())),
        "error_count": len(result.get("errors") or []),
        "warning_count": len(result.get("warnings") or []),
        "recommended_review": bool(result.get("errors")) or any(key != "valid" for key in validation_classification_counts),
        **SAFETY_FLAGS,
    }


def _variant(schema: dict[str, Any], fixture: dict[str, Any], field_name: str, mutation_type: str, value: Any) -> dict[str, Any]:
    mutated = deepcopy(fixture)
    if mutation_type == "missing_required_field":
        mutated.pop(field_name, None)
    else:
        mutated[field_name] = value
    return _make_variant(schema, fixture, mutated, mutation_type, field_name)


def _make_variant(
    schema: dict[str, Any],
    original: dict[str, Any],
    mutated: dict[str, Any],
    mutation_type: str,
    field_name: str,
) -> dict[str, Any]:
    validation = validate_fixture(schema, mutated)
    material = f"{mutation_type}:{field_name}:{_estimated_size(original)}:{_estimated_size(mutated)}"
    return {
        "mutation_id": "mutation-" + sha256(material.encode("utf-8")).hexdigest()[:12],
        "mutation_type": mutation_type,
        "field_name": field_name,
        "fixture": _json_safe(mutated),
        "validation": validation,
        **SAFETY_FLAGS,
    }


def _mutation_result(
    status: str,
    variants: list[dict[str, Any]],
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    classification = "mutation_limited" if status == "mutation_limited" else status
    if status == "ok":
        classification = "valid"
    payload = {
        "ok": status == "ok",
        "status": status,
        "classification": classification,
        "diagnostic_type": "fixture_mutation",
        "mutation_count": len(variants),
        "variants": variants,
        "errors": errors,
        "warnings": warnings,
        **SAFETY_FLAGS,
        "integration_hooks": {
            "event_pipeline_ready": True,
            "policy_review_ready": status != "ok",
            "timeline_ready": True,
            "correlation_ready": True,
            "storage_ready": True,
        },
    }
    payload["summary"] = summarize_mutation_result(payload)
    payload["integration_hooks"]["policy_review_ready"] = payload["summary"]["recommended_review"]
    return payload


def _short_value(field_type: str, min_length: int) -> Any:
    target_length = max(0, min_length - 1)
    if field_type == "bytes":
        return b"\x00" * target_length
    if field_type == "list":
        return ["sample"] * target_length
    if field_type == "hex":
        return "00" * target_length
    return "x" * target_length


def _long_value(field_type: str, max_length: int) -> Any:
    target_length = max_length + 1
    if field_type == "bytes":
        return b"\x41" * target_length
    if field_type == "list":
        return ["sample"] * target_length
    if field_type == "hex":
        return "41" * target_length
    return "x" * target_length


def _flip_first_byte(value: bytes) -> bytes:
    if not value:
        return b"\xff"
    return bytes([value[0] ^ 0xFF]) + value[1:]


def _flip_first_hex_byte(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return "ff"
    return _flip_first_byte(raw).hex()


def _estimated_size(value: Any) -> int:
    if isinstance(value, dict):
        return sum(len(str(key)) + _estimated_size(item) for key, item in value.items())
    if isinstance(value, list):
        return sum(_estimated_size(item) for item in value)
    if isinstance(value, (bytes, bytearray, str)):
        return len(value)
    return len(str(value))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return {
            "type": "bytes",
            "length": len(raw),
            "hex_summary": raw[:16].hex(),
        }
    return value
