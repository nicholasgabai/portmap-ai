import json
import re

from core_engine.diagnostics import (
    SchemaValidationError,
    classify_exception,
    mutate_fixture,
    validate_fixture,
    validate_schema_definition,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _schema():
    return {
        "name": "sample_message",
        "version": "sample-version",
        "fields": {
            "message_type": {"type": "str", "required": True, "allowed_values": ["sample_request", "sample_response"]},
            "sequence": {"type": "int", "required": True, "min_value": 1, "max_value": 99},
            "payload_hex": {"type": "hex", "required": True, "min_length": 2, "max_length": 16},
            "payload_bytes": {"type": "bytes", "required": False, "min_length": 1, "max_length": 8},
            "labels": {"type": "list", "required": False, "max_length": 3},
            "metadata": {"type": "dict", "required": False},
        },
    }


def _fixture():
    return {
        "message_type": "sample_request",
        "sequence": 7,
        "payload_hex": "414243",
        "payload_bytes": b"ABC",
        "labels": ["sample"],
        "metadata": {"source": "fixture"},
    }


def test_schema_definition_validation_accepts_supported_schema():
    result = validate_schema_definition(_schema())

    assert result["ok"] is True
    assert result["classification"] == "valid"
    assert result["schema_id"].startswith("sample_message-")
    assert result["raw_payload_stored"] is False


def test_schema_definition_validation_rejects_unsupported_type():
    schema = _schema()
    schema["fields"]["payload_hex"]["type"] = "unsupported_type"

    result = validate_schema_definition(schema)

    assert result["ok"] is False
    assert result["classification"] == "malformed"
    assert "unsupported type" in result["errors"][0]


def test_valid_fixture_returns_field_summaries_without_raw_payload_storage():
    result = validate_fixture(_schema(), _fixture())

    assert result["ok"] is True
    assert result["classification"] == "valid"
    assert len(result["field_results"]) == 6
    assert result["automatic_changes"] is False
    assert result["administrator_controlled"] is True
    assert result["local_only"] is True
    json.dumps(result)


def test_invalid_fixture_reports_missing_required_and_bad_values():
    fixture = _fixture()
    fixture.pop("message_type")
    fixture["sequence"] = 120
    fixture["payload_hex"] = "not-hex"

    result = validate_fixture(_schema(), fixture)

    assert result["ok"] is False
    assert result["classification"] == "invalid"
    assert any("message_type is required" in error for error in result["errors"])
    assert any("above maximum value" in error for error in result["errors"])
    assert any("must be a hex string" in error for error in result["errors"])


def test_malformed_fixture_and_unsupported_schema_are_classified_safely():
    malformed = validate_fixture(_schema(), ["not", "object"])
    unsupported = validate_fixture({"fields": {"sample": {"type": "callable"}}}, {})

    assert malformed["classification"] == "malformed"
    assert unsupported["classification"] == "unsupported"


def test_exception_classification():
    unsupported = classify_exception(SchemaValidationError("sample unsupported schema"))
    malformed = classify_exception(ValueError("sample malformed fixture"))

    assert unsupported["classification"] == "unsupported"
    assert malformed["classification"] == "malformed"
    assert unsupported["raw_payload_stored"] is False


def test_fixture_mutation_generates_bounded_variants_and_validation_results():
    result = mutate_fixture(_schema(), _fixture(), max_mutations=5)

    assert result["ok"] is True
    assert result["mutation_count"] == 5
    assert any(variant["mutation_type"] == "missing_required_field" for variant in result["variants"])
    assert all("validation" in variant for variant in result["variants"])
    assert all(variant["automatic_changes"] is False for variant in result["variants"])
    json.dumps(result)


def test_fixture_mutation_handles_byte_values_as_json_safe_summaries():
    result = mutate_fixture(_schema(), _fixture(), max_mutations=12)
    byte_variants = [variant for variant in result["variants"] if variant["field_name"] == "payload_bytes"]

    assert byte_variants
    assert any(isinstance(variant["fixture"]["payload_bytes"], dict) for variant in byte_variants)
    assert all(variant["fixture"]["payload_bytes"].get("type") == "bytes" for variant in byte_variants)


def test_fixture_mutation_limit_and_oversized_fixture_handling():
    limited = mutate_fixture(_schema(), _fixture(), max_mutations=1)
    oversized = mutate_fixture(_schema(), {"message_type": "x" * 128}, max_fixture_size=8)

    assert limited["mutation_count"] == 1
    assert "mutation limit reached" in limited["warnings"]
    assert oversized["status"] == "mutation_limited"
    assert oversized["ok"] is False


def test_no_private_identifiers_in_examples_or_output():
    output = repr(
        {
            "validation": validate_fixture(_schema(), _fixture()),
            "mutation": mutate_fixture(_schema(), _fixture(), max_mutations=3),
        }
    )

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
