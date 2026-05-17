import json
import re

from core_engine.diagnostics import (
    SchemaValidationError,
    build_validation_correlation_record,
    build_validation_event,
    build_validation_finding,
    build_validation_timeline_entry,
    classify_exception,
    mutate_fixture,
    summarize_mutation_result,
    summarize_validation_result,
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
    assert result["diagnostic_type"] == "schema_validation"
    assert result["record_version"] >= 2
    assert result["summary"]["classification"] == "valid"
    assert result["resource_bounds"]["max_fields"] == 64
    assert result["integration_hooks"]["event_pipeline_ready"] is True
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
    assert result["summary"]["mutation_count"] == 5
    assert result["integration_hooks"]["event_pipeline_ready"] is True
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


def test_validation_operational_integration_records():
    result = validate_fixture(_schema(), {"sequence": 120, "payload_hex": "not-hex"})
    summary = summarize_validation_result(result)
    event = build_validation_event(result, timestamp="sample-time")
    finding = build_validation_finding(result, source_ref="sample-source")
    timeline = build_validation_timeline_entry(result, timestamp="sample-time", source_ref="sample-source")
    correlation = build_validation_correlation_record(result, source_ref="sample-source")

    assert summary["recommended_review"] is True
    assert event["event_type"] == "policy_review_required"
    assert event["metadata"]["diagnostic_type"] == "schema_validation"
    assert finding["category"] == "diagnostic_validation"
    assert finding["recommended_review"] is True
    assert timeline["category"] == "diagnostic_validation"
    assert timeline["recommended_review"] is True
    assert correlation["correlation_key"].startswith("schema_validation:")
    assert correlation["raw_payload_stored"] is False


def test_mutation_summary_is_event_and_policy_ready():
    result = mutate_fixture(_schema(), _fixture(), max_mutations=6)
    summary = summarize_mutation_result(result)

    assert summary["mutation_count"] == 6
    assert summary["mutation_type_counts"]
    assert summary["validation_classification_counts"]
    assert result["integration_hooks"]["policy_review_ready"] == summary["recommended_review"]


def test_no_private_identifiers_in_examples_or_output():
    output = repr(
        {
            "validation": validate_fixture(_schema(), _fixture()),
            "mutation": mutate_fixture(_schema(), _fixture(), max_mutations=3),
        }
    )

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
