import json

import pytest

from core_engine.intelligence import (
    IOCRecordError,
    build_ioc_export_summary,
    build_ioc_inventory,
    build_ioc_record,
    deterministic_ioc_json,
    empty_ioc_inventory,
    match_ioc,
    match_iocs,
    normalize_ioc_value,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:05:00+00:00"
T3 = "2026-01-01T00:10:00+00:00"


def test_ioc_record_generation_hashes_and_redacts_values():
    record = build_ioc_record(
        "Example.TEST.",
        ioc_type="domain",
        source_category="dns",
        source_mode="live",
        confidence_score=0.82,
        first_seen=T1,
        last_seen=T2,
        tags=["review", "fixture"],
        metadata={"source_detail": "hostname/private-device"},
    )
    payload = record.to_dict()

    assert payload["record_type"] == "ioc_record"
    assert payload["ioc_type"] == "domain"
    assert payload["source_category"] == "dns"
    assert payload["source_mode"] == "live"
    assert payload["value_hash"]
    assert payload["value_preview"].startswith("domain:")
    assert "Example.TEST" not in payload["value_preview"]
    assert record.normalized_value == "example.test"
    assert payload["metadata"]["source_detail"].startswith("redacted-")
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert "malicious" not in payload
    assert "threat_verdict" not in payload


def test_ioc_normalization_is_deterministic_for_supported_types():
    one = build_ioc_record("HTTPS://Example.TEST/Path?A=1#frag", ioc_type="url", source_category="manual", first_seen=T1)
    two = build_ioc_record("https://example.test/Path?A=1", ioc_type="url", source_category="manual", first_seen=T1)
    process = build_ioc_record("  SSHD  ", ioc_type="process_name", source_category="process", first_seen=T1)
    digest = build_ioc_record("AA:BB:CC", ioc_type="certificate_fingerprint", source_category="tls", first_seen=T1)

    assert one.value_hash == two.value_hash
    assert normalize_ioc_value("Example.TEST.", "fqdn") == "example.test"
    assert process.normalized_value == "sshd"
    assert digest.normalized_value == "aabbcc"


def test_supported_ioc_and_source_types_normalize_unknown_values():
    ioc_types = [
        "ipv4",
        "ipv6",
        "domain",
        "fqdn",
        "url",
        "sha256",
        "md5",
        "process_name",
        "tls_sni",
        "certificate_fingerprint",
        "dns_pattern",
        "unknown",
    ]
    source_categories = ["dns", "flow", "socket", "process", "tls", "packet", "topology", "manual", "unknown"]

    for source in source_categories:
        record = build_ioc_record("example.test", ioc_type="domain", source_category=source, source_mode="fixture", first_seen=T1)
        assert record.to_dict()["source_category"] == source

    records = [build_ioc_record(_value_for_type(kind), ioc_type=kind, source_category="manual", first_seen=T1) for kind in ioc_types]
    assert {record.to_dict()["ioc_type"] for record in records} == set(ioc_types)

    unknown = build_ioc_record("value", ioc_type="bad-type", source_category="bad-source", source_mode="bad-mode", first_seen=T1)
    payload = unknown.to_dict()
    assert payload["ioc_type"] == "unknown"
    assert payload["source_category"] == "unknown"
    assert payload["source_mode"] == "unknown"


def test_ioc_inventory_deduplicates_merges_counts_and_bounds_records():
    duplicate_one = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="live", confidence_score=0.4, first_seen=T1, last_seen=T1, tags=["one"])
    duplicate_two = build_ioc_record("EXAMPLE.TEST.", ioc_type="domain", source_category="flow", source_mode="replay", confidence_score=0.9, first_seen=T2, last_seen=T3, tags=["two"])
    unique = build_ioc_record("sshd", ioc_type="process_name", source_category="process", source_mode="fixture", confidence_score=0.7, first_seen=T2, last_seen=T3)

    summary = build_ioc_inventory([duplicate_one, duplicate_two, unique], generated_at=T3, max_iocs=10).to_dict()

    assert summary["record_type"] == "ioc_inventory_summary"
    assert summary["ioc_count"] == 2
    assert summary["type_counts"] == {"domain": 1, "process_name": 1}
    assert summary["source_modes"] == ["fixture", "live", "replay"]
    assert summary["iocs"][0]["bounded"] is True
    merged_domain = [ioc for ioc in summary["iocs"] if ioc["ioc_type"] == "domain"][0]
    assert merged_domain["confidence_score"] == 0.9
    assert sorted(merged_domain["tags"]) == ["one", "two"]
    assert merged_domain["first_seen"] == T1
    assert merged_domain["last_seen"] == T3

    bounded = build_ioc_inventory(
        [build_ioc_record(f"value-{index}", ioc_type="unknown", source_category="manual", first_seen=T1) for index in range(8)],
        generated_at=T3,
        max_iocs=3,
    ).to_dict()
    assert bounded["ioc_count"] == 3
    assert bounded["max_iocs"] == 3
    assert bounded["bounded"] is True


def test_empty_inventory_behavior():
    empty = empty_ioc_inventory(generated_at=T1).to_dict()

    assert empty["ioc_count"] == 0
    assert empty["iocs"] == []
    assert empty["type_counts"] == {}
    assert empty["source_category_counts"] == {}
    assert empty["source_modes"] == ["unknown"]
    assert empty["export_safe"] is True


def test_exact_normalized_and_pattern_matching():
    domain = build_ioc_record("Example.TEST.", ioc_type="domain", source_category="dns", source_mode="live", confidence_score=0.8, first_seen=T1)
    pattern = build_ioc_record("*.example.test", ioc_type="dns_pattern", source_category="dns", source_mode="fixture", confidence_score=0.6, first_seen=T1)

    exact = match_ioc(domain, {"value": "example.test", "ioc_type": "domain", "candidate_reference": "candidate-redacted-dns", "source_mode": "live"}).to_dict()
    normalized = match_ioc(domain, {"value": "api.example.test", "ioc_type": "domain", "candidate_reference": "candidate-redacted-flow", "source_mode": "live"}).to_dict()
    wildcard = match_ioc(pattern, {"value": "api.example.test", "ioc_type": "dns_pattern", "candidate_reference": "candidate-redacted-pattern", "source_mode": "fixture"}).to_dict()
    miss = match_ioc(domain, {"value": "other.test", "ioc_type": "domain", "candidate_reference": "candidate-redacted-other"}).to_dict()

    assert exact["match_state"] == "matched"
    assert exact["match_type"] == "exact"
    assert normalized["match_state"] == "partial_match"
    assert wildcard["match_state"] == "pattern_match"
    assert miss["match_state"] == "not_matched"
    assert exact["preview_only"] is True
    assert exact["destructive_action"] is False


def test_invalid_and_malformed_input_handling():
    with pytest.raises(IOCRecordError):
        build_ioc_record("not-an-address", ioc_type="ipv4", first_seen=T1)
    with pytest.raises(IOCRecordError):
        build_ioc_record("", ioc_type="domain", first_seen=T1)

    record = build_ioc_record("example.test", ioc_type="domain", first_seen=T1)
    invalid = match_ioc(record, {"value": "", "ioc_type": "domain", "candidate_reference": "candidate-redacted-empty"}).to_dict()
    malformed = match_ioc(object(), {"value": "example.test"}, candidate_reference="candidate-redacted-invalid").to_dict()
    mixed = match_iocs([record, object()], [{"value": "example.test", "ioc_type": "domain"}, object()])

    assert invalid["match_state"] == "invalid"
    assert malformed["match_state"] == "invalid"
    assert len(mixed) == 2
    assert {row.to_dict()["match_state"] for row in mixed} == {"matched", "invalid"}


def test_ioc_export_summary_and_csv_rows_are_safe():
    record = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="live", confidence_score=0.8, first_seen=T1)
    inventory = build_ioc_inventory([record], generated_at=T2)
    matches = match_iocs([record], [{"value": "example.test", "ioc_type": "domain", "candidate_reference": "candidate-redacted-dns", "source_mode": "live"}])
    summary = build_ioc_export_summary(inventory, matches, generated_at=T3)
    payload = summary.to_dict()
    rows = summary.to_csv_rows()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["record_type"] == "ioc_export_summary"
    assert payload["inventory_summary"]["ioc_count"] == 1
    assert payload["match_summary"]["matched_count"] == 1
    assert payload["export_formats"] == ["json", "csv_rows"]
    assert rows[0]["row_type"] == "ioc"
    assert "example.test" not in encoded
    assert "private_identifier_exported" in encoded
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False


def test_serialization_contains_no_raw_private_identifiers_or_verdict_fields():
    record = build_ioc_record(
        "internal.example.test",
        ioc_type="fqdn",
        source_category="manual",
        source_mode="fixture",
        first_seen=T1,
        metadata={"operator_path": "/private/operator/path", "note": "hostname should be hidden"},
    )
    payload = deterministic_ioc_json(record)

    assert payload == json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert "internal.example.test" not in payload
    assert "/private/operator/path" not in payload
    assert "hostname should be hidden" not in payload
    assert "malicious" not in payload
    assert "threat_verdict" not in payload
    assert '"preview_only":true' in payload
    assert '"destructive_action":false' in payload
    assert '"remote_feed_loaded":false' in payload


def _value_for_type(kind: str) -> str:
    return {
        "ipv4": ".".join(["203", "0", "113", "10"]),
        "ipv6": "2001:db8::10",
        "domain": "example.test",
        "fqdn": "host.example.test.",
        "url": "https://example.test/path",
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "process_name": "sshd",
        "tls_sni": "example.test",
        "certificate_fingerprint": "aa:bb:cc",
        "dns_pattern": "*.example.test",
        "unknown": "unknown-value",
    }[kind]
