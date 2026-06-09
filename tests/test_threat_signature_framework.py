import json

import pytest

from core_engine.intelligence import (
    SignatureRecordError,
    analyze_domain_pattern,
    build_ioc_record,
    build_signature_record,
    match_ioc,
    match_signature,
    match_signatures,
)


T1 = "2026-01-01T00:00:00+00:00"


def test_signature_record_generation_is_export_safe():
    signature = build_signature_record(
        signature_name="DNS review signature",
        signature_type="dns_pattern",
        severity_level="high",
        confidence_score=1.4,
        match_conditions={"pattern_type": "dns_tunneling_candidate", "pattern_state": "review_recommended"},
        tags=["dns", "review"],
        source_category="manual",
        source_mode="fixture",
    )
    payload = signature.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["record_type"] == "signature_record"
    assert payload["signature_type"] == "dns_pattern"
    assert payload["severity_level"] == "high"
    assert payload["confidence_score"] == 1.0
    assert payload["enabled"] is True
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded


def test_required_field_validation_and_unsafe_action_rejection():
    with pytest.raises(SignatureRecordError):
        build_signature_record(signature_name="", signature_type="ioc_match", match_conditions={"match_state": "matched"})
    with pytest.raises(SignatureRecordError):
        build_signature_record(signature_name="missing-conditions", signature_type="ioc_match", match_conditions={})
    with pytest.raises(SignatureRecordError):
        build_signature_record(
            signature_name="unsafe",
            signature_type="flow_behavior",
            match_conditions={"protocol": "tcp", "enforcement_mode": "block"},
        )


def test_disabled_signature_returns_not_matched():
    signature = build_signature_record(
        signature_name="disabled",
        signature_type="ioc_match",
        enabled=False,
        match_conditions={"match_state": "matched"},
    )
    result = match_signature(signature, {"ioc_matches": []}).to_dict()

    assert result["match_state"] == "not_matched"
    assert result["match_reason"] == "signature is disabled"
    assert result["preview_only"] is True
    assert result["destructive_action"] is False


def test_ioc_match_integration():
    ioc = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="fixture", first_seen=T1)
    match = match_ioc(
        ioc,
        {"value": "example.test", "ioc_type": "domain", "candidate_reference": "dns-candidate-one", "source_mode": "live"},
    )
    signature = build_signature_record(
        signature_name="ioc match",
        signature_type="ioc_match",
        severity_level="medium",
        confidence_score=0.8,
        match_conditions={"match_state": "matched"},
        source_mode="live",
    )
    result = match_signature(signature, {"ioc_matches": [match]}).to_dict()

    assert result["match_state"] == "matched"
    assert result["supporting_iocs"] == [ioc.ioc_id]
    assert result["confidence_score"] > 0
    assert result["source_mode"] == "live"


def test_dns_pattern_match_integration():
    pattern = [
        row
        for row in analyze_domain_pattern(
            {"domain": "q9x8z7v6b5n4m3p2r1s0q9x8z7v6b5n4m3p2r1s0.chunk.one.two.example.test", "query_type": "TXT"},
            generated_at=T1,
        )
        if row.pattern_type == "dns_tunneling_candidate"
    ][0]
    signature = build_signature_record(
        signature_name="dns pattern",
        signature_type="dns_pattern",
        severity_level="high",
        confidence_score=0.9,
        match_conditions={"pattern_type": "dns_tunneling_candidate", "pattern_state": "review_recommended"},
    )
    result = match_signature(signature, {"domain_patterns": [pattern]}).to_dict()

    assert result["match_state"] == "matched"
    assert result["supporting_dns_patterns"] == [pattern.pattern_id]
    assert result["severity_level"] == "high"


def test_flow_protocol_attribution_and_topology_matching():
    flow_sig = build_signature_record(
        signature_name="flow",
        signature_type="flow_behavior",
        match_conditions={"protocol": "tcp", "session_classification": "recurring"},
    )
    protocol_sig = build_signature_record(
        signature_name="protocol",
        signature_type="protocol_behavior",
        match_conditions={"protocol_hint": "tls", "protocol_state": "observed"},
    )
    attribution_sig = build_signature_record(
        signature_name="attribution",
        signature_type="application_attribution",
        match_conditions={"attribution_state": "probable", "candidate_service_class": "remote_access"},
    )
    topology_sig = build_signature_record(
        signature_name="topology",
        signature_type="topology_relationship",
        match_conditions={"relationship_state": "recurring", "relationship_type": "service_dependency"},
    )
    context = {
        "flows": [{"flow_reference": "flow-redacted-one", "protocol": "tcp", "session_classification": "recurring", "confidence_score": 0.7}],
        "protocols": [{"protocol_reference": "protocol-one", "protocol_hint": "tls", "protocol_state": "observed", "confidence_score": 0.6}],
        "attribution": [
            {
                "attribution_id": "attr-one",
                "attribution_state": "probable",
                "candidate_service_class": "remote_access",
                "confidence_score": 0.8,
            }
        ],
        "topology": [
            {
                "relationship_reference": "topology-one",
                "relationship_state": "recurring",
                "relationship_type": "service_dependency",
                "confidence_score": 0.9,
            }
        ],
    }

    assert match_signature(flow_sig, context).to_dict()["supporting_flows"] == ["flow-redacted-one"]
    assert match_signature(protocol_sig, context).to_dict()["supporting_protocols"] == ["protocol-one"]
    assert match_signature(attribution_sig, context).to_dict()["supporting_attribution"] == ["attr-one"]
    assert match_signature(topology_sig, context).to_dict()["supporting_topology"] == ["topology-one"]


def test_runtime_health_matching():
    signature = build_signature_record(
        signature_name="runtime health",
        signature_type="runtime_health",
        match_conditions={"health_state": "degraded"},
        severity_level="low",
    )
    result = match_signature(signature, {"runtime_health": {"id": "runtime-one", "health_state": "degraded", "confidence_score": 0.7}}).to_dict()

    assert result["match_state"] == "matched"
    assert result["matched_references"] == ["runtime-one"]


def test_composite_match_behavior():
    ioc = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="fixture", first_seen=T1)
    ioc_match = match_ioc(ioc, {"value": "example.test", "ioc_type": "domain", "candidate_reference": "candidate-one"})
    dns_pattern = [
        row
        for row in analyze_domain_pattern({"domain": "review-target.zip", "source_mode": "fixture"}, generated_at=T1)
        if row.pattern_type == "suspicious_tld"
    ][0]
    signature = build_signature_record(
        signature_name="composite",
        signature_type="composite",
        severity_level="high",
        confidence_score=0.9,
        match_conditions={"match_state": "matched", "pattern_type": "suspicious_tld", "min_signal_matches": 2},
    )
    result = match_signature(signature, {"ioc_matches": [ioc_match], "domain_patterns": [dns_pattern]}).to_dict()

    assert result["match_state"] == "matched"
    assert result["supporting_iocs"] == [ioc.ioc_id]
    assert result["supporting_dns_patterns"] == [dns_pattern.pattern_id]


def test_partial_not_matched_invalid_and_unknown_handling():
    partial = build_signature_record(
        signature_name="partial",
        signature_type="flow_behavior",
        match_conditions={"protocol": "udp", "min_count": 2},
    )
    miss = build_signature_record(
        signature_name="miss",
        signature_type="protocol_behavior",
        match_conditions={"protocol_hint": "ssh"},
    )
    unknown = build_signature_record(
        signature_name="unknown",
        signature_type="not-real",
        match_conditions={"field": "value"},
    )

    assert match_signature(partial, {"flows": [{"flow_reference": "flow-one", "protocol": "udp"}]}).to_dict()["match_state"] == "partial_match"
    assert match_signature(miss, {"protocols": [{"protocol_hint": "tls"}]}).to_dict()["match_state"] == "not_matched"
    assert match_signature(object(), {}).to_dict()["match_state"] == "invalid"
    assert match_signature(unknown, {}).to_dict()["match_state"] == "unknown"


def test_match_signatures_serialization_and_no_external_behavior():
    signature = build_signature_record(
        signature_name="flow",
        signature_type="flow_behavior",
        source_mode="fixture",
        match_conditions={"protocol": "tcp"},
    )
    rows = match_signatures([signature], {"flows": [{"flow_reference": "flow-one", "protocol": "tcp"}]})
    payload = rows[0].to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["match_state"] == "matched"
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert payload["raw_payload_stored"] is False
    assert payload["raw_dns_history_stored"] is False
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded
