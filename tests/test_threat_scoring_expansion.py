import json

from core_engine.intelligence import (
    analyze_domain_pattern,
    build_advisory_threat_score,
    build_ai_correlation_summary,
    build_dns_analytics,
    build_ioc_inventory,
    build_ioc_record,
    build_scoring_weight_profile,
    build_signature_record,
    default_scoring_weight_profile,
    match_ioc,
    match_signature,
    normalize_weight_values,
    scoring_state_from_score,
    severity_from_score,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:05:00+00:00"


def _threat_inputs():
    ioc = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="fixture", first_seen=T1)
    inventory = build_ioc_inventory([ioc], generated_at=T1)
    ioc_match = match_ioc(ioc, {"value": "example.test", "ioc_type": "domain", "candidate_reference": "candidate-one"})
    patterns = analyze_domain_pattern({"domain": "review-target.zip", "source_mode": "fixture", "timestamp": T1}, generated_at=T1)
    dns = build_dns_analytics(
        [{"domain": "example.test", "source_mode": "fixture", "timestamp": T1}],
        ioc_inventory=inventory,
        domain_patterns=patterns,
        generated_at=T2,
    )
    signature = build_signature_record(
        signature_name="ioc-dns",
        signature_type="ioc_match",
        match_conditions={"match_state": "matched"},
        severity_level="high",
        confidence_score=0.9,
        source_mode="fixture",
    )
    signature_match = match_signature(signature, {"ioc_matches": [ioc_match]})
    correlation = build_ai_correlation_summary(
        ioc_inventories=[inventory],
        ioc_matches=[ioc_match],
        dns_analytics=[dns],
        dns_patterns=patterns,
        signature_matches=[signature_match],
        generated_at=T2,
    )
    return inventory, ioc_match, dns, patterns, signature_match, correlation


def test_default_weight_profile_generation_and_export_safety():
    profile = default_scoring_weight_profile()
    payload = profile.to_dict()

    assert payload["record_type"] == "scoring_weight_profile"
    assert payload["profile_name"] == "default_advisory"
    assert payload["enabled"] is True
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert 0.0 <= payload["ioc_weight"] <= 1.0
    assert 0.0 <= payload["confidence_floor"] <= payload["confidence_ceiling"] <= 1.0


def test_weight_normalization_and_bounds():
    normalized = normalize_weight_values({"ioc_weight": 3.0, "dns_weight": -2.0, "signature_weight": 0.5})
    profile = build_scoring_weight_profile(
        profile_name="bounds",
        ioc_weight=3.0,
        dns_weight=-2.0,
        signature_weight=0.5,
        confidence_floor=0.8,
        confidence_ceiling=0.2,
    ).to_dict()

    assert normalized["ioc_weight"] == 1.0
    assert normalized["dns_weight"] == 0.0
    assert normalized["signature_weight"] == 0.5
    assert profile["confidence_floor"] == 0.2
    assert profile["confidence_ceiling"] == 0.8


def test_scoring_from_ioc_dns_signature_and_correlation_inputs():
    inventory, ioc_match, dns, patterns, signature_match, correlation = _threat_inputs()
    score = build_advisory_threat_score(
        ioc_inventories=[inventory],
        ioc_matches=[ioc_match],
        dns_analytics=[dns],
        dns_patterns=patterns,
        signature_matches=[signature_match],
        ai_correlations=[correlation],
    )
    payload = score.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["record_type"] == "advisory_threat_scoring_record"
    assert payload["scoring_state"] in {"elevated", "high"}
    assert payload["advisory_score"] > 0.4
    assert payload["supporting_ioc_references"]
    assert payload["supporting_dns_references"]
    assert payload["supporting_signature_references"]
    assert payload["supporting_correlation_references"]
    assert "ioc" in payload["score_breakdown"]
    assert "dns" in payload["score_breakdown"]
    assert "signature" in payload["score_breakdown"]
    assert "correlation" in payload["score_breakdown"]
    assert "example.test" not in encoded
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded


def test_scoring_from_flow_attribution_drift_and_topology_inputs():
    score = build_advisory_threat_score(
        flow_summaries=[
            {"record_type": "flow_summary", "flow_reference": "flow-one", "risk_score": 0.7, "confidence_score": 0.8, "source_mode": "live"}
        ],
        attribution_summaries=[
            {"record_type": "application_attribution", "attribution_id": "attr-one", "confidence_score": 0.6, "severity_level": "medium", "source_mode": "live"}
        ],
        drift_records=[
            {"record_type": "drift_record", "drift_id": "drift-one", "drift_score": 0.65, "confidence_score": 0.7, "source_mode": "live"}
        ],
        topology_summaries=[
            {"record_type": "topology_relationship", "relationship_reference": "topology-one", "risk_score": 0.55, "confidence_score": 0.75, "source_mode": "live"}
        ],
    ).to_dict()

    assert score["scoring_state"] in {"moderate", "elevated"}
    assert score["supporting_flow_references"] == ["flow-one"]
    assert score["supporting_attribution_references"] == ["attr-one"]
    assert score["supporting_drift_references"] == ["drift-one"]
    assert score["supporting_topology_references"] == ["topology-one"]
    assert score["source_modes"] == ["live"]


def test_scoring_from_runtime_remediation_and_guardrail_inputs():
    score = build_advisory_threat_score(
        runtime_health_summaries=[
            {"record_type": "runtime_health", "runtime_id": "runtime-one", "health_state": "degraded", "confidence_score": 0.7, "source_mode": "fixture"}
        ],
        remediation_recommendations=[
            {"record_type": "remediation_recommendation", "recommendation_id": "rec-one", "risk_score": 0.5, "confidence_score": 0.7, "source_mode": "fixture"}
        ],
        guardrail_records=[
            {"record_type": "guardrail_record", "guardrail_id": "guard-one", "guardrail_state": "blocked", "confidence_score": 0.8, "source_mode": "fixture"}
        ],
    ).to_dict()

    assert score["supporting_runtime_references"] == ["runtime-one"]
    assert score["supporting_remediation_references"] == ["rec-one"]
    assert score["supporting_guardrail_references"] == ["guard-one"]
    assert score["score_breakdown"]["guardrail"]["category_score"] >= 0.75


def test_confidence_aggregation_and_severity_state_mapping():
    profile = build_scoring_weight_profile(confidence_floor=0.3, confidence_ceiling=0.6)
    score = build_advisory_threat_score(
        weight_profile=profile,
        flow_summaries=[{"flow_reference": "flow-one", "risk_score": 0.9, "confidence_score": 0.95}],
    ).to_dict()

    assert score["confidence_score"] == 0.6
    assert scoring_state_from_score(0.1) == "low"
    assert scoring_state_from_score(0.3) == "moderate"
    assert scoring_state_from_score(0.6) == "elevated"
    assert scoring_state_from_score(0.8) == "high"
    assert severity_from_score(0.9) == "critical"


def test_empty_and_degraded_behavior():
    empty = build_advisory_threat_score().to_dict()
    degraded = build_advisory_threat_score(flow_summaries=[object()]).to_dict()

    assert empty["scoring_state"] == "empty"
    assert empty["advisory_score"] == 0.0
    assert degraded["scoring_state"] == "degraded"
    assert degraded["recommended_next_step"] == "collect_more_metadata"


def test_explanation_points_safety_and_bounds():
    score = build_advisory_threat_score(
        flow_summaries=[{"flow_reference": "flow-one", "risk_score": 2.0, "confidence_score": -1.0, "source_mode": "replay"}]
    ).to_dict()
    encoded = json.dumps(score, sort_keys=True)

    assert 0.0 <= score["advisory_score"] <= 1.0
    assert 0.0 <= score["confidence_score"] <= 1.0
    assert score["explanation_points"]
    assert score["preview_only"] is True
    assert score["destructive_action"] is False
    assert score["external_lookup_performed"] is False
    assert score["raw_payload_stored"] is False
    assert score["raw_dns_history_stored"] is False
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded
