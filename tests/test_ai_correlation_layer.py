import json

from core_engine.intelligence import (
    analyze_domain_pattern,
    build_ai_correlation_summary,
    build_dns_analytics,
    build_evidence_chain,
    build_ioc_inventory,
    build_ioc_record,
    build_signature_record,
    degraded_evidence_chain,
    empty_ai_correlation_summary,
    match_ioc,
    match_signature,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:05:00+00:00"


def _ioc_dns_signature_fixture():
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
        confidence_score=0.9,
        source_mode="fixture",
    )
    signature_match = match_signature(signature, {"ioc_matches": [ioc_match]})
    return inventory, ioc_match, dns, patterns, signature_match


def test_evidence_chain_generation_for_ioc_dns_signature():
    inventory, ioc_match, dns, patterns, signature_match = _ioc_dns_signature_fixture()
    chain = build_evidence_chain(
        chain_type="ioc_dns_signature",
        evidence_items=[inventory, ioc_match, dns, patterns[0], signature_match],
        explanation_summary="local IOC DNS and signature signals correlate",
    )
    payload = chain.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["record_type"] == "evidence_chain_record"
    assert payload["chain_type"] == "ioc_dns_signature"
    assert payload["chain_state"] == "correlated"
    assert payload["related_ioc_references"]
    assert payload["related_dns_references"]
    assert payload["related_signature_references"]
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert "example.test" not in encoded
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded


def test_flow_attribution_drift_correlation():
    summary = build_ai_correlation_summary(
        flow_summaries=[
            {
                "record_type": "flow_summary",
                "flow_reference": "flow-one",
                "protocol": "tcp",
                "confidence_score": 0.7,
                "source_mode": "live",
                "severity_level": "medium",
            }
        ],
        attribution_summaries=[
            {
                "record_type": "application_attribution",
                "attribution_id": "attr-one",
                "attribution_state": "probable",
                "confidence_score": 0.8,
                "source_mode": "live",
            }
        ],
        drift_records=[
            {
                "record_type": "drift_record",
                "drift_id": "drift-one",
                "drift_severity": "moderate_drift",
                "confidence_score": 0.6,
                "source_mode": "live",
                "severity_level": "medium",
            }
        ],
        generated_at=T2,
    )
    chain = [row for row in summary.evidence_chains if row.chain_type == "flow_attribution_drift"][0].to_dict()

    assert chain["chain_state"] == "correlated"
    assert chain["related_flow_references"] == ["flow-one"]
    assert chain["related_attribution_references"] == ["attr-one"]
    assert chain["related_drift_references"] == ["drift-one"]
    assert "live" in summary.to_dict()["source_modes"]


def test_topology_policy_risk_correlation():
    summary = build_ai_correlation_summary(
        topology_summaries=[
            {
                "record_type": "topology_relationship",
                "relationship_reference": "topology-one",
                "relationship_state": "recurring",
                "confidence_score": 0.8,
                "source_mode": "fixture",
                "severity_level": "medium",
            }
        ],
        policy_evaluations=[
            {
                "record_type": "policy_evaluation",
                "policy_id": "policy-one",
                "matched": True,
                "confidence_score": 0.7,
                "source_mode": "fixture",
                "severity_level": "high",
            }
        ],
        risk_dashboard_summaries=[
            {
                "record_type": "risk_dashboard",
                "dashboard_id": "risk-one",
                "overall_risk_score": 0.75,
                "source_modes": ["fixture"],
                "highest_severity": "high",
            }
        ],
        generated_at=T2,
    )
    payload = summary.to_dict()
    chain = [row for row in summary.evidence_chains if row.chain_type == "topology_policy_risk"][0].to_dict()

    assert payload["correlation_state"] == "correlated"
    assert payload["risk_summary"]["risk_state"] == "review"
    assert chain["related_topology_references"] == ["topology-one"]
    assert chain["related_policy_references"] == ["policy-one"]


def test_remediation_guardrail_correlation():
    summary = build_ai_correlation_summary(
        remediation_recommendations=[
            {
                "record_type": "remediation_recommendation",
                "recommendation_id": "rec-one",
                "recommended_action": "review",
                "confidence_score": 0.7,
                "source_mode": "fixture",
            }
        ],
        guardrail_records=[
            {
                "record_type": "guardrail_record",
                "guardrail_id": "guard-one",
                "guardrail_state": "blocked",
                "confidence_score": 0.8,
                "source_mode": "fixture",
                "severity_level": "high",
            }
        ],
        generated_at=T2,
    )
    payload = summary.to_dict()
    chain = [row for row in summary.evidence_chains if row.chain_type == "remediation_guardrail"][0].to_dict()

    assert chain["chain_state"] == "partially_correlated"
    assert payload["recommendation_summary"]["recommendation_count"] == 1
    assert payload["recommendation_summary"]["guardrail_count"] == 1
    assert payload["recommendation_summary"]["blocked_count"] == 1


def test_composite_chain_behavior_and_aggregation():
    inventory, ioc_match, dns, patterns, signature_match = _ioc_dns_signature_fixture()
    summary = build_ai_correlation_summary(
        ioc_inventories=[inventory],
        ioc_matches=[ioc_match],
        dns_analytics=[dns],
        dns_patterns=patterns,
        signature_matches=[signature_match],
        flow_summaries=[{"record_type": "flow_summary", "flow_reference": "flow-one", "confidence_score": 0.7, "source_mode": "fixture"}],
        attribution_summaries=[{"record_type": "application_attribution", "attribution_id": "attr-one", "confidence_score": 0.7, "source_mode": "fixture"}],
        drift_records=[{"record_type": "drift_record", "drift_id": "drift-one", "confidence_score": 0.7, "source_mode": "fixture"}],
        generated_at=T2,
    )
    payload = summary.to_dict()
    chain_types = {chain.chain_type for chain in summary.evidence_chains}

    assert "ioc_dns_signature" in chain_types
    assert "flow_attribution_drift" in chain_types
    assert "composite" in chain_types
    assert payload["correlation_state"] == "correlated"
    assert payload["chain_count"] == 3
    assert 0.0 <= payload["confidence_score"] <= 1.0
    assert payload["highest_severity"] in {"medium", "high", "critical"}
    assert payload["evidence_chain_summary"]["type_counts"]["composite"] == 1


def test_empty_and_degraded_behavior():
    empty = empty_ai_correlation_summary(generated_at=T1).to_dict()
    degraded = build_ai_correlation_summary(flow_summaries=[object()], generated_at=T1).to_dict()
    explicit_degraded = build_ai_correlation_summary(evidence_chains=[degraded_evidence_chain(reason="bad input")], generated_at=T1).to_dict()

    assert empty["correlation_state"] == "empty"
    assert empty["chain_count"] == 0
    assert degraded["correlation_state"] == "degraded"
    assert explicit_degraded["correlation_state"] == "degraded"


def test_source_mode_preservation_and_export_safety():
    summary = build_ai_correlation_summary(
        flow_summaries=[
            {
                "record_type": "flow_summary",
                "flow_reference": "flow-redacted",
                "confidence_score": 0.6,
                "source_mode": "replay",
                "summary": "safe metadata only",
            }
        ],
        generated_at=T1,
    ).to_dict()
    encoded = json.dumps(summary, sort_keys=True)

    assert summary["source_modes"] == ["replay"]
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["external_lookup_performed"] is False
    assert summary["raw_payload_stored"] is False
    assert summary["raw_dns_history_stored"] is False
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded


def test_no_external_api_or_model_call_fields():
    summary = build_ai_correlation_summary(
        evidence_chains=[build_evidence_chain(chain_type="unknown", evidence_items=[])],
        generated_at=T1,
    ).to_dict()
    encoded = json.dumps(summary, sort_keys=True)

    assert summary["correlation_state"] == "empty"
    assert "external_model" not in encoded
    assert "api_call" not in encoded
    assert "network_request" not in encoded
    assert summary["enforcement_action_created"] is False
