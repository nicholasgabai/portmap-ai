import json

from core_engine.intelligence import (
    analyze_domain_pattern,
    build_advisory_threat_score,
    build_ai_correlation_summary,
    build_dns_analytics,
    build_hunt_query,
    build_ioc_inventory,
    build_ioc_record,
    build_signature_record,
    deterministic_hunt_json,
    match_ioc,
    match_signature,
    max_results_from_filters,
    normalize_filters,
    normalize_query_type,
    run_threat_hunt,
    severity_meets_threshold,
    validate_query,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:05:00+00:00"


def _hunt_inputs():
    ioc = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="fixture", confidence_score=0.8, first_seen=T1)
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
    score = build_advisory_threat_score(
        ioc_inventories=[inventory],
        ioc_matches=[ioc_match],
        dns_analytics=[dns],
        dns_patterns=patterns,
        signature_matches=[signature_match],
        ai_correlations=[correlation],
    )
    timeline = {
        "record_type": "visual_timeline_window",
        "timeline_window_id": "timeline-one",
        "events": [
            {
                "record_type": "visual_timeline_event",
                "event_id": "event-one",
                "event_type": "policy_matched",
                "summary": "policy review event",
                "severity_level": "medium",
                "confidence_score": 0.7,
                "source_mode": "fixture",
            }
        ],
        "source_modes": ["fixture"],
    }
    topology = {
        "record_type": "visual_topology_graph",
        "topology_graph_id": "topology-one",
        "summary": "topology review graph",
        "risk_score": 0.55,
        "confidence_score": 0.75,
        "source_mode": "fixture",
    }
    fleet = {
        "record_type": "fleet_visibility_panel",
        "summary_id": "fleet-one",
        "summary": "fleet collector degraded",
        "risk_state": "elevated",
        "confidence_score": 0.7,
        "source_modes": ["fixture"],
    }
    risk = {
        "record_type": "visual_risk_dashboard_panel",
        "dashboard_id": "risk-one",
        "overall_risk_score": 0.7,
        "highest_severity": "high",
        "cards": [
            {
                "record_type": "visual_risk_card",
                "card_id": "risk-card-one",
                "card_type": "policy_risk",
                "summary": "risk card review",
                "severity_level": "high",
                "confidence_score": 0.8,
                "source_modes": ["fixture"],
            }
        ],
        "source_modes": ["fixture"],
    }
    return {
        "inventory": inventory,
        "ioc_match": ioc_match,
        "dns": dns,
        "patterns": patterns,
        "signature_match": signature_match,
        "correlation": correlation,
        "score": score,
        "timeline": timeline,
        "topology": topology,
        "fleet": fleet,
        "risk": risk,
    }


def test_query_creation_and_filter_validation():
    query = build_hunt_query(
        query_name="signature review",
        query_type="signature_search",
        filters=[
            {"field": "record_type", "operator": "equals", "value": "signature_match_record"},
            {"operator": "min_confidence", "value": 0.5},
            {"operator": "min_severity", "value": "medium"},
            {"operator": "source_mode", "value": "fixture"},
        ],
    )
    payload = query.to_dict()

    assert payload["record_type"] == "threat_hunt_query"
    assert payload["query_type"] == "signature_search"
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert validate_query(query) == []
    assert normalize_query_type("dns_search") == "dns_search"
    assert severity_meets_threshold("high", "medium") is True


def test_filter_normalization_and_bounded_limit():
    filters = normalize_filters({"source_mode": "fixture", "confidence_min": 0.4, "severity_min": "medium", "limit": 2})

    assert {"operator": "source_mode", "field": "source_mode", "value": "fixture"} in filters
    assert max_results_from_filters({"limit": 9999}) == 512
    assert max_results_from_filters({"limit": 2}) == 2


def test_ioc_dns_signature_correlation_and_scoring_searches():
    data = _hunt_inputs()

    ioc_hunt = run_threat_hunt(build_hunt_query(query_name="ioc", query_type="ioc_search"), ioc_inventories=[data["inventory"]], ioc_matches=[data["ioc_match"]]).to_dict()
    dns_hunt = run_threat_hunt(build_hunt_query(query_name="dns", query_type="dns_search"), dns_analytics=[data["dns"]], dns_patterns=data["patterns"]).to_dict()
    signature_hunt = run_threat_hunt(build_hunt_query(query_name="sig", query_type="signature_search"), signature_matches=[data["signature_match"]]).to_dict()
    correlation_hunt = run_threat_hunt(build_hunt_query(query_name="corr", query_type="correlation_search"), ai_correlations=[data["correlation"]]).to_dict()
    scoring_hunt = run_threat_hunt(build_hunt_query(query_name="score", query_type="scoring_search"), threat_scores=[data["score"]]).to_dict()

    assert ioc_hunt["hunt_state"] == "results_found"
    assert dns_hunt["hunt_state"] == "results_found"
    assert signature_hunt["hunt_state"] == "results_found"
    assert correlation_hunt["hunt_state"] == "results_found"
    assert scoring_hunt["hunt_state"] == "results_found"
    assert scoring_hunt["matched_records"][0]["source_scope"] == "scoring"


def test_equality_contains_confidence_severity_and_source_mode_filters():
    data = _hunt_inputs()
    query = build_hunt_query(
        query_name="filtered signature",
        query_type="signature_search",
        filters=[
            {"field": "record_type", "operator": "equals", "value": "signature_match_record"},
            {"field": "summary", "operator": "contains", "value": "IOC"},
            {"operator": "min_confidence", "value": 0.5},
            {"operator": "min_severity", "value": "medium"},
            {"operator": "source_mode", "value": "fixture"},
        ],
    )
    hunt = run_threat_hunt(query, signature_matches=[data["signature_match"]]).to_dict()

    assert hunt["hunt_state"] == "results_found"
    assert hunt["result_count"] == 1
    assert hunt["source_modes"] == ["fixture"]


def test_timeline_topology_fleet_and_risk_searches():
    data = _hunt_inputs()

    timeline_hunt = run_threat_hunt(build_hunt_query(query_name="timeline", query_type="timeline_search"), timeline_summaries=[data["timeline"]]).to_dict()
    topology_hunt = run_threat_hunt(build_hunt_query(query_name="topology", query_type="topology_search"), topology_summaries=[data["topology"]]).to_dict()
    fleet_hunt = run_threat_hunt(build_hunt_query(query_name="fleet", query_type="fleet_search"), fleet_summaries=[data["fleet"]]).to_dict()
    risk_hunt = run_threat_hunt(build_hunt_query(query_name="risk", query_type="composite_search", source_scopes=["risk"]), risk_dashboard_summaries=[data["risk"]]).to_dict()

    assert timeline_hunt["hunt_state"] == "results_found"
    assert topology_hunt["hunt_state"] == "results_found"
    assert fleet_hunt["hunt_state"] == "results_found"
    assert risk_hunt["hunt_state"] == "results_found"
    assert risk_hunt["matched_records"][0]["source_scope"] == "risk"


def test_composite_search_and_bounded_results():
    data = _hunt_inputs()
    hunt = run_threat_hunt(
        build_hunt_query(query_name="composite", query_type="composite_search", filters={"limit": 3}),
        ioc_inventories=[data["inventory"]],
        ioc_matches=[data["ioc_match"]],
        dns_analytics=[data["dns"]],
        dns_patterns=data["patterns"],
        signature_matches=[data["signature_match"]],
        ai_correlations=[data["correlation"]],
        threat_scores=[data["score"]],
        timeline_summaries=[data["timeline"]],
        topology_summaries=[data["topology"]],
        fleet_summaries=[data["fleet"]],
        risk_dashboard_summaries=[data["risk"]],
    ).to_dict()

    assert hunt["hunt_state"] == "results_found"
    assert hunt["result_count"] == 3
    assert hunt["confidence_summary"]["count"] == 3


def test_empty_degraded_invalid_and_no_results_behavior():
    empty = run_threat_hunt(build_hunt_query(query_name="empty", query_type="ioc_search")).to_dict()
    degraded = run_threat_hunt(build_hunt_query(query_name="degraded", query_type="ioc_search"), ioc_matches=[object()]).to_dict()
    invalid = run_threat_hunt({"query_name": "", "query_type": "bad", "filters": [{"operator": "bad"}]}).to_dict()
    no_results = run_threat_hunt(
        build_hunt_query(query_name="nomatch", query_type="scoring_search", filters=[{"field": "record_type", "operator": "equals", "value": "missing"}]),
        threat_scores=[_hunt_inputs()["score"]],
    ).to_dict()

    assert empty["hunt_state"] == "empty"
    assert degraded["hunt_state"] == "degraded"
    assert invalid["hunt_state"] == "invalid"
    assert no_results["hunt_state"] == "no_results"


def test_export_safe_serialization_and_no_verdict_fields():
    data = _hunt_inputs()
    hunt = run_threat_hunt(
        build_hunt_query(query_name="safe", query_type="composite_search"),
        ioc_inventories=[data["inventory"]],
        ioc_matches=[data["ioc_match"]],
        dns_analytics=[data["dns"]],
        threat_scores=[data["score"]],
    )
    payload = hunt.to_dict()
    encoded = deterministic_hunt_json(hunt)
    decoded = json.loads(encoded)

    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert payload["raw_payload_stored"] is False
    assert payload["raw_dns_history_stored"] is False
    assert decoded["record_type"] == "threat_hunt_result"
    assert "example.test" not in encoded
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded
