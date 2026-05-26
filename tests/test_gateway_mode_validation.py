import re

from core_engine.gateway import (
    build_gateway_mode_validation_report,
    build_gateway_validation_operator_view,
    deterministic_gateway_operator_view_json,
    deterministic_gateway_validation_json,
    validate_router_log_ingestion,
    validate_span_readiness,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _flow_enrichment():
    return {
        "record_type": "flow_enrichment_report",
        "report_id": "flow-enrichment-placeholder",
        "summary": {
            "observation_count": 2,
            "malformed_flow_count": 0,
            "dropped_observation_count": 0,
        },
        "raw_payload_stored": False,
    }


def _process_service_attribution():
    return {
        "record_type": "process_service_attribution_report",
        "status": "ok",
        "summary": {"attribution_count": 1, "warnings": []},
        "raw_payload_stored": False,
    }


def _dns_visibility(encrypted_count=0):
    return {
        "record_type": "dns_visibility_report",
        "report_id": "dns-visibility-placeholder",
        "queries": [{"query_record_id": "dns-query-placeholder"}],
        "responses": [{"response_record_id": "dns-response-placeholder"}],
        "encrypted_dns_limitations": {"encrypted_flow_count": encrypted_count},
        "summary": {
            "query_count": 1,
            "response_count": 1,
            "anomaly_hint_count": 0,
        },
        "raw_payload_stored": False,
    }


def _router_logs(malformed_count=0):
    return {
        "record_type": "gateway_log_ingestion_report",
        "report_id": "gateway-log-report-placeholder",
        "records": [{"gateway_event_id": "gateway-event-placeholder"}],
        "summary": {
            "record_count": 1,
            "malformed_count": malformed_count,
            "deny_count": 0,
        },
        "raw_payload_stored": False,
    }


def _span(status="ready", blocked_count=0, review_count=0):
    return {
        "record_type": "span_readiness_report",
        "report_id": "span-readiness-report-placeholder",
        "summary": {
            "status": status,
            "check_count": 6,
            "review_count": review_count,
            "blocked_count": blocked_count,
            "warnings": [],
        },
        "promiscuous_mode_enabled": False,
        "interface_mode_changed": False,
    }


def _topology():
    return {
        "record_type": "live_topology",
        "topology_id": "live-topology-placeholder",
        "graph": {
            "node_count": 2,
            "edge_count": 1,
            "nodes": [{"asset_id": "node-placeholder-a"}, {"asset_id": "node-placeholder-b"}],
            "edges": [{"edge_id": "edge-placeholder"}],
        },
        "health_summary": {"status": "ok", "warnings": []},
        "raw_payload_stored": False,
    }


def _runtime_health():
    return {
        "record_type": "runtime_health_summary",
        "status": "ok",
        "summary": {"check_count": 7, "failed_count": 0},
    }


def _operator_visibility():
    return {
        "record_type": "operator_visibility_summary",
        "status": "ok",
        "panels": {"gateway": {"status": "ok"}},
    }


def test_gateway_validation_report_builds_supported_state_and_safety_fields():
    report = build_gateway_mode_validation_report(
        flow_enrichment=_flow_enrichment(),
        process_service_attribution=_process_service_attribution(),
        dns_visibility=_dns_visibility(),
        router_logs=_router_logs(),
        span_readiness=_span(),
        topology_correlation=_topology(),
        runtime_health=_runtime_health(),
        operator_visibility=_operator_visibility(),
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "gateway_mode_validation_report"
    assert report["summary"]["status"] == "supported"
    assert report["summary"]["supported_count"] == 8
    assert report["summary"]["unsafe_count"] == 0
    assert report["operator_safety_checklist"]["blocked_count"] == 0
    assert report["export_summary"]["export_ready"] is True
    assert report["bridge_mode_enabled"] is False
    assert report["promiscuous_mode_enabled"] is False
    assert report["router_settings_modified"] is False
    assert report["switch_settings_modified"] is False
    assert report["service_started"] is False
    assert report["automatic_blocking"] is False
    assert report["raw_payload_stored"] is False


def test_gateway_validation_degraded_and_unsafe_states_are_visible():
    degraded = build_gateway_mode_validation_report(
        flow_enrichment=_flow_enrichment(),
        process_service_attribution=_process_service_attribution(),
        dns_visibility=_dns_visibility(encrypted_count=2),
        router_logs=_router_logs(malformed_count=1),
        span_readiness=_span(status="review_required", review_count=1),
        topology_correlation=_topology(),
        runtime_health=_runtime_health(),
        operator_visibility=_operator_visibility(),
        generated_at=GENERATED_AT,
    )
    unsafe = build_gateway_mode_validation_report(
        flow_enrichment=_flow_enrichment(),
        span_readiness=_span(status="unsafe", blocked_count=1),
        generated_at=GENERATED_AT,
    )

    assert degraded["summary"]["status"] == "degraded"
    assert degraded["summary"]["degraded_count"] == 3
    assert "encrypted_dns_visibility_limited" in degraded["summary"]["warnings"]
    assert "malformed_gateway_logs_present" in degraded["summary"]["warnings"]
    assert unsafe["summary"]["status"] == "unsafe"
    assert unsafe["summary"]["unsafe_count"] == 1
    assert unsafe["operator_safety_checklist"]["blocked_count"] == 1


def test_component_validators_report_unavailable_and_specific_states():
    router_missing = validate_router_log_ingestion(None, generated_at=GENERATED_AT)
    span_unsafe = validate_span_readiness(_span(status="unsafe", blocked_count=1), generated_at=GENERATED_AT)

    assert router_missing["component"] == "router_log_ingestion"
    assert router_missing["state"] == "unavailable"
    assert span_unsafe["component"] == "span_readiness"
    assert span_unsafe["state"] == "unsafe"
    assert span_unsafe["metrics"]["blocked_count"] == 1


def test_gateway_operator_view_is_dashboard_and_api_ready():
    report = build_gateway_mode_validation_report(
        flow_enrichment=_flow_enrichment(),
        process_service_attribution=_process_service_attribution(),
        dns_visibility=_dns_visibility(),
        router_logs=_router_logs(),
        span_readiness=_span(),
        topology_correlation=_topology(),
        runtime_health=_runtime_health(),
        operator_visibility=_operator_visibility(),
        generated_at=GENERATED_AT,
    )
    view = build_gateway_validation_operator_view(report, generated_at=GENERATED_AT)

    assert view["record_type"] == "gateway_validation_operator_view"
    assert view["status"] == "supported"
    assert view["dashboard_status"]["panel"] == "gateway_mode_validation"
    assert view["dashboard_status"]["metrics"]["component_count"] == 8
    assert view["api_status"]["status"] == "supported"
    assert len(view["api_status"]["component_validations"]) == 8
    assert view["empty_state"] is None


def test_empty_gateway_operator_view_is_clean():
    view = build_gateway_validation_operator_view(None, generated_at=GENERATED_AT)

    assert view["status"] == "unavailable"
    assert view["empty_state"]["rows"] == []
    assert view["dashboard_status"]["metrics"]["component_count"] == 0
    assert view["api_status"]["component_validations"] == []


def test_gateway_validation_serialization_is_deterministic_and_private_safe():
    report = build_gateway_mode_validation_report(
        flow_enrichment=_flow_enrichment(),
        process_service_attribution=_process_service_attribution(),
        dns_visibility=_dns_visibility(),
        router_logs=_router_logs(),
        span_readiness=_span(),
        topology_correlation=_topology(),
        runtime_health=_runtime_health(),
        operator_visibility=_operator_visibility(),
        generated_at=GENERATED_AT,
    )
    view = build_gateway_validation_operator_view(report, generated_at=GENERATED_AT)
    report_json = deterministic_gateway_validation_json(report)
    view_json = deterministic_gateway_operator_view_json(view)

    assert report_json == deterministic_gateway_validation_json(report)
    assert view_json == deterministic_gateway_operator_view_json(view)
    assert '"bridge_mode_enabled":false' in report_json
    assert '"promiscuous_mode_enabled":false' in report_json
    assert '"automatic_blocking":false' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)
        assert not pattern.search(view_json)
