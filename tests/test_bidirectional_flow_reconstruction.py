import json

import pytest

from core_engine.flows import (
    BidirectionalFlowReconstructionError,
    FlowSessionTrackingError,
    build_session_tracking_record,
    deterministic_bidirectional_flow_json,
    deterministic_session_tracking_json,
    infer_flow_direction,
    normalize_socket_observations,
    reconstruct_bidirectional_flows,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _observation(**overrides):
    base = {
        "local_endpoint_class": "local",
        "remote_endpoint_class": "public",
        "local_port": 443,
        "remote_port": 55000,
        "protocol": "tcp",
        "transport_state": "established",
        "process_attribution": "web-service",
        "service_attribution": "https",
        "source_mode": "live",
        "observed_timestamps": [FIXED_TIME],
    }
    base.update(overrides)
    return base


def test_inbound_outbound_and_loopback_direction_inference():
    inbound = build_session_tracking_record(_observation(), generated_at=FIXED_TIME)
    outbound = build_session_tracking_record(
        _observation(local_port=55000, remote_port=443, flow_direction="", service_attribution="https-client"),
        generated_at=FIXED_TIME,
    )
    loopback = build_session_tracking_record(
        _observation(local_endpoint_class="loopback", remote_endpoint_class="loopback", local_port=8080, remote_port=56000),
        generated_at=FIXED_TIME,
    )

    assert inbound["flow_direction"] == "inbound"
    assert outbound["flow_direction"] == "outbound"
    assert loopback["flow_direction"] == "local_loopback"
    assert infer_flow_direction(local_endpoint_class="unknown", remote_endpoint_class="unknown", local_port=None, remote_port=443) == "unknown_direction"
    assert inbound["raw_payload_stored"] is False
    assert inbound["packet_payload_inspected"] is False
    assert inbound["pcap_generated"] is False


def test_repeated_observation_normalization_preserves_source_mode_and_deduplicates():
    observations = [
        _observation(observed_timestamps=["2026-01-01T00:00:00+00:00"]),
        _observation(observed_timestamps=["2026-01-01T00:01:00+00:00"]),
        _observation(local_port=55000, remote_port=443, source_mode="fixture", service_attribution="https-client"),
    ]

    records = normalize_socket_observations(observations, generated_at=FIXED_TIME)

    assert len(records) == 2
    live = [row for row in records if row["source_mode"] == "live"][0]
    fixture = [row for row in records if row["source_mode"] == "fixture"][0]
    assert live["session_duration_preview"]["duration_seconds"] == 60
    assert fixture["flow_direction"] == "outbound"
    assert deterministic_session_tracking_json(live) == json.dumps(live, sort_keys=True, separators=(",", ":"), default=str)


def test_bidirectional_reconstruction_splits_transient_and_recurring_sessions():
    current = [
        _observation(local_port=443, remote_port=55000, observed_timestamps=["2026-01-01T00:00:00+00:00", "2026-01-01T00:02:00+00:00"]),
        _observation(local_port=55001, remote_port=22, service_attribution="ssh", process_attribution="terminal", session_state="transient", observed_timestamps=["2026-01-01T00:03:00+00:00"]),
    ]
    previous = [
        _observation(local_port=443, remote_port=55000, observed_timestamps=["2025-12-31T00:00:00+00:00"]),
        _observation(local_port=443, remote_port=55000, observed_timestamps=["2025-12-31T01:00:00+00:00"]),
    ]

    report = reconstruct_bidirectional_flows(current, previous_observations=previous, generated_at=FIXED_TIME)

    assert report["summary"]["session_count"] == 2
    assert report["summary"]["recurring_count"] == 1
    assert report["summary"]["transient_count"] == 1
    assert len(report["recurring_sessions"]) == 1
    assert len(report["transient_sessions"]) == 1
    recurring = report["recurring_sessions"][0]
    assert recurring["session_classification"] == "recurring"
    assert recurring["relationship_strength"] >= 0.7
    assert recurring["reconstruction_confidence"] >= 0.8
    assert report["raw_payload_stored"] is False
    assert report["pcap_generated"] is False
    assert report["deep_packet_inspection"] is False


def test_flow_relationships_include_dns_destination_correlations():
    report = reconstruct_bidirectional_flows(
        [_observation(service_attribution="https")],
        dns_correlations=[{"service_attribution": "https", "domain_summary": "example redacted", "confidence": 0.8}],
        generated_at=FIXED_TIME,
    )

    pair = report["flow_pairs"][0]
    relationship = report["flow_relationships"][0]

    assert pair["dns_destination_correlations"] == [{"domain_summary": "example redacted", "confidence": 0.8}]
    assert relationship["service_attribution"] == "https"
    assert relationship["relationship_strength"] >= 0.6
    assert report["dashboard_status"]["panel"] == "bidirectional_flow_reconstruction"
    assert report["api_status"]["flow_pairs"][0]["source_mode"] == "live"


def test_dormant_session_reports_drift_without_enforcement():
    report = reconstruct_bidirectional_flows(
        [
            _observation(
                transport_state="closed",
                session_state="dormant",
                observed_timestamps=[
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:02:00+00:00",
                    "2026-01-01T00:04:00+00:00",
                ],
            )
        ],
        generated_at=FIXED_TIME,
    )

    pair = report["flow_pairs"][0]
    assert pair["session_classification"] == "dormant"
    assert pair["drift_detected"] is True
    assert report["summary"]["drift_detected_count"] == 1
    assert report["automatic_changes"] is False
    assert report["advisory_only"] is True


def test_export_safe_serialization_has_no_payload_or_pcap_fields_enabled():
    report = reconstruct_bidirectional_flows([_observation(source_mode="replay")], generated_at=FIXED_TIME)
    serialized = deterministic_bidirectional_flow_json(report)

    assert report["summary"]["source_modes"] == ["replay"]
    assert "payload_content" not in serialized
    assert "credential" in serialized
    assert '"credential_material_stored":false' in serialized
    assert '"pcap_generated":false' in serialized
    assert '"packet_payload_inspected":false' in serialized


def test_malformed_observation_handling_and_validation_errors():
    report = reconstruct_bidirectional_flows(
        [
            {"local_endpoint_class": "local", "remote_endpoint_class": "public", "protocol": "tcp", "source_mode": "unknown"},
            "not-an-observation",
        ],
        generated_at=FIXED_TIME,
    )

    assert report["summary"]["session_count"] == 1
    assert report["summary"]["unknown_direction_count"] == 1
    assert report["api_status"]["status"] == "review_required"
    with pytest.raises(FlowSessionTrackingError):
        build_session_tracking_record("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(BidirectionalFlowReconstructionError):
        reconstruct_bidirectional_flows(object(), generated_at=FIXED_TIME)


def test_cross_platform_socket_style_records_normalize_without_host_identifiers():
    windows_like = _observation(
        local_endpoint_class="local",
        remote_endpoint_class="external",
        local_port="56000",
        remote_port="3389",
        protocol="TCP",
        transport_state="ESTABLISHED",
        process_attribution={"display_name": "remote-client"},
        service_attribution={"service_name": "rdp"},
        source_mode="live",
    )
    record = build_session_tracking_record(windows_like, generated_at=FIXED_TIME)

    assert record["flow_direction"] == "outbound"
    assert record["protocol"] == "tcp"
    assert record["transport_state"] == "established"
    assert record["process_attribution"] == "remote-client"
    assert record["service_attribution"] == "rdp"
    assert "hostname" not in deterministic_session_tracking_json(record)
