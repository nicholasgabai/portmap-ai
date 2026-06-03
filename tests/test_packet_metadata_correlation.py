import json

import pytest

from core_engine.flows import (
    MetadataCorrelationError,
    ProcessCorrelationError,
    build_metadata_correlation_record,
    build_metadata_correlation_report,
    build_process_correlation_record,
    build_process_correlation_report,
    build_session_tracking_record,
    deterministic_metadata_correlation_json,
    deterministic_process_correlation_json,
    reconstruct_bidirectional_flows,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _observation(**overrides):
    base = {
        "local_endpoint_class": "local",
        "remote_endpoint_class": "public",
        "local_port": 55000,
        "remote_port": 443,
        "protocol": "tcp",
        "transport_state": "established",
        "process_attribution": "browser-client",
        "service_attribution": "https",
        "source_mode": "live",
        "observed_timestamps": [FIXED_TIME],
    }
    base.update(overrides)
    return base


def _packet(**overrides):
    base = {
        "packet_id": "packet-fixture-001",
        "source_mode": "live",
        "interface_ref": "interface-redacted",
        "protocol": "tcp",
        "local_endpoint_class": "local",
        "remote_endpoint_class": "public",
        "local_port": 55000,
        "remote_port": 443,
        "packet_size": 128,
    }
    base.update(overrides)
    return base


def _dns(**overrides):
    base = {
        "domain_ref": "domain-redacted-001",
        "domain_summary": "service redacted",
        "destination_class": "public",
        "resolver_class": "local_resolver",
        "correlation_state": "correlated",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _topology(**overrides):
    base = {
        "relationship_id": "relationship-redacted-001",
        "remote_endpoint_class": "public",
        "correlation_state": "correlated",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _session_and_flow():
    report = reconstruct_bidirectional_flows([_observation()], generated_at=FIXED_TIME)
    return report["normalized_sessions"][0], report["flow_pairs"][0]


def test_metadata_correlation_generation_connects_packet_socket_session_dns_protocol_and_topology():
    session, flow = _session_and_flow()
    record = build_metadata_correlation_record(
        packet_metadata=_packet(),
        socket_observation=_observation(),
        reconstructed_session=session,
        flow_pair=flow,
        dns_destination_behavior=_dns(),
        protocol_metadata={"protocol_hint": "tcp", "application_protocol": "https", "source_mode": "live"},
        topology_relationship=_topology(),
        generated_at=FIXED_TIME,
    )

    assert record["correlation_state"] == "correlated"
    assert record["session_reference"] == session["session_id"]
    assert record["flow_reference"] == flow["flow_pair_id"]
    assert record["protocol_hint"] == "https"
    assert record["destination_class"] == "public"
    assert record["dns_correlation_state"] == "correlated"
    assert record["topology_correlation_state"] == "correlated"
    assert record["metadata_confidence"] >= 0.9
    assert record["source_mode"] == "live"
    assert record["raw_payload_stored"] is False
    assert record["pcap_generated"] is False


def test_metadata_report_summarizes_partial_uncorrelated_and_drift_states():
    session, flow = _session_and_flow()
    partial = {"packet_metadata": _packet(packet_id="packet-fixture-002"), "session": session}
    full = {
        "packet": _packet(packet_id="packet-fixture-003"),
        "socket": _observation(),
        "session": session,
        "flow": {**flow, "drift_detected": True},
        "dns": _dns(),
        "protocol": {"protocol_hint": "tcp"},
        "topology": _topology(),
    }

    report = build_metadata_correlation_report([partial, full], generated_at=FIXED_TIME)

    assert report["summary"]["correlation_count"] == 2
    assert report["summary"]["correlated_count"] == 1
    assert report["summary"]["partially_correlated_count"] == 1
    assert report["summary"]["drift_detected_count"] == 1
    assert report["dashboard_status"]["panel"] == "packet_metadata_correlation"
    assert report["api_status"]["metadata_correlations"][0]["source_mode"] == "live"


def test_conflicting_protocol_and_topology_states_require_review():
    session, flow = _session_and_flow()
    record = build_metadata_correlation_record(
        packet_metadata=_packet(protocol="udp"),
        reconstructed_session=session,
        flow_pair=flow,
        topology_relationship=_topology(correlation_state="conflicting"),
        generated_at=FIXED_TIME,
    )

    assert record["correlation_state"] == "conflicting"
    assert record["conflict_reason"] in {"topology_relationship_conflict", "packet_session_protocol_conflict"}
    assert record["metadata_confidence"] == 0.1


def test_process_attribution_correlation_preserves_live_unknown_and_unattributed_labels():
    session = build_session_tracking_record(
        _observation(process_attribution="", service_attribution="", source_mode="live"),
        generated_at=FIXED_TIME,
    )
    record = build_process_correlation_record(session, generated_at=FIXED_TIME)

    assert record["attribution_state"] == "unattributed"
    assert record["process_attribution"] == "Unknown"
    assert record["service_attribution"] == "Unattributed"
    assert "dummy_app" not in deterministic_process_correlation_json(record)
    assert "dummy_db" not in deterministic_process_correlation_json(record)


def test_dummy_labels_are_allowed_for_fixture_or_simulated_mode_only():
    fixture_session = build_session_tracking_record(
        _observation(process_attribution="dummy_app", service_attribution="dummy_db", source_mode="fixture"),
        generated_at=FIXED_TIME,
    )
    live_session = build_session_tracking_record(
        _observation(process_attribution="dummy_app", service_attribution="dummy_db", source_mode="live"),
        generated_at=FIXED_TIME,
    )

    fixture_record = build_process_correlation_record(fixture_session, generated_at=FIXED_TIME)
    live_record = build_process_correlation_record(
        live_session,
        process_attribution={"display_name": "dummy_app", "source_mode": "live"},
        service_attribution={"service_name": "dummy_db", "source_mode": "live"},
        generated_at=FIXED_TIME,
    )

    assert fixture_record["process_attribution"] == "dummy_app"
    assert fixture_record["service_attribution"] == "dummy_db"
    assert fixture_record["attribution_state"] == "attributed"
    assert live_record["attribution_state"] == "conflicting"
    assert live_record["process_attribution"] == "Unknown"
    assert live_record["service_attribution"] == "Unattributed"
    assert "dummy_app" not in deterministic_process_correlation_json(live_record)
    assert "dummy_db" not in deterministic_process_correlation_json(live_record)


def test_process_correlation_report_and_export_serialization_are_deterministic():
    sessions = [
        build_session_tracking_record(_observation(), generated_at=FIXED_TIME),
        build_session_tracking_record(_observation(local_port=56000, remote_port=22, service_attribution="ssh"), generated_at=FIXED_TIME),
    ]

    report = build_process_correlation_report(sessions, generated_at=FIXED_TIME)
    serialized = deterministic_process_correlation_json(report)

    assert report["summary"]["correlation_count"] == 2
    assert report["summary"]["attributed_count"] == 2
    assert serialized == json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
    assert '"source_mode":"live"' in serialized


def test_payload_like_inputs_are_ignored_and_never_stored():
    session, flow = _session_and_flow()
    record = build_metadata_correlation_record(
        packet_metadata={**_packet(), "payload": "must-not-be-exported", "packet_bytes": b"abc"},
        reconstructed_session=session,
        flow_pair=flow,
        generated_at=FIXED_TIME,
    )
    serialized = deterministic_metadata_correlation_json(record)

    assert record["payload_fields_ignored"] == ["packet_bytes", "payload"]
    assert "must-not-be-exported" not in serialized
    assert '"raw_payload_stored":false' in serialized
    assert '"packet_payload_inspected":false' in serialized
    assert '"pcap_generated":false' in serialized


def test_malformed_metadata_handling_and_cross_platform_safe_records():
    with pytest.raises(MetadataCorrelationError):
        build_metadata_correlation_record(packet_metadata="not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(MetadataCorrelationError):
        build_metadata_correlation_report(object(), generated_at=FIXED_TIME)
    with pytest.raises(ProcessCorrelationError):
        build_process_correlation_record("not-an-object", generated_at=FIXED_TIME)

    session = build_session_tracking_record(
        _observation(
            local_endpoint_class="local",
            remote_endpoint_class="external",
            local_port="56000",
            remote_port="3389",
            protocol="TCP",
            process_attribution="remote-client",
            service_attribution="rdp",
            source_mode="live",
        ),
        generated_at=FIXED_TIME,
    )
    record = build_process_correlation_record(session, generated_at=FIXED_TIME)

    assert record["attribution_state"] == "attributed"
    assert "hostname" not in deterministic_process_correlation_json(record)
