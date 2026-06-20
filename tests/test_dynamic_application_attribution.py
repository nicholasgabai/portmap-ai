import json

import pytest

from core_engine.attribution import (
    ApplicationAttributionError,
    SignatureLearningError,
    build_application_attribution_report,
    build_behavioral_signature_record,
    build_probable_application_attributions,
    build_probabilistic_application_model,
    build_signature_learning_report,
    deterministic_application_attribution_json,
    deterministic_confidence_json,
    deterministic_probabilistic_application_model_json,
    deterministic_signature_json,
    score_application_attribution_confidence,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _observation(**overrides):
    base = {
        "observed_entity_reference": "session-redacted-001",
        "process_hint": "browser-client",
        "service_hint": "https",
        "protocol_hint": "tls",
        "destination_behavior_hint": "redacted_destination",
        "flow_behavior_hint": "recurring",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _signature(**overrides):
    base = {
        "signature_class": "process_service_pattern",
        "process_hint": "browser-client",
        "service_hint": "https",
        "protocol_hint": "tls",
        "destination_behavior_hint": "redacted_destination",
        "flow_behavior_hint": "recurring",
        "observation_count": 8,
        "stable_behavior": True,
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_probable_app_attribution_generation_and_candidate_ranking():
    signatures = [build_behavioral_signature_record(_signature(), generated_at=FIXED_TIME)]
    rows = build_probable_application_attributions(
        _observation(),
        signatures=signatures,
        generated_at=FIXED_TIME,
    )

    assert len(rows) >= 2
    assert rows[0]["candidate_app_class"] == "browser_or_web_client"
    assert rows[0]["candidate_service_class"] == "web_service"
    assert rows[0]["attribution_state"] in {"attributed", "probable"}
    assert rows[0]["confidence_score"] >= rows[-1]["confidence_score"]
    assert rows[0]["source_mode"] == "live"
    assert rows[0]["raw_payload_stored"] is False
    assert rows[0]["pcap_generated"] is False
    assert rows[0]["raw_dns_history_stored"] is False


def test_multiple_candidates_include_destination_and_recurring_signature_hints():
    report = build_application_attribution_report(
        [
            _observation(
                observed_entity_reference="session-redacted-002",
                service_hint="dns",
                protocol_hint="udp",
                destination_behavior_hint="resolver_behavior",
                flow_behavior_hint="recurring",
            )
        ],
        signature_observations=[_signature(signature_class="destination_pattern", service_hint="dns", protocol_hint="udp")],
        generated_at=FIXED_TIME,
    )
    classes = {row["candidate_app_class"] for row in report["attributions"]}

    assert "name_resolution_client" in classes
    assert "recurring_application_behavior" in classes
    assert report["summary"]["attribution_count"] >= 2
    assert report["dashboard_status"]["panel"] == "dynamic_application_attribution"
    assert report["api_status"]["summary"]["source_modes"] == ["live"]


def test_unknown_unattributed_live_observation_remains_unresolved():
    rows = build_probable_application_attributions(
        {
            "observed_entity_reference": "session-redacted-003",
            "process_hint": "",
            "service_hint": "",
            "protocol_hint": "",
            "destination_behavior_hint": "",
            "flow_behavior_hint": "",
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert len(rows) == 1
    assert rows[0]["candidate_app_class"] == "Unknown"
    assert rows[0]["candidate_service_class"] == "Unattributed"
    assert rows[0]["attribution_state"] == "unattributed"
    assert "dummy_app" not in deterministic_application_attribution_json(rows[0])
    assert "dummy_db" not in deterministic_application_attribution_json(rows[0])


def test_probabilistic_application_model_ranks_candidates_from_existing_metadata():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-nginx",
            "program": "nginx",
            "service_name": "https",
            "protocol": "tls",
            "port": 443,
            "status": "LISTEN",
            "score_factors": ["sensitive_port:443"],
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert record["record_type"] == "probabilistic_application_model"
    assert record["top_classification"] == "nginx"
    assert record["confidence"] > 0.0
    assert record["candidate_count"] >= 3
    assert {row["candidate"] for row in record["candidates"]} >= {"nginx", "https_service", "unknown_proxy"}
    assert record["evidence_count"] >= 5
    assert "port:443" in record["evidence_signals"]
    assert record["training_performed"] is False
    assert record["inference_executed"] is False
    assert record["automated_action"] is False
    assert record["raw_payload_stored"] is False
    assert record["pcap_generated"] is False


def test_probabilistic_application_model_is_deterministic_and_export_safe():
    observation = {
        "observed_entity_reference": "session-redacted-db",
        "program": "postgres",
        "service_name": "postgresql",
        "protocol": "tcp",
        "port": 5432,
        "payload_content": "must-not-export",
        "raw_packet": "ignored",
        "source_mode": "live",
    }
    first = build_probabilistic_application_model(observation, generated_at=FIXED_TIME)
    second = build_probabilistic_application_model(observation, generated_at=FIXED_TIME)
    serialized = deterministic_probabilistic_application_model_json(first)

    assert first == second
    assert first["top_classification"] == "postgresql"
    assert round(sum(float(row["probability"]) for row in first["candidates"]), 3) == 1.0
    assert "must-not-export" not in serialized
    assert "ignored" not in serialized
    assert '"training_performed":false' in serialized


def test_probabilistic_application_model_handles_unknown_metadata():
    record = build_probabilistic_application_model(
        {"observed_entity_reference": "session-redacted-unknown", "source_mode": "live"},
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == "unknown_application"
    assert record["confidence"] == 1.0
    assert record["candidate_count"] == 1
    assert record["evidence_count"] == 0


def test_dummy_labels_remain_fixture_or_simulated_only():
    fixture = build_probable_application_attributions(
        _observation(process_hint="dummy_app", service_hint="dummy_db", source_mode="fixture"),
        generated_at=FIXED_TIME,
    )[0]
    live = build_probable_application_attributions(
        _observation(process_hint="dummy_app", service_hint="dummy_db", protocol_hint="", destination_behavior_hint="", flow_behavior_hint="", source_mode="live"),
        generated_at=FIXED_TIME,
    )[0]

    assert fixture["candidate_app_class"] == "dummy_app"
    assert fixture["candidate_service_class"] == "dummy_db"
    assert fixture["source_mode"] == "fixture"
    assert live["candidate_app_class"] == "Unknown"
    assert live["candidate_service_class"] == "Unattributed"
    assert "dummy_app" not in deterministic_application_attribution_json(live)
    assert "dummy_db" not in deterministic_application_attribution_json(live)


def test_confidence_score_bounds_and_conflict_penalty_behavior():
    strong = score_application_attribution_confidence(
        process_confidence=1.0,
        service_confidence=1.0,
        protocol_confidence=1.0,
        destination_confidence=1.0,
        flow_confidence=1.0,
        recurrence_confidence=1.0,
    )
    penalized = score_application_attribution_confidence(
        process_confidence=1.0,
        service_confidence=1.0,
        protocol_confidence=1.0,
        destination_confidence=1.0,
        flow_confidence=1.0,
        recurrence_confidence=1.0,
        conflict_penalty=0.4,
    )

    assert strong == 1.0
    assert 0.0 <= penalized < strong <= 1.0
    breakdown_json = deterministic_confidence_json(
        {
            "confidence_score": penalized,
            "raw_payload_stored": False,
            "pcap_generated": False,
        }
    )
    assert '"pcap_generated":false' in breakdown_json


def test_recurring_signature_confidence_and_drift_detection():
    stable = build_behavioral_signature_record(_signature(), generated_at=FIXED_TIME)
    drifted = build_behavioral_signature_record(_signature(drift_detected=True), generated_at=FIXED_TIME)
    report = build_signature_learning_report([_signature(), _signature(drift_detected=True)], generated_at=FIXED_TIME)

    assert stable["signature_class"] == "process_service_pattern"
    assert stable["confidence_score"] > drifted["confidence_score"]
    assert drifted["drift_detected"] is True
    assert report["summary"]["signature_count"] == 2
    assert report["summary"]["drift_detected_count"] == 1
    assert deterministic_signature_json(stable) == json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)


def test_export_safe_serialization_has_no_payload_pcap_or_dns_history_storage():
    report = build_application_attribution_report(
        [_observation(payload_content="must-not-export", raw_packet="ignored", domain_summary="redacted only")],
        signature_observations=[_signature(domain_summary="redacted only")],
        generated_at=FIXED_TIME,
    )
    serialized = deterministic_application_attribution_json(report)

    assert "must-not-export" not in serialized
    assert "ignored" not in serialized
    assert '"raw_payload_stored":false' in serialized
    assert '"raw_packet_stored":false' in serialized
    assert '"pcap_generated":false' in serialized
    assert '"raw_dns_history_stored":false' in serialized
    assert '"hostname_stored":false' in serialized


def test_malformed_attribution_and_cross_platform_safe_records():
    with pytest.raises(ApplicationAttributionError):
        build_probable_application_attributions("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(ApplicationAttributionError):
        build_application_attribution_report(object(), generated_at=FIXED_TIME)
    with pytest.raises(SignatureLearningError):
        build_behavioral_signature_record("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(SignatureLearningError):
        build_signature_learning_report(object(), generated_at=FIXED_TIME)

    row = build_probable_application_attributions(
        _observation(
            observed_entity_reference="session-redacted-004",
            process_hint="remote-client",
            service_hint="rdp",
            protocol_hint="tcp",
            destination_behavior_hint="redacted_destination",
            source_mode="unknown",
        ),
        generated_at=FIXED_TIME,
    )[0]

    assert row["source_mode"] == "unknown"
    assert "real_hostname" not in deterministic_application_attribution_json(row)
