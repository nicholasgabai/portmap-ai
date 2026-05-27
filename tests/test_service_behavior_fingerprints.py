import re

import pytest

from core_engine.telemetry import (
    ServiceBehaviorFingerprintError,
    build_live_telemetry_operator_summary,
    build_service_behavior_fingerprint_report,
    deterministic_service_behavior_fingerprint_json,
)


GENERATED_AT = "2026-01-01T00:20:00+00:00"

PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


def _flow_observation(index: int, *, port: int = 443, service_name: str = "https", direction: str = "inbound"):
    return {
        "record_type": "enriched_flow_observation",
        "generated_at": f"2026-01-01T00:1{index}:00+00:00",
        "flow_ref": f"flow-{index}",
        "transport_protocol": "tcp",
        "last_seen": f"2026-01-01T00:1{index}:00+00:00",
        "direction": {"direction": direction},
        "service_port_hint": {
            "service_port": port,
            "service_name": service_name,
            "service_endpoint": "responder",
            "confidence": 0.9,
        },
        "source_refs": [f"fixture:flow:{index}"],
    }


def _service_attribution(index: int, *, port: int = 443, service_name: str = "https", process_name: str = "sample-server"):
    return {
        "record_type": "service_attribution_record",
        "generated_at": f"2026-01-01T00:1{index}:00+00:00",
        "flow_ref": f"flow-{index}",
        "service_name": service_name,
        "service_port": port,
        "transport_protocol": "tcp",
        "protocol_hint": "tls" if service_name == "https" else service_name,
        "process_attribution": {
            "status": "matched",
            "process_ref": f"process-{process_name}",
            "process_display": {"display_name": process_name},
            "confidence": 0.9,
        },
        "last_seen": f"2026-01-01T00:1{index}:00+00:00",
        "confidence": 0.9,
        "source_refs": [f"fixture:service:{index}"],
    }


def _stable_report(**kwargs):
    attributions = [_service_attribution(index) for index in range(4)]
    flows = [_flow_observation(index) for index in range(4)]
    return build_service_behavior_fingerprint_report(
        service_attributions=attributions,
        flow_observations=flows,
        dns_records=[{"query_name": "updates.example.test", "generated_at": GENERATED_AT}],
        runtime_platform="linux",
        interface_class="ethernet",
        generated_at=GENERATED_AT,
        **kwargs,
    )


def test_detects_recurring_stable_service_fingerprint_profile():
    report = _stable_report()
    profile = report["profiles"][0]

    assert report["record_type"] == "service_behavior_fingerprint_report"
    assert report["summary"]["fingerprint_count"] == 4
    assert report["profile_summary"]["stable_profile_count"] == 1
    assert profile["stable_service_profile"] is True
    assert profile["behavior_state"] == "stable"
    assert "stable_service_behavior" in profile["classification_labels"]
    assert profile["confidence"] >= 0.8
    assert report["raw_payload_stored"] is False
    assert report["credentials_stored"] is False
    assert report["full_dns_queries_stored"] is False
    assert report["firewall_changes"] is False


def test_detects_unusual_process_port_pairs_and_uncommon_bindings():
    report = build_service_behavior_fingerprint_report(
        service_attributions=[
            _service_attribution(1, port=22, service_name="ssh", process_name="web-service"),
            _service_attribution(2, port=443, service_name="https", process_name="ssh-shell"),
        ],
        flow_observations=[
            _flow_observation(1, port=22, service_name="ssh"),
            _flow_observation(2, port=443, service_name="https"),
        ],
        generated_at=GENERATED_AT,
    )
    labels = {label for row in report["profiles"] for label in row["classification_labels"]}

    assert "unusual_process_port_pair" in labels
    assert report["profile_summary"]["unusual_combination_count"] == 2
    assert report["dashboard_status"]["status"] == "review_required"


def test_tracks_dormant_service_return():
    first_report = _stable_report()
    previous_profile = dict(first_report["profiles"][0])
    previous_profile["dormant"] = True
    previous_profile["behavior_state"] = "dormant"
    second_report = _stable_report(previous_profiles=[previous_profile])
    profile = second_report["profiles"][0]

    assert profile["dormant_reappeared"] is True
    assert "dormant_service_returned" in profile["classification_labels"]
    assert second_report["profile_summary"]["dormant_reappeared_count"] == 1


def test_malformed_and_low_confidence_inputs_degrade_safely():
    report = build_service_behavior_fingerprint_report(
        service_attributions=[
            {
                "service_name": "unknown",
                "service_port": "not-a-port",
                "process_attribution": {"status": "permission_denied"},
                "confidence": 0.1,
            },
            "malformed-row",
        ],
        flow_observations=[],
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["fingerprint_count"] == 1
    assert report["profile_summary"]["low_confidence_count"] == 1
    assert report["profiles"][0]["low_confidence_warning"] is True
    assert report["privilege_escalation_attempted"] is False


def test_bounds_fingerprint_and_profile_retention():
    report = build_service_behavior_fingerprint_report(
        service_attributions=[
            _service_attribution(1, port=443, service_name="https", process_name="sample-server"),
            _service_attribution(2, port=22, service_name="ssh", process_name="ssh-daemon"),
            _service_attribution(3, port=53, service_name="dns", process_name="dns-service"),
        ],
        flow_observations=[],
        generated_at=GENERATED_AT,
        max_fingerprints=2,
        max_profiles=1,
    )

    assert len(report["fingerprints"]) == 2
    assert len(report["profiles"]) == 1
    assert report["dropped_fingerprint_count"] == 1
    assert all(row["bounded_retention_applied"] is True for row in report["fingerprints"])
    assert report["profiles"][0]["bounded_retention_applied"] is True


def test_operator_summary_and_export_serialization_are_safe_and_deterministic():
    report = _stable_report()
    operator = build_live_telemetry_operator_summary(service_fingerprint_report=report, generated_at=GENERATED_AT)
    report_json = deterministic_service_behavior_fingerprint_json(report)

    assert operator["panels"]["service_fingerprints"]["metrics"]["profile_count"] == report["profile_summary"]["profile_count"]
    assert operator["summary"]["service_fingerprint_count"] == report["profile_summary"]["profile_count"]
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert report_json == deterministic_service_behavior_fingerprint_json(report)
    assert "updates.example.test" not in report_json
    assert '"raw_payload_stored":false' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)


def test_rejects_invalid_fingerprint_bounds():
    with pytest.raises(ServiceBehaviorFingerprintError):
        _stable_report(max_fingerprints=0)
