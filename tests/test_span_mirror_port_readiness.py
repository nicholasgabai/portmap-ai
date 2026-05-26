import re
import socket

import pytest

from core_engine.gateway import (
    SpanMirrorProfileError,
    SpanReadinessError,
    build_span_mirror_profile,
    build_span_readiness_report,
    deterministic_mirror_profile_json,
    deterministic_span_readiness_json,
)
from core_engine.telemetry import enumerate_local_interfaces


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


def _interfaces():
    return {
        "mirror0": [
            {
                "family": socket.AF_INET,
                "address": "203.0.113.10",
                "netmask": "255.255.255.0",
                "broadcast": "203.0.113.255",
            },
            {
                "family": socket.AF_INET6,
                "address": "2001:db8::10",
                "netmask": "",
                "broadcast": "",
            },
        ],
        "lo0": [
            {
                "family": socket.AF_INET,
                "address": "127.0.0.1",
                "netmask": "255.0.0.0",
                "broadcast": "",
            }
        ],
    }


def test_span_mirror_profile_builds_dry_run_readiness_record():
    profile = build_span_mirror_profile(
        profile_id="span-profile-test",
        interface_name="mirror0",
        expected_traffic_mbps=40,
        expected_packet_rate=4000,
        generated_at=GENERATED_AT,
    )

    assert profile["record_type"] == "span_mirror_profile"
    assert profile["profile_ref"].startswith("span-profile-")
    assert profile["passive_capture_required"] is True
    assert profile["promiscuous_mode_enabled"] is False
    assert profile["interface_mode_changed"] is False
    assert profile["capture_loop_started"] is False
    assert profile["switch_settings_modified"] is False
    assert profile["raw_payload_stored"] is False
    assert profile["passive_capture_requirements"]["capture_mode"] == "passive-metadata-only"
    assert profile["expected_traffic"]["status"] == "within_budget"
    assert profile["privilege_requirements"]["privilege_escalation_attempted"] is False


def test_span_readiness_report_summarizes_interface_resource_and_checklist():
    inventory = enumerate_local_interfaces(interfaces=_interfaces(), generated_at=GENERATED_AT)
    report = build_span_readiness_report(
        interface_inventory=inventory,
        interface_name="mirror0",
        expected_traffic_mbps=40,
        expected_packet_rate=4000,
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "span_readiness_report"
    assert report["summary"]["status"] == "review_required"
    assert report["summary"]["interface_name"] == "mirror0"
    assert report["interface_capability"]["status"] == "ok"
    assert report["resource_budget"]["status"] == "within_budget"
    assert report["packet_loss_risk"]["risk_level"] == "low"
    assert report["telemetry_scaling"]["recommended_update_interval_seconds"] == 5
    assert report["operator_checklist"]["review_count"] == 1
    assert report["operator_checklist"]["blocked_count"] == 0
    assert report["dashboard_status"]["panel"] == "span_mirror_readiness"
    assert report["api_status"]["summary"]["expected_packet_rate"] == 4000
    assert report["capture_plan"]["packets_captured"] == 0
    assert report["promiscuous_mode_enabled"] is False
    assert report["interface_mode_changed"] is False


def test_raspberry_pi_resource_awareness_reports_volume_warnings():
    inventory = enumerate_local_interfaces(interfaces=_interfaces(), generated_at=GENERATED_AT)
    report = build_span_readiness_report(
        interface_inventory=inventory,
        interface_name="mirror0",
        expected_traffic_mbps=100,
        expected_packet_rate=9000,
        edge_device=True,
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["edge_device"] is True
    assert report["resource_budget"]["status"] == "review_required"
    assert "expected_traffic_mbps_exceeds_budget" in report["resource_budget"]["warnings"]
    assert "expected_packet_rate_exceeds_budget" in report["resource_budget"]["warnings"]
    assert report["packet_loss_risk"]["risk_level"] == "high"
    assert report["telemetry_scaling"]["recommended_update_interval_seconds"] == 10
    assert report["summary"]["status"] == "review_required"


def test_loopback_and_missing_interface_are_reported_without_interface_changes():
    inventory = enumerate_local_interfaces(interfaces=_interfaces(), generated_at=GENERATED_AT)
    loopback_report = build_span_readiness_report(
        interface_inventory=inventory,
        interface_name="lo0",
        generated_at=GENERATED_AT,
    )
    missing_report = build_span_readiness_report(
        interface_inventory=inventory,
        interface_name="missing0",
        generated_at=GENERATED_AT,
    )

    assert "loopback_interface_not_suitable_for_span" in loopback_report["interface_capability"]["warnings"]
    assert loopback_report["summary"]["status"] == "review_required"
    assert "interface_not_found" in missing_report["interface_capability"]["warnings"]
    assert missing_report["summary"]["status"] == "unsafe"
    assert missing_report["operator_checklist"]["blocked_count"] == 1
    assert missing_report["capture_loop_started"] is False
    assert missing_report["interface_mode_changed"] is False


def test_span_readiness_input_validation_is_explicit():
    with pytest.raises(SpanMirrorProfileError):
        build_span_mirror_profile(interface_name="", generated_at=GENERATED_AT)

    with pytest.raises(SpanReadinessError):
        build_span_readiness_report(generated_at=GENERATED_AT)


def test_span_readiness_serialization_is_deterministic_and_private_safe():
    inventory = enumerate_local_interfaces(interfaces=_interfaces(), generated_at=GENERATED_AT)
    report = build_span_readiness_report(
        interface_inventory=inventory,
        interface_name="mirror0",
        expected_traffic_mbps=40,
        expected_packet_rate=4000,
        generated_at=GENERATED_AT,
    )
    profile_json = deterministic_mirror_profile_json(report["profile"])
    report_json = deterministic_span_readiness_json(report)

    assert profile_json == deterministic_mirror_profile_json(report["profile"])
    assert report_json == deterministic_span_readiness_json(report)
    assert '"raw_payload_stored":false' in report_json
    assert '"promiscuous_mode_enabled":false' in report_json
    assert '"interface_mode_changed":false' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(profile_json)
        assert not pattern.search(report_json)
