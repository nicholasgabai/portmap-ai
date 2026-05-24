import re
import socket

import pytest

from core_engine import platform_utils
from core_engine.telemetry import (
    PassiveCaptureSessionError,
    build_interface_resource_budget_summary,
    build_passive_capture_session_plan,
    deterministic_capture_plan_json,
    deterministic_interface_json,
    enumerate_local_interfaces,
    normalize_interface_metadata,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _fixture_interfaces():
    return {
        "en0": [
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
            },
            {
                "family": socket.AF_INET6,
                "address": "::1",
                "netmask": "",
                "broadcast": "",
            },
        ],
        "awdl0": [
            {
                "family": socket.AF_INET6,
                "address": "fe80::1",
                "netmask": "",
                "broadcast": "",
            }
        ],
    }


def test_interface_inventory_normalizes_metadata_without_capture():
    inventory = enumerate_local_interfaces(
        interfaces=_fixture_interfaces(),
        generated_at=GENERATED_AT,
    )

    assert inventory["record_type"] == "local_interface_inventory"
    assert inventory["summary"]["interface_count"] == 3
    assert inventory["summary"]["ipv4_interface_count"] == 2
    assert inventory["summary"]["ipv6_interface_count"] == 3
    assert inventory["summary"]["loopback_count"] == 1
    assert inventory["summary"]["broadcast_capable_count"] == 1
    assert inventory["capture_started"] is False
    assert inventory["packets_captured"] == 0
    assert inventory["raw_payload_stored"] is False
    assert inventory["privilege_escalation_attempted"] is False
    assert inventory["live_sniffing_loop_started"] is False
    assert inventory["dashboard_status"]["metrics"]["operator_selectable_count"] == 3
    assert inventory["api_status"]["count"] == 3


def test_interface_metadata_classifies_loopback_broadcast_and_link_local():
    en0 = normalize_interface_metadata("en0", _fixture_interfaces()["en0"], generated_at=GENERATED_AT)
    lo0 = normalize_interface_metadata("lo0", _fixture_interfaces()["lo0"], generated_at=GENERATED_AT)
    awdl0 = normalize_interface_metadata("awdl0", _fixture_interfaces()["awdl0"], generated_at=GENERATED_AT)

    assert en0["classification"] == "network"
    assert en0["broadcast_capable"] is True
    assert en0["multicast_capable"] is True
    assert en0["address_family_summary"]["by_family"] == {"ipv4": 1, "ipv6": 1}
    assert lo0["classification"] == "loopback"
    assert lo0["loopback"] is True
    assert awdl0["classification"] == "link_local"
    assert awdl0["link_local_only"] is True


def test_capture_session_plan_targets_operator_selected_interfaces():
    inventory = enumerate_local_interfaces(interfaces=_fixture_interfaces(), generated_at=GENERATED_AT)
    plan = build_passive_capture_session_plan(
        selected_interfaces=["en0"],
        interface_inventory=inventory,
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert plan["record_type"] == "passive_capture_session_plan"
    assert plan["selected_interfaces"] == ["en0"]
    assert plan["summary"]["selected_interface_count"] == 1
    assert plan["summary"]["capture_allowed_count"] == 1
    assert plan["duration_seconds"] == 0
    assert plan["max_packets"] == 0
    assert plan["summary"]["dry_run"] is True
    assert plan["summary"]["packets_captured"] == 0
    assert plan["capture_targets"][0]["passive_mode"] is True
    assert plan["capture_started"] is False
    assert plan["raw_payload_stored"] is False
    assert plan["privilege_escalation_attempted"] is False
    assert plan["live_sniffing_loop_started"] is False
    assert plan["dashboard_status"]["metrics"]["selected_interface_count"] == 1
    assert plan["api_status"]["status"] == "ok"


def test_capture_session_plan_defaults_to_first_selectable_interface(monkeypatch):
    monkeypatch.setattr(platform_utils, "network_interfaces", _fixture_interfaces)

    plan = build_passive_capture_session_plan(generated_at=GENERATED_AT)

    assert plan["selected_interfaces"] == ["awdl0"]
    assert plan["summary"]["selected_interface_count"] == 1
    assert plan["capture_started"] is False


def test_resource_budget_and_plan_validation_are_explicit():
    budget = build_interface_resource_budget_summary(
        interface_count=4,
        selected_interface_count=2,
        edge_device=True,
        generated_at=GENERATED_AT,
    )

    assert budget["status"] == "review_required"
    assert "selected_interface_count_exceeds_budget" in budget["warnings"]

    with pytest.raises(PassiveCaptureSessionError):
        build_passive_capture_session_plan(
            interfaces=_fixture_interfaces(),
            selected_interfaces=["en0"],
            duration_seconds=-1,
            generated_at=GENERATED_AT,
        )


def test_interface_and_capture_plan_serialization_is_deterministic_and_private_safe():
    inventory = enumerate_local_interfaces(interfaces=_fixture_interfaces(), generated_at=GENERATED_AT)
    plan = build_passive_capture_session_plan(
        selected_interfaces=["en0"],
        interface_inventory=inventory,
        generated_at="2026-01-01T00:01:00+00:00",
    )

    inventory_json = deterministic_interface_json(inventory)
    plan_json = deterministic_capture_plan_json(plan)

    assert inventory_json == deterministic_interface_json(inventory)
    assert plan_json == deterministic_capture_plan_json(plan)
    assert "203.0.113.10" in inventory_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(inventory_json)
        assert not pattern.search(plan_json)
