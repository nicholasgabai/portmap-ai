import json
import re

from core_engine.platform.capture_backends import (
    build_capture_backend_record,
    build_capture_backend_summary,
    deterministic_capture_backend_json,
)
from core_engine.platform.capture_readiness import (
    build_capture_permission_requirement_summary,
    build_cross_platform_capture_readiness_report,
    deterministic_capture_readiness_json,
)
from core_engine.platform.runtime_detection import build_platform_runtime_record


GENERATED_AT = "2026-01-01T00:00:00+00:00"

PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


def _interfaces():
    return {
        "eth-placeholder": [
            {
                "family": "AddressFamily.AF_INET",
                "address": "203.0.113.10",
                "netmask": "255.255.255.0",
                "broadcast": "203.0.113.255",
            }
        ],
        "lo-placeholder": [
            {
                "family": "AddressFamily.AF_INET",
                "address": "127.0.0.1",
                "netmask": "255.0.0.0",
                "broadcast": "",
            }
        ],
    }


def _platform(system, machine, *, is_admin=False):
    return build_platform_runtime_record(
        platform_info={
            "system": system,
            "release": "release-placeholder",
            "machine": machine,
            "python_version": "3.11.5",
        },
        is_admin=is_admin,
        generated_at=GENERATED_AT,
    )


def test_macos_backends_include_bpf_and_libpcap_without_capture():
    summary = build_capture_backend_summary(platform_record=_platform("Darwin", "arm64"), generated_at=GENERATED_AT)

    names = [row["backend_name"] for row in summary["backends"]]
    assert names == ["bpf", "libpcap"]
    assert summary["summary"]["degraded_count"] == 2
    assert summary["capture_loop_started"] is False
    assert summary["promiscuous_mode_enabled"] is False
    assert summary["raw_payload_stored"] is False


def test_linux_and_raspberry_pi_backend_summaries_are_distinct():
    linux = build_capture_backend_summary(platform_record=_platform("Linux", "x86_64"), generated_at=GENERATED_AT)
    pi = build_capture_backend_summary(platform_record=_platform("Linux", "aarch64"), generated_at=GENERATED_AT)

    assert [row["backend_name"] for row in linux["backends"]] == ["af_packet", "libpcap", "scapy"]
    assert [row["backend_name"] for row in pi["backends"]] == ["af_packet", "libpcap", "scapy"]
    assert "edge_device_resource_review_required" not in linux["summary"]["warnings"]
    assert "edge_device_resource_review_required" in pi["summary"]["warnings"]


def test_windows_backends_include_npcap_winpcap_and_scapy_without_assumptions():
    summary = build_capture_backend_summary(platform_record=_platform("Windows", "AMD64"), generated_at=GENERATED_AT)
    by_name = {row["backend_name"]: row for row in summary["backends"]}

    assert sorted(by_name) == ["npcap", "scapy", "winpcap"]
    assert by_name["npcap"]["status"] == "unknown"
    assert by_name["winpcap"]["status"] == "unavailable"
    assert by_name["npcap"]["install_assumed"] is False
    assert by_name["npcap"]["install_attempted"] is False
    assert summary["npcap_assumed_installed"] is False if "npcap_assumed_installed" in summary else True


def test_backend_record_accepts_supported_fixture_but_keeps_capture_disabled():
    record = build_capture_backend_record(
        backend_name="libpcap",
        platform_family="linux",
        status="supported",
        generated_at=GENERATED_AT,
    )

    assert record["status"] == "supported"
    assert record["capture_enabled"] is False
    assert record["provider_installed"] is False
    assert "capture_still_disabled" in record["warnings"]
    assert deterministic_capture_backend_json(record) == deterministic_capture_backend_json(json.loads(deterministic_capture_backend_json(record)))


def test_capture_permission_summary_never_requests_elevation():
    permission = build_capture_permission_requirement_summary(_platform("Linux", "x86_64", is_admin=False), generated_at=GENERATED_AT)

    assert permission["status"] == "degraded"
    assert permission["admin_or_root_required_for_future_capture"] is True
    assert permission["elevation_requested"] is False
    assert permission["admin_elevation_requested"] is False


def test_capture_readiness_report_is_dashboard_and_api_ready():
    report = build_cross_platform_capture_readiness_report(
        platform_record=_platform("Linux", "x86_64", is_admin=False),
        interfaces=_interfaces(),
        selected_interfaces=["eth-placeholder"],
        backend_statuses={"libpcap": "supported"},
        runtime_health={"status": "ok", "summary": {"status": "ok"}},
        gateway_validation={"summary": {"status": "supported"}},
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "cross_platform_capture_readiness_report"
    assert report["summary"]["platform_family"] == "linux"
    assert report["summary"]["selected_interface_count"] == 1
    assert report["dashboard_status"]["panel"] == "cross_platform_packet_capture_readiness"
    assert report["api_status"]["record_type"] == "capture_readiness_api"
    assert report["packet_payload_storage_prohibited"] is True
    assert report["capture_started"] is False
    assert report["capture_loop_started"] is False
    assert report["promiscuous_mode_enabled"] is False
    assert report["interface_mode_changed"] is False
    assert report["provider_install_attempted"] is False
    assert report["raw_payload_stored"] is False
    assert "packet_payload_storage_prohibited" in report["passive_capture_warnings"]["warnings"]

    encoded = deterministic_capture_readiness_json(report)
    assert encoded == deterministic_capture_readiness_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_unknown_platform_capture_readiness_is_unknown_and_safe():
    report = build_cross_platform_capture_readiness_report(
        platform_record=_platform("UnknownOS", "unknown"),
        interfaces={},
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["platform_family"] == "unknown"
    assert report["summary"]["status"] == "unknown"
    assert report["backend_readiness"]["summary"]["unknown_count"] == 1
    assert report["packets_captured"] == 0
    assert report["raw_payload_stored"] is False
