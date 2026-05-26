import json
import re

from core_engine.platform.capabilities import (
    build_capability_status_record,
    build_platform_capability_summary,
    deterministic_platform_capability_json,
)
from core_engine.platform.runtime_detection import (
    build_platform_runtime_record,
    build_runtime_compatibility_report,
    detect_platform_family,
    deterministic_runtime_detection_json,
)


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


def test_detect_platform_family_covers_supported_families():
    assert detect_platform_family(system="Darwin", machine="arm64") == "macos"
    assert detect_platform_family(system="Linux", machine="x86_64") == "linux"
    assert detect_platform_family(system="Linux", machine="aarch64") == "raspberry-pi-linux-arm"
    assert detect_platform_family(system="Linux", machine="x86_64", os_release="Raspbian placeholder") == "raspberry-pi-linux-arm"
    assert detect_platform_family(system="Windows", machine="AMD64") == "windows"
    assert detect_platform_family(system="Plan9", machine="mips") == "unknown"


def test_platform_runtime_record_is_deterministic_and_sanitized():
    record = build_platform_runtime_record(
        platform_info={
            "system": "Linux",
            "release": "6.1-placeholder",
            "machine": "aarch64",
            "python_version": "3.11.5",
        },
        is_admin=False,
        generated_at=GENERATED_AT,
    )

    assert record["record_type"] == "platform_runtime"
    assert record["platform_family"] == "raspberry-pi-linux-arm"
    assert record["architecture"]["is_arm"] is True
    assert record["python"]["supported"] is True
    assert record["permissions"]["elevated"] is False
    assert record["permissions"]["elevation_requested"] is False
    assert record["packet_capture_enabled"] is False
    assert record["firewall_rules_changed"] is False
    assert record["service_installed"] is False
    assert record["host_identifier_included"] is False

    encoded = deterministic_runtime_detection_json(record)
    assert encoded == deterministic_runtime_detection_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_platform_capability_summary_builds_placeholder_capabilities():
    platform_record = build_platform_runtime_record(
        platform_info={
            "system": "Windows",
            "release": "placeholder",
            "machine": "AMD64",
            "python_version": "3.11.5",
        },
        is_admin=True,
        generated_at=GENERATED_AT,
    )
    summary = build_platform_capability_summary(
        platform_record=platform_record,
        runtime_profile={
            "runtime_mode": "dry-run",
            "export": {"output_path": "<portmap-export-dir>\\bundle.json"},
        },
        telemetry_readiness={"summary": {"status": "review_required"}},
        generated_at=GENERATED_AT,
    )

    assert summary["record_type"] == "platform_capability_summary"
    assert summary["platform_family"] == "windows"
    assert summary["summary"]["capability_count"] == 4
    assert summary["dashboard_status"]["panel"] == "platform_capabilities"
    assert summary["api_status"]["record_type"] == "platform_capabilities_api"
    assert summary["raw_payload_stored"] is False
    assert summary["automatic_changes"] is False
    packet = [row for row in summary["capabilities"] if row["capability"] == "packet_capture"][0]
    assert "npcap" in packet["details"]["provider_placeholders"]
    assert packet["details"]["capture_enabled"] is False

    encoded = deterministic_platform_capability_json(summary)
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_runtime_compatibility_report_is_dashboard_and_api_ready():
    report = build_runtime_compatibility_report(
        platform_info={
            "system": "Darwin",
            "release": "23-placeholder",
            "machine": "arm64",
            "python_version": "3.11.5",
        },
        is_admin=False,
        runtime_profile={"runtime_mode": "dry-run", "export": {"output_path": "<portmap-export-dir>/bundle.json"}},
        runtime_health={"status": "ok", "summary": {"status": "ok"}},
        service_mode={"summary": {"status": "ready"}},
        gateway_validation={"summary": {"status": "supported"}},
        telemetry_readiness={"summary": {"status": "ready"}},
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "runtime_compatibility_report"
    assert report["platform"]["platform_family"] == "macos"
    assert report["summary"]["platform_family"] == "macos"
    assert report["dashboard_status"]["panel"] == "cross_platform_runtime_detection"
    assert report["api_status"]["record_type"] == "runtime_detection_api"
    assert report["raw_payload_stored"] is False
    assert report["packet_capture_enabled"] is False
    assert report["firewall_rules_changed"] is False
    assert report["service_started"] is False
    assert report["elevation_requested"] is False

    encoded = deterministic_runtime_detection_json(report)
    assert encoded == deterministic_runtime_detection_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_unknown_platform_reports_unknown_and_unavailable_states():
    report = build_runtime_compatibility_report(
        platform_info={
            "system": "UnknownOS",
            "release": "placeholder",
            "machine": "unknown",
            "python_version": "3.11.5",
        },
        is_admin=False,
        generated_at=GENERATED_AT,
    )

    assert report["platform"]["platform_family"] == "unknown"
    assert report["platform"]["status"] == "unavailable"
    assert report["summary"]["status"] == "unavailable"
    assert report["capabilities"]["summary"]["unknown_count"] == 4
    assert "platform_family_unknown" in report["summary"]["warnings"]


def test_capability_status_normalizes_invalid_status():
    record = build_capability_status_record(
        "custom_placeholder",
        "not-a-status",
        "Custom placeholder.",
        generated_at=GENERATED_AT,
    )

    assert record["status"] == "unknown"
    assert record["capability_id"].startswith("platform-capability-")
