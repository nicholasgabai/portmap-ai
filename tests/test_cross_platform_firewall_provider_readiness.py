import json
import re

from core_engine.platform.firewall_providers import (
    build_firewall_provider_record,
    build_firewall_provider_summary,
    build_firewall_rule_preview,
    deterministic_firewall_provider_json,
)
from core_engine.platform.firewall_readiness import (
    build_cross_platform_firewall_readiness_report,
    build_firewall_permission_requirement_summary,
    deterministic_firewall_readiness_json,
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


def test_windows_provider_summary_uses_defender_preview_only():
    summary = build_firewall_provider_summary(platform_record=_platform("Windows", "AMD64"), generated_at=GENERATED_AT)

    assert [row["provider_name"] for row in summary["providers"]] == ["windows_defender_firewall"]
    provider = summary["providers"][0]
    assert provider["provider_label"] == "Windows Defender Firewall"
    assert provider["status"] == "degraded"
    assert provider["windows_defender_modified"] is False
    assert provider["rule_preview_only"] is True
    assert provider["admin_elevation_requested"] is False


def test_macos_provider_summary_uses_pf_preview_only():
    summary = build_firewall_provider_summary(platform_record=_platform("Darwin", "arm64"), generated_at=GENERATED_AT)

    assert [row["provider_name"] for row in summary["providers"]] == ["pf"]
    assert summary["providers"][0]["provider_label"] == "macOS pf"
    assert summary["providers"][0]["pf_modified"] is False
    assert "pf_preview_only" in summary["summary"]["warnings"]


def test_linux_and_raspberry_pi_provider_summaries_include_common_tools():
    linux = build_firewall_provider_summary(platform_record=_platform("Linux", "x86_64"), generated_at=GENERATED_AT)
    pi = build_firewall_provider_summary(platform_record=_platform("Linux", "aarch64"), generated_at=GENERATED_AT)

    assert [row["provider_name"] for row in linux["providers"]] == ["iptables", "nftables", "ufw"]
    assert [row["provider_name"] for row in pi["providers"]] == ["iptables", "nftables", "ufw"]
    iptables = [row for row in linux["providers"] if row["provider_name"] == "iptables"][0]
    assert iptables["registered_plugin_available"] is True
    assert "edge_device_resource_review_required" not in linux["summary"]["warnings"]
    assert "edge_device_resource_review_required" in pi["summary"]["warnings"]


def test_provider_record_accepts_supported_fixture_but_remains_preview_only():
    record = build_firewall_provider_record(
        provider_name="iptables",
        platform_family="linux",
        status="supported",
        generated_at=GENERATED_AT,
    )

    assert record["status"] == "supported"
    assert record["rule_applied"] is False
    assert record["firewall_rules_changed"] is False
    assert record["automatic_blocking"] is False
    assert "provider_still_preview_only" in record["warnings"]
    assert deterministic_firewall_provider_json(record) == deterministic_firewall_provider_json(json.loads(deterministic_firewall_provider_json(record)))


def test_rule_preview_is_dry_run_and_safety_gated():
    preview = build_firewall_rule_preview(
        provider_name="iptables",
        protocol="tcp",
        port="<service-port>",
        target_ref="<endpoint-ref>",
        generated_at=GENERATED_AT,
    )

    assert preview["record_type"] == "firewall_rule_preview"
    assert preview["command"]["dry_run"] is True
    assert preview["command"]["metadata"]["enforcement"] == "dry_run"
    assert preview["operator_review_required"] is True
    assert preview["rule_applied"] is False
    assert preview["firewall_rules_changed"] is False
    assert preview["preview_command"].startswith("<iptables-preview>")


def test_firewall_permission_summary_never_requests_elevation():
    permission = build_firewall_permission_requirement_summary(_platform("Linux", "x86_64", is_admin=False), generated_at=GENERATED_AT)

    assert permission["status"] == "degraded"
    assert permission["admin_or_root_required_for_future_rules"] is True
    assert permission["elevation_requested"] is False
    assert permission["admin_elevation_requested"] is False


def test_firewall_readiness_report_is_dashboard_and_api_ready():
    report = build_cross_platform_firewall_readiness_report(
        platform_record=_platform("Linux", "x86_64", is_admin=False),
        provider_statuses={"iptables": "supported"},
        runtime_health={"status": "ok", "summary": {"status": "ok"}},
        gateway_validation={"summary": {"status": "supported"}},
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "cross_platform_firewall_readiness_report"
    assert report["summary"]["platform_family"] == "linux"
    assert report["summary"]["provider_count"] == 3
    assert report["summary"]["rule_preview_count"] == 3
    assert report["dashboard_status"]["panel"] == "cross_platform_firewall_provider_readiness"
    assert report["api_status"]["record_type"] == "firewall_readiness_api"
    assert report["operator_review_required"] is True
    assert report["rules_applied_count"] == 0
    assert report["firewall_rules_changed"] is False
    assert report["automatic_blocking"] is False
    assert report["admin_elevation_requested"] is False

    encoded = deterministic_firewall_readiness_json(report)
    assert encoded == deterministic_firewall_readiness_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_unknown_platform_firewall_readiness_is_unknown_and_safe():
    report = build_cross_platform_firewall_readiness_report(
        platform_record=_platform("UnknownOS", "unknown"),
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["platform_family"] == "unknown"
    assert report["summary"]["status"] == "unknown"
    assert report["provider_readiness"]["summary"]["unknown_count"] == 1
    assert report["rules_applied_count"] == 0
    assert report["firewall_rules_changed"] is False
