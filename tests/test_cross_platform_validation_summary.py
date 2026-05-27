import json
import re

from core_engine.platform.operator_views import (
    build_cross_platform_validation_operator_view,
    deterministic_platform_operator_view_json,
)
from core_engine.platform.validation_summary import (
    build_cli_table_rows,
    build_cross_platform_validation_report,
    build_operator_recommendations,
    deterministic_validation_summary_json,
    export_validation_summary_json,
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
    re.compile(r"(?i)c:\\users\\"),
]


def test_validation_report_builds_all_default_platform_summaries():
    report = build_cross_platform_validation_report(generated_at=GENERATED_AT)

    assert report["record_type"] == "cross_platform_validation_report"
    assert report["summary"]["platform_count"] == 4
    assert [row["platform_family"] for row in report["platforms"]] == [
        "linux",
        "macos",
        "raspberry-pi-linux-arm",
        "windows",
    ]
    assert report["summary"]["status"] in {"degraded", "unknown", "supported"}
    assert report["service_installed"] is False
    assert report["firewall_rules_changed"] is False
    assert report["packet_capture_enabled"] is False
    assert report["admin_elevation_requested"] is False
    assert report["raw_payload_stored"] is False

    encoded = deterministic_validation_summary_json(report)
    assert encoded == deterministic_validation_summary_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_validation_report_accepts_component_overrides():
    platforms = [{"platform_family": "linux", "system": "Linux", "release": "linux-placeholder", "machine": "x86_64"}]
    report = build_cross_platform_validation_report(
        platform_inputs=platforms,
        runtime_reports={"linux": {"summary": {"status": "supported"}, "report_id": "runtime-report-placeholder"}},
        capture_readiness={"linux": {"summary": {"status": "supported"}, "report_id": "capture-report-placeholder"}},
        firewall_readiness={"linux": {"summary": {"status": "supported"}, "report_id": "firewall-report-placeholder"}},
        filesystem_safety={"linux": {"summary": {"status": "ok"}, "report_id": "filesystem-report-placeholder"}},
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["platform_count"] == 1
    assert report["summary"]["status"] == "supported"
    assert report["platforms"][0]["status"] == "supported"
    assert report["operator_recommendations"]["recommendation_count"] == 0


def test_operator_recommendations_include_non_supported_components():
    report = build_cross_platform_validation_report(
        platform_inputs=[{"platform_family": "windows", "system": "Windows", "release": "windows-placeholder", "machine": "AMD64"}],
        generated_at=GENERATED_AT,
    )
    recommendations = build_operator_recommendations(report["platforms"], generated_at=GENERATED_AT)

    assert recommendations["operator_review_required"] is True
    assert recommendations["recommendation_count"] >= 1
    assert {item["platform_family"] for item in recommendations["items"]} == {"windows"}
    assert all(item["raw_payload_stored"] is False for item in recommendations["items"])


def test_cli_table_and_json_outputs_are_stable():
    report = build_cross_platform_validation_report(generated_at=GENERATED_AT)
    rows = build_cli_table_rows(report)
    text = export_validation_summary_json(report)

    assert rows[0]["platform"] == "linux"
    assert rows[-1]["platform"] == "windows"
    assert set(rows[0]) == {"platform", "status", "runtime", "capture", "firewall", "filesystem", "windows", "review"}
    assert text == deterministic_validation_summary_json(json.loads(text))


def test_operator_view_is_dashboard_api_and_table_ready():
    report = build_cross_platform_validation_report(generated_at=GENERATED_AT)
    view = build_cross_platform_validation_operator_view(report, generated_at=GENERATED_AT)

    assert view["record_type"] == "cross_platform_validation_operator_view"
    assert view["dashboard_status"]["panel"] == "cross_platform_validation"
    assert view["api_status"]["record_type"] == "cross_platform_validation_api"
    assert view["table_status"]["record_type"] == "cross_platform_validation_table"
    assert view["table_status"]["row_count"] == 4
    assert view["empty_state"] is None
    assert view["service_started"] is False
    assert view["firewall_rules_changed"] is False
    assert view["capture_loop_started"] is False

    encoded = deterministic_platform_operator_view_json(view)
    assert encoded == deterministic_platform_operator_view_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_empty_operator_view_renders_cleanly():
    empty_report = {
        "record_type": "cross_platform_validation_report",
        "summary": {"status": "unknown", "platform_count": 0},
        "platforms": [],
        "operator_recommendations": {"items": [], "recommendation_count": 0},
    }
    view = build_cross_platform_validation_operator_view(empty_report, generated_at=GENERATED_AT)

    assert view["status"] == "unknown"
    assert view["empty_state"]["panel"] == "cross_platform_validation"
    assert view["dashboard_status"]["metrics"]["platform_count"] == 0
