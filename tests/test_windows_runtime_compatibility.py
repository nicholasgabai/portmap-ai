import json
import re

from core_engine.platform.windows_paths import (
    build_windows_path_summary,
    deterministic_windows_path_json,
    normalize_windows_path,
)
from core_engine.platform.windows_runtime import (
    build_windows_process_socket_visibility_summary,
    build_windows_runtime_compatibility_report,
    build_windows_runtime_profile_defaults,
    build_windows_service_mode_preview,
    deterministic_windows_runtime_json,
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


def test_windows_path_normalization_redacts_private_absolute_paths():
    private_path = "C:" + "\\Users\\" + "account-placeholder" + "\\AppData\\Local\\PortMap\\portmap.log"
    record = normalize_windows_path(
        private_path,
        path_kind="log",
        generated_at=GENERATED_AT,
    )

    assert record["path_kind"] == "log"
    assert record["path"] == "<windows-log-dir>\\portmap.log"
    assert record["sanitized"] is True
    assert record["private_path_detected"] is True
    assert record["path_created"] is False
    assert "private_or_absolute_path_redacted" in record["warnings"]
    encoded = deterministic_windows_path_json(record)
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_windows_path_summary_is_dashboard_and_api_ready():
    summary = build_windows_path_summary(
        log_path="<windows-log-dir>\\portmap.log",
        export_path="<windows-export-dir>\\bundle.json",
        cache_path="<windows-cache-dir>",
        generated_at=GENERATED_AT,
    )

    assert summary["record_type"] == "windows_path_summary"
    assert summary["summary"]["path_count"] == 5
    assert summary["dashboard_status"]["panel"] == "windows_paths"
    assert summary["api_status"]["record_type"] == "windows_path_api"
    assert summary["path_created"] is False
    assert summary["private_path_rendered"] is False
    assert not any(pattern.search(deterministic_windows_path_json(summary)) for pattern in PRIVATE_PATTERNS)


def test_windows_runtime_profile_defaults_are_dry_run_and_local_only():
    profile = build_windows_runtime_profile_defaults(generated_at=GENERATED_AT)

    assert profile["profile_id"] == "runtime-windows-preview"
    assert profile["runtime_mode"] == "dry-run"
    assert profile["api"]["bind_host"] == "127.0.0.1"
    assert profile["export"]["output_path"] == "<windows-export-dir>\\bundle.json"
    assert profile["storage"]["database_path"] == "<windows-data-dir>\\portmap.db"
    assert profile["raw_payload_stored"] is False
    assert profile["automatic_changes"] is False


def test_windows_process_socket_visibility_uses_safe_fallback():
    fallback = build_windows_process_socket_visibility_summary(generated_at=GENERATED_AT)
    supported = build_windows_process_socket_visibility_summary(
        process_service_attribution={
            "status": "ok",
            "report_id": "process-attribution-placeholder",
            "summary": {"attribution_count": 2, "socket_count": 2, "warnings": []},
        },
        generated_at=GENERATED_AT,
    )

    assert fallback["status"] == "degraded"
    assert fallback["fallback_behavior"]["permission_denied_safe"] is True
    assert fallback["fallback_behavior"]["command_line_args_exposed"] is False
    assert supported["status"] == "supported"
    assert supported["metrics"]["attribution_count"] == 2


def test_windows_service_mode_preview_never_installs_or_starts_services():
    preview = build_windows_service_mode_preview(
        service_mode={"summary": {"status": "ready"}},
        generated_at=GENERATED_AT,
    )

    assert preview["record_type"] == "windows_service_mode_preview"
    assert preview["status"] == "supported"
    assert preview["preview_commands"][0]["preview_only"] is True
    assert preview["windows_service_installed"] is False
    assert preview["windows_service_started"] is False
    assert preview["registry_keys_written"] is False


def test_windows_runtime_compatibility_report_is_sanitized_and_api_ready():
    report = build_windows_runtime_compatibility_report(
        platform_info={
            "system": "Windows",
            "release": "windows-release-placeholder",
            "machine": "AMD64",
            "python_version": "3.11.5",
        },
        is_admin=False,
        process_service_attribution={
            "status": "ok",
            "report_id": "process-attribution-placeholder",
            "summary": {"attribution_count": 1, "socket_count": 1, "warnings": []},
        },
        service_mode={"summary": {"status": "ready"}},
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "windows_runtime_compatibility_report"
    assert report["platform"]["platform_family"] == "windows"
    assert report["summary"]["status"] == "degraded"
    assert report["summary"]["component_statuses"]["platform"] == "supported"
    assert report["permissions"]["elevation_requested"] is False
    assert report["dashboard_status"]["panel"] == "windows_runtime_compatibility"
    assert report["api_status"]["record_type"] == "windows_runtime_api"
    assert report["windows_firewall_modified"] is False
    assert report["windows_service_installed"] is False
    assert report["npcap_assumed_installed"] is False
    assert report["raw_payload_stored"] is False

    encoded = deterministic_windows_runtime_json(report)
    assert encoded == deterministic_windows_runtime_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_non_windows_platform_reports_unavailable_fallback():
    report = build_windows_runtime_compatibility_report(
        platform_info={
            "system": "Darwin",
            "release": "macos-release-placeholder",
            "machine": "arm64",
            "python_version": "3.11.5",
        },
        is_admin=False,
        generated_at=GENERATED_AT,
    )

    assert report["platform"]["platform_family"] == "macos"
    assert report["summary"]["status"] == "unavailable"
    assert report["summary"]["component_statuses"]["platform"] == "unavailable"
