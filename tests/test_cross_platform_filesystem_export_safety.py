import json
import re

from core_engine.platform.export_paths import (
    build_cross_platform_path_summary,
    build_export_path_summary,
    deterministic_export_path_json,
)
from core_engine.platform.filesystem_safety import (
    build_filesystem_safety_report,
    build_private_file_warning_records,
    classify_runtime_artifact,
    deterministic_filesystem_safety_json,
    normalize_cross_platform_path,
    validate_artifact_exclusions,
    validate_public_doc_safety,
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
    re.compile(r"(?i)c:\\users\\"),
]


def _platform(system="Linux", machine="x86_64"):
    return build_platform_runtime_record(
        platform_info={
            "system": system,
            "release": "release-placeholder",
            "machine": machine,
            "python_version": "3.11.5",
        },
        is_admin=False,
        generated_at=GENERATED_AT,
    )


def _private_posix_path():
    return "/" + "Users/" + "account-placeholder" + "/project/runtime.log"


def test_cross_platform_path_normalization_redacts_private_paths():
    record = normalize_cross_platform_path(
        _private_posix_path(),
        platform_family="macos",
        path_kind="log",
        generated_at=GENERATED_AT,
    )

    assert record["path"] == "<portmap-log-dir>/runtime.log"
    assert record["sanitized"] is True
    assert record["private_path_detected"] is True
    assert record["path_deleted"] is False
    assert "private_or_absolute_path_redacted" in record["warnings"]
    encoded = deterministic_filesystem_safety_json(record)
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)


def test_path_summary_builds_log_export_cache_and_database_records():
    summary = build_cross_platform_path_summary(
        platform_record=_platform(),
        log_path="<portmap-log-dir>/portmap.log",
        export_path="<portmap-export-dir>/bundle.json",
        cache_path="<portmap-cache-dir>/runtime-cache",
        database_path="<portmap-data-dir>/portmap.db",
        generated_at=GENERATED_AT,
    )

    assert summary["record_type"] == "cross_platform_path_summary"
    assert summary["summary"]["path_count"] == 4
    assert summary["dashboard_status"]["panel"] == "cross_platform_paths"
    assert summary["api_status"]["record_type"] == "path_summary_api"
    assert summary["export_written"] is False
    assert summary["archive_created"] is False
    assert deterministic_export_path_json(summary) == deterministic_export_path_json(json.loads(deterministic_export_path_json(summary)))


def test_windows_path_summary_reuses_windows_safe_helpers():
    summary = build_cross_platform_path_summary(
        platform_record=_platform("Windows", "AMD64"),
        log_path="<windows-log-dir>\\portmap.log",
        export_path="<windows-export-dir>\\bundle.json",
        cache_path="<windows-cache-dir>",
        database_path="<windows-data-dir>\\portmap.db",
        generated_at=GENERATED_AT,
    )

    assert summary["summary"]["platform_family"] == "windows"
    assert {row["path_kind"] for row in summary["paths"]} >= {"log", "export", "cache", "database"}
    assert all(row["platform_family"] == "windows" for row in summary["paths"])


def test_export_path_summary_flags_archives_for_operator_review():
    summary = build_export_path_summary(
        platform_record=_platform(),
        export_path="<portmap-export-dir>/bundle.zip",
        create_archive=True,
        generated_at=GENERATED_AT,
    )

    assert summary["record_type"] == "export_path_summary"
    assert summary["status"] == "review_required"
    assert summary["archive_output"] is True
    assert summary["export_written"] is False
    assert summary["archive_created"] is False
    assert "archive_creation_requires_explicit_operator_path" in summary["warnings"]


def test_runtime_artifact_classification_and_exclusion_validation():
    rows = [
        "docs/real_device_validation.md",
        "logs/runtime.log",
        "screenshots/dashboard.png",
        "docs/cross_platform_filesystem_export_safety.md",
    ]
    validation = validate_artifact_exclusions(rows, generated_at=GENERATED_AT)
    private = classify_runtime_artifact("docs/real_device_validation.md", generated_at=GENERATED_AT)

    assert validation["status"] == "blocked"
    assert validation["blocked_count"] == 3
    assert validation["private_file_staged"] is True
    assert validation["runtime_artifact_staged"] is True
    assert private["is_private_file"] is True
    assert private["exclude_from_public_commit"] is True


def test_private_file_warning_records_are_explicit():
    warnings = build_private_file_warning_records(
        ["docs/real_device_validation.md", "docs/README.txt"],
        generated_at=GENERATED_AT,
    )

    assert warnings["status"] == "blocked"
    assert warnings["warning_count"] == 1
    assert warnings["private_file_staged"] is True
    assert warnings["warnings"][0]["warning"] == "private_validation_file_must_remain_unstaged"


def test_public_doc_safety_detects_private_patterns_without_echoing_values():
    private_doc = "Example private address " + "192" + ".168.1.10 should not be public."
    result = validate_public_doc_safety(
        [
            {"doc_ref": "docs/safe.md", "content": "Uses <placeholder-host> only."},
            {"doc_ref": "docs/private.md", "content": private_doc},
        ],
        generated_at=GENERATED_AT,
    )

    assert result["status"] == "blocked"
    assert result["blocked_count"] == 1
    assert result["public_doc_safe"] is False
    assert result["items"][1]["match_count"] == 1
    encoded = deterministic_filesystem_safety_json(result)
    assert "192" + ".168.1.10" not in encoded


def test_filesystem_safety_report_is_dashboard_and_api_ready():
    paths = build_cross_platform_path_summary(platform_record=_platform(), generated_at=GENERATED_AT)["paths"]
    report = build_filesystem_safety_report(
        platform_record=_platform(),
        path_records=paths,
        candidate_paths=["docs/real_device_validation.md", "build/package.zip", "docs/README.txt"],
        public_doc_records=[{"doc_ref": "docs/safe.md", "content": "All placeholders are sanitized."}],
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "cross_platform_filesystem_safety_report"
    assert report["summary"]["status"] == "blocked"
    assert report["summary"]["artifact_blocked_count"] == 2
    assert report["summary"]["private_warning_count"] == 1
    assert report["dashboard_status"]["panel"] == "cross_platform_filesystem_export_safety"
    assert report["api_status"]["record_type"] == "filesystem_safety_api"
    assert report["path_deleted"] is False
    assert report["file_deleted"] is False
    assert report["file_moved"] is False
    assert report["private_file_staged"] is True

    encoded = deterministic_filesystem_safety_json(report)
    assert encoded == deterministic_filesystem_safety_json(json.loads(encoded))
    assert not any(pattern.search(encoded) for pattern in PRIVATE_PATTERNS)
