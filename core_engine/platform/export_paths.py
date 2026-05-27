from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.platform.filesystem_safety import (
    FILESYSTEM_SAFETY_FLAGS,
    normalize_cross_platform_path,
)
from core_engine.platform.runtime_detection import build_platform_runtime_record
from core_engine.platform.windows_paths import build_windows_path_summary


EXPORT_PATH_RECORD_VERSION = 1

EXPORT_PATH_SAFETY_FLAGS = {
    **FILESYSTEM_SAFETY_FLAGS,
    "export_path_safety_only": True,
    "export_written": False,
    "archive_created": False,
    "external_delivery_enabled": False,
}


def build_cross_platform_path_summary(
    *,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    log_path: str | None = None,
    export_path: str | None = None,
    cache_path: str | None = None,
    database_path: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    platform_payload = platform_record or build_platform_runtime_record(platform_info=platform_info, generated_at=timestamp)
    platform_family = str(platform_payload.get("platform_family") or "unknown")
    if platform_family == "windows":
        windows = build_windows_path_summary(
            log_path=log_path,
            export_path=export_path,
            cache_path=cache_path,
            database_path=database_path,
            generated_at=timestamp,
        )
        paths = [
            _from_windows_path(row, platform_family=platform_family, generated_at=timestamp)
            for row in windows.get("paths") or []
            if isinstance(row, dict)
        ]
    else:
        paths = [
            normalize_cross_platform_path(log_path or "<portmap-log-dir>/portmap.log", platform_family=platform_family, path_kind="log", generated_at=timestamp),
            normalize_cross_platform_path(export_path or "<portmap-export-dir>/bundle.json", platform_family=platform_family, path_kind="export", generated_at=timestamp),
            normalize_cross_platform_path(cache_path or "<portmap-cache-dir>/runtime-cache", platform_family=platform_family, path_kind="cache", generated_at=timestamp),
            normalize_cross_platform_path(database_path or "<portmap-data-dir>/portmap.db", platform_family=platform_family, path_kind="database", generated_at=timestamp),
        ]
    summary = summarize_path_records(paths, platform_family=platform_family, generated_at=timestamp)
    dashboard = build_path_summary_dashboard_record(summary=summary, paths=paths, generated_at=timestamp)
    api = build_path_summary_api_response(summary=summary, platform_record=platform_payload, paths=paths, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "cross_platform_path_summary",
        "record_version": EXPORT_PATH_RECORD_VERSION,
        "path_summary_id": "path-summary-" + _digest({"generated_at": timestamp, "platform": platform_family, "paths": paths})[:16],
        "generated_at": timestamp,
        "platform": platform_payload,
        "paths": sorted(paths, key=lambda item: str(item.get("path_kind") or "")),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **EXPORT_PATH_SAFETY_FLAGS,
    }


def build_export_path_summary(
    *,
    platform_record: dict[str, Any] | None = None,
    export_path: str | None = None,
    create_archive: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    path_record = normalize_cross_platform_path(
        export_path or ("<windows-export-dir>\\bundle.zip" if platform_family == "windows" and create_archive else "<portmap-export-dir>/bundle.zip" if create_archive else "<portmap-export-dir>/bundle.json"),
        platform_family=platform_family,
        path_kind="export",
        generated_at=timestamp,
    )
    suffix = str(path_record.get("path") or "").lower().rsplit(".", 1)[-1]
    archive = suffix in {"zip", "gz", "tar"} or bool(create_archive)
    warnings = list(path_record.get("warnings") or [])
    if archive:
        warnings.append("archive_creation_requires_explicit_operator_path")
    return {
        "record_type": "export_path_summary",
        "record_version": EXPORT_PATH_RECORD_VERSION,
        "generated_at": timestamp,
        "status": "review_required" if warnings else "ok",
        "path": path_record,
        "create_archive_requested": bool(create_archive),
        "archive_output": archive,
        "warnings": sorted(set(warnings)),
        **EXPORT_PATH_SAFETY_FLAGS,
    }


def summarize_path_records(paths: list[dict[str, Any]], *, platform_family: str, generated_at: str | None = None) -> dict[str, Any]:
    warnings = sorted({warning for row in paths for warning in row.get("warnings") or []})
    return {
        "record_type": "cross_platform_path_rollup",
        "record_version": EXPORT_PATH_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": "review_required" if warnings else "ok",
        "platform_family": platform_family,
        "path_count": len(paths),
        "sanitized_path_count": sum(1 for row in paths if row.get("sanitized")),
        "private_path_count": sum(1 for row in paths if row.get("private_path_detected")),
        "warnings": warnings,
        **EXPORT_PATH_SAFETY_FLAGS,
    }


def build_path_summary_dashboard_record(
    *,
    summary: dict[str, Any],
    paths: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "path_summary_dashboard",
        "panel": "cross_platform_paths",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "path_count": int(summary.get("path_count") or 0),
            "sanitized_path_count": int(summary.get("sanitized_path_count") or 0),
            "private_path_count": int(summary.get("private_path_count") or 0),
        },
        "rows": [
            {
                "path_kind": row.get("path_kind"),
                "platform_family": row.get("platform_family"),
                "path": row.get("path"),
                "sanitized": row.get("sanitized"),
            }
            for row in sorted(paths, key=lambda item: str(item.get("path_kind") or ""))
        ],
        "recommended_review": str(summary.get("status") or "") != "ok",
        **EXPORT_PATH_SAFETY_FLAGS,
    }


def build_path_summary_api_response(
    *,
    summary: dict[str, Any],
    platform_record: dict[str, Any],
    paths: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "path_summary_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "platform": dict(platform_record),
        "paths": sorted([dict(row) for row in paths], key=lambda item: str(item.get("path_kind") or "")),
        "dashboard": dict(dashboard),
        **EXPORT_PATH_SAFETY_FLAGS,
    }


def deterministic_export_path_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _from_windows_path(row: dict[str, Any], *, platform_family: str, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "cross_platform_path_record",
        "record_version": EXPORT_PATH_RECORD_VERSION,
        "platform_family": platform_family,
        "path_kind": str(row.get("path_kind") or "unknown"),
        "path": str(row.get("path") or ""),
        "is_absolute": bool(row.get("is_absolute")),
        "sanitized": bool(row.get("sanitized")),
        "private_path_detected": bool(row.get("private_path_detected")),
        "warnings": list(row.get("warnings") or []),
        "generated_at": generated_at,
        **EXPORT_PATH_SAFETY_FLAGS,
    }


def _digest(payload: Any) -> str:
    return sha256(deterministic_export_path_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "EXPORT_PATH_SAFETY_FLAGS",
    "build_cross_platform_path_summary",
    "build_export_path_summary",
    "build_path_summary_api_response",
    "build_path_summary_dashboard_record",
    "deterministic_export_path_json",
    "summarize_path_records",
]
