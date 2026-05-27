from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import PureWindowsPath
from typing import Any

from core_engine.platform.capabilities import PLATFORM_CAPABILITY_SAFETY_FLAGS


WINDOWS_PATH_SAFETY_FLAGS = {
    **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    "windows_only": True,
    "path_created": False,
    "path_modified": False,
    "path_deleted": False,
    "private_path_rendered": False,
}

WINDOWS_PATH_KINDS = frozenset({"log", "export", "cache", "data", "database", "unknown"})


def build_windows_path_summary(
    *,
    log_path: str | None = None,
    export_path: str | None = None,
    cache_path: str | None = None,
    data_path: str | None = None,
    database_path: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build sanitized Windows path summaries without touching the filesystem."""
    timestamp = generated_at or _now()
    paths = [
        normalize_windows_path(log_path or "<windows-log-dir>\\portmap.log", path_kind="log", generated_at=timestamp),
        normalize_windows_path(export_path or "<windows-export-dir>\\bundle.json", path_kind="export", generated_at=timestamp),
        normalize_windows_path(cache_path or "<windows-cache-dir>\\runtime-cache", path_kind="cache", generated_at=timestamp),
        normalize_windows_path(data_path or "<windows-data-dir>", path_kind="data", generated_at=timestamp),
        normalize_windows_path(database_path or "<windows-data-dir>\\portmap.db", path_kind="database", generated_at=timestamp),
    ]
    warnings = sorted({warning for row in paths for warning in row.get("warnings") or []})
    status = "degraded" if warnings else "supported"
    summary = {
        "record_type": "windows_path_summary_rollup",
        "record_version": 1,
        "generated_at": timestamp,
        "status": status,
        "path_count": len(paths),
        "sanitized_path_count": sum(1 for row in paths if row.get("sanitized")),
        "private_path_count": sum(1 for row in paths if row.get("private_path_detected")),
        "warnings": warnings,
        **WINDOWS_PATH_SAFETY_FLAGS,
    }
    dashboard = build_windows_path_dashboard_record(summary=summary, paths=paths, generated_at=timestamp)
    api = build_windows_path_api_response(summary=summary, paths=paths, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "windows_path_summary",
        "record_version": 1,
        "path_summary_id": "windows-paths-" + _digest({"generated_at": timestamp, "paths": paths})[:16],
        "generated_at": timestamp,
        "paths": sorted(paths, key=lambda item: str(item.get("path_kind") or "")),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **WINDOWS_PATH_SAFETY_FLAGS,
    }


def normalize_windows_path(path: str | None, *, path_kind: str = "unknown", generated_at: str | None = None) -> dict[str, Any]:
    """Return a sanitized Windows path record safe for public display."""
    timestamp = generated_at or _now()
    kind = path_kind if path_kind in WINDOWS_PATH_KINDS else "unknown"
    raw = str(path or "")
    private_detected = _looks_private(raw)
    placeholder = _placeholder_for_kind(kind)
    if not raw:
        rendered = placeholder
        sanitized = True
        warnings = ["path_missing_placeholder_used"]
    elif raw.startswith("<") and raw.endswith(">"):
        rendered = raw
        sanitized = True
        warnings = []
    elif raw.startswith("<") and ">" in raw:
        rendered = raw.replace("/", "\\")
        sanitized = True
        warnings = []
    elif private_detected or _is_absolute_windows_path(raw):
        rendered = _placeholder_with_filename(placeholder, raw)
        sanitized = True
        warnings = ["private_or_absolute_path_redacted"]
    else:
        rendered = raw.replace("/", "\\")
        sanitized = False
        warnings = ["relative_path_requires_operator_review"] if rendered.startswith("..") else []
    record = {
        "record_type": "windows_path_record",
        "record_version": 1,
        "path_kind": kind,
        "path": rendered,
        "is_absolute": _is_absolute_windows_path(raw),
        "sanitized": sanitized,
        "private_path_detected": private_detected,
        "warnings": sorted(set(warnings)),
        "generated_at": timestamp,
        **WINDOWS_PATH_SAFETY_FLAGS,
    }
    record["path_id"] = "windows-path-" + _digest(record)[:16]
    return record


def build_windows_path_dashboard_record(
    *,
    summary: dict[str, Any],
    paths: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "windows_path_dashboard",
        "panel": "windows_paths",
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
                "path": row.get("path"),
                "sanitized": row.get("sanitized"),
                "warning_count": len(row.get("warnings") or []),
            }
            for row in sorted(paths, key=lambda item: str(item.get("path_kind") or ""))
        ],
        "recommended_review": str(summary.get("status") or "") != "supported",
        **WINDOWS_PATH_SAFETY_FLAGS,
    }


def build_windows_path_api_response(
    *,
    summary: dict[str, Any],
    paths: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "windows_path_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "paths": sorted([dict(row) for row in paths], key=lambda item: str(item.get("path_kind") or "")),
        "dashboard": dict(dashboard),
        **WINDOWS_PATH_SAFETY_FLAGS,
    }


def deterministic_windows_path_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _placeholder_for_kind(path_kind: str) -> str:
    return {
        "log": "<windows-log-dir>\\portmap.log",
        "export": "<windows-export-dir>\\bundle.json",
        "cache": "<windows-cache-dir>",
        "data": "<windows-data-dir>",
        "database": "<windows-data-dir>\\portmap.db",
    }.get(path_kind, "<windows-path>")


def _placeholder_with_filename(placeholder: str, raw_path: str) -> str:
    name = PureWindowsPath(raw_path.replace("/", "\\")).name
    if not name or "." not in name:
        return placeholder
    base = placeholder.rsplit("\\", 1)[0] if "\\" in placeholder else placeholder
    return f"{base}\\{name}"


def _is_absolute_windows_path(path: str) -> bool:
    text = str(path or "")
    return bool(len(text) >= 3 and text[1] == ":" and text[2] in {"\\", "/"}) or text.startswith("\\\\")


def _looks_private(path: str) -> bool:
    lowered = str(path or "").lower().replace("/", "\\")
    private_markers = ("\\users\\", "\\documents and settings\\", "\\appdata\\", "\\desktop\\", "\\downloads\\")
    return any(marker in lowered for marker in private_markers) or lowered.startswith("\\\\")


def _digest(payload: Any) -> str:
    return sha256(deterministic_windows_path_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "WINDOWS_PATH_KINDS",
    "WINDOWS_PATH_SAFETY_FLAGS",
    "build_windows_path_api_response",
    "build_windows_path_dashboard_record",
    "build_windows_path_summary",
    "deterministic_windows_path_json",
    "normalize_windows_path",
]
