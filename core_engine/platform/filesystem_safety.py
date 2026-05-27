from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Iterable

from core_engine.export.bundle import SAFETY_FLAGS as EXPORT_SAFETY_FLAGS
from core_engine.platform.capabilities import PLATFORM_CAPABILITY_SAFETY_FLAGS
from core_engine.platform.runtime_detection import build_platform_runtime_record


FILESYSTEM_SAFETY_RECORD_VERSION = 1

FILESYSTEM_SAFETY_FLAGS = {
    **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    **EXPORT_SAFETY_FLAGS,
    "filesystem_safety_only": True,
    "path_created": False,
    "path_modified": False,
    "path_deleted": False,
    "file_deleted": False,
    "file_moved": False,
    "private_file_staged": False,
    "runtime_artifact_staged": False,
    "public_doc_safe": True,
}

ARTIFACT_EXTENSIONS = {
    ".db": "database",
    ".sqlite": "database",
    ".sqlite3": "database",
    ".log": "runtime_log",
    ".jsonl": "runtime_log",
    ".png": "screenshot",
    ".jpg": "screenshot",
    ".jpeg": "screenshot",
    ".gif": "screenshot",
    ".zip": "archive",
    ".tar": "archive",
    ".gz": "archive",
    ".env": "environment_file",
}

ARTIFACT_DIR_MARKERS = ("logs", "artifacts", "dist", "build", "__pycache__", ".pytest_cache")
PRIVATE_FILE_NAMES = {"real_device_validation.md"}

PRIVATE_PATTERNS = (
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
)


def build_filesystem_safety_report(
    *,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    path_records: Iterable[dict[str, Any]] | None = None,
    candidate_paths: Iterable[str] | None = None,
    public_doc_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a read-only filesystem/export safety report from supplied path candidates."""
    timestamp = generated_at or _now()
    platform_payload = platform_record or build_platform_runtime_record(platform_info=platform_info, generated_at=timestamp)
    platform_family = str(platform_payload.get("platform_family") or "unknown")
    paths = [dict(row) for row in path_records or [] if isinstance(row, dict)]
    artifact_validation = validate_artifact_exclusions(candidate_paths or [], generated_at=timestamp)
    private_warnings = build_private_file_warning_records(candidate_paths or [], generated_at=timestamp)
    public_docs = validate_public_doc_safety(public_doc_records or [], generated_at=timestamp)
    summary = summarize_filesystem_safety(
        platform_family=platform_family,
        paths=paths,
        artifact_validation=artifact_validation,
        private_warnings=private_warnings,
        public_docs=public_docs,
        generated_at=timestamp,
    )
    dashboard = build_filesystem_safety_dashboard_record(summary=summary, paths=paths, artifact_validation=artifact_validation, generated_at=timestamp)
    api = build_filesystem_safety_api_response(
        summary=summary,
        platform_record=platform_payload,
        paths=paths,
        artifact_validation=artifact_validation,
        private_warnings=private_warnings,
        public_docs=public_docs,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    return {
        "record_type": "cross_platform_filesystem_safety_report",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "report_id": "filesystem-safety-" + _digest({"generated_at": timestamp, "platform": platform_family, "summary": summary})[:16],
        "generated_at": timestamp,
        "platform": platform_payload,
        "paths": sorted(paths, key=lambda item: str(item.get("path_kind") or "")),
        "artifact_validation": artifact_validation,
        "private_file_warnings": private_warnings,
        "public_doc_safety": public_docs,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **FILESYSTEM_SAFETY_FLAGS,
        "runtime_artifact_staged": bool(summary.get("runtime_artifact_staged")),
        "private_file_staged": bool(summary.get("private_file_staged")),
        "public_doc_safe": bool(summary.get("public_doc_safe", True)),
    }


def normalize_cross_platform_path(
    path: str | None,
    *,
    platform_family: str = "unknown",
    path_kind: str = "unknown",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    raw = str(path or "")
    placeholder = _placeholder_for(platform_family, path_kind)
    private_detected = _looks_private(raw, platform_family=platform_family)
    absolute = _is_absolute(raw, platform_family=platform_family)
    if not raw:
        rendered = placeholder
        sanitized = True
        warnings = ["path_missing_placeholder_used"]
    elif raw.startswith("<") and ">" in raw:
        rendered = _normalize_separator(raw, platform_family=platform_family)
        sanitized = True
        warnings = []
    elif private_detected or absolute:
        rendered = _placeholder_with_name(placeholder, raw, platform_family=platform_family)
        sanitized = True
        warnings = ["private_or_absolute_path_redacted"]
    else:
        rendered = _normalize_separator(raw, platform_family=platform_family)
        sanitized = False
        warnings = ["relative_path_requires_operator_review"] if rendered.startswith("..") else []
    record = {
        "record_type": "cross_platform_path_record",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "platform_family": str(platform_family or "unknown"),
        "path_kind": str(path_kind or "unknown"),
        "path": rendered,
        "is_absolute": absolute,
        "sanitized": sanitized,
        "private_path_detected": private_detected,
        "warnings": sorted(set(warnings)),
        "generated_at": timestamp,
        **FILESYSTEM_SAFETY_FLAGS,
    }
    record["path_id"] = "filesystem-path-" + _digest(record)[:16]
    return record


def classify_runtime_artifact(path: str, *, generated_at: str | None = None) -> dict[str, Any]:
    text = str(path or "")
    lowered = text.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    artifact_type = ARTIFACT_EXTENSIONS.get(suffix, "")
    dir_hit = next((marker for marker in ARTIFACT_DIR_MARKERS if f"/{marker}/" in f"/{lowered}/" or lowered.endswith(f"/{marker}")), "")
    private = name in PRIVATE_FILE_NAMES or "real_device_validation.md" in lowered
    is_artifact = bool(artifact_type or dir_hit or private)
    classification = artifact_type or ("runtime_directory" if dir_hit else "private_validation" if private else "public_source")
    return {
        "record_type": "runtime_artifact_classification",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "path_ref": _safe_path_ref(text),
        "classification": classification,
        "artifact_type": artifact_type,
        "directory_marker": dir_hit,
        "is_runtime_artifact": is_artifact and not private,
        "is_private_file": private,
        "exclude_from_public_commit": bool(is_artifact or private),
        "warnings": _artifact_warnings(classification, private=private, is_artifact=is_artifact),
        **FILESYSTEM_SAFETY_FLAGS,
    }


def validate_artifact_exclusions(paths: Iterable[str], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [classify_runtime_artifact(path, generated_at=timestamp) for path in paths or []]
    blocked = [row for row in rows if row.get("exclude_from_public_commit")]
    return {
        "record_type": "artifact_exclusion_validation",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "generated_at": timestamp,
        "status": "blocked" if blocked else "ok",
        "candidate_count": len(rows),
        "blocked_count": len(blocked),
        "classifications": rows,
        "warnings": sorted({warning for row in blocked for warning in row.get("warnings") or []}),
        **FILESYSTEM_SAFETY_FLAGS,
        "runtime_artifact_staged": bool(blocked),
        "private_file_staged": any(row.get("is_private_file") for row in blocked),
    }


def build_private_file_warning_records(paths: Iterable[str], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [classify_runtime_artifact(path, generated_at=timestamp) for path in paths or []]
    private_rows = [row for row in rows if row.get("is_private_file")]
    warnings = [
        {
            "record_type": "private_file_warning",
            "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
            "generated_at": timestamp,
            "path_ref": row.get("path_ref"),
            "warning": "private_validation_file_must_remain_unstaged",
            **FILESYSTEM_SAFETY_FLAGS,
            "private_file_staged": True,
        }
        for row in private_rows
    ]
    return {
        "record_type": "private_file_warning_summary",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "generated_at": timestamp,
        "status": "blocked" if warnings else "ok",
        "warning_count": len(warnings),
        "warnings": warnings,
        **FILESYSTEM_SAFETY_FLAGS,
        "private_file_staged": bool(warnings),
    }


def validate_public_doc_safety(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        text = str(record.get("content") or "")
        doc_ref = str(record.get("doc_ref") or "<doc-ref>")
        matches = sorted({pattern.pattern for pattern in PRIVATE_PATTERNS if pattern.search(text)})
        rows.append(
            {
                "record_type": "public_doc_safety_record",
                "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
                "generated_at": timestamp,
                "doc_ref": doc_ref,
                "status": "blocked" if matches else "ok",
                "match_count": len(matches),
                "private_pattern_refs": matches,
                **FILESYSTEM_SAFETY_FLAGS,
                "public_doc_safe": not matches,
            }
        )
    blocked = [row for row in rows if row["status"] == "blocked"]
    return {
        "record_type": "public_doc_safety_validation",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "generated_at": timestamp,
        "status": "blocked" if blocked else "ok",
        "doc_count": len(rows),
        "blocked_count": len(blocked),
        "items": rows,
        **FILESYSTEM_SAFETY_FLAGS,
        "public_doc_safe": not blocked,
    }


def summarize_filesystem_safety(
    *,
    platform_family: str,
    paths: list[dict[str, Any]],
    artifact_validation: dict[str, Any],
    private_warnings: dict[str, Any],
    public_docs: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    blocked = int(artifact_validation.get("blocked_count") or 0) + int(private_warnings.get("warning_count") or 0) + int(public_docs.get("blocked_count") or 0)
    path_warnings = sorted({warning for row in paths for warning in row.get("warnings") or []})
    status = "blocked" if blocked else "review_required" if path_warnings else "ok"
    warnings = sorted(set(path_warnings + list(artifact_validation.get("warnings") or [])))
    return {
        "record_type": "filesystem_safety_summary",
        "record_version": FILESYSTEM_SAFETY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "platform_family": str(platform_family or "unknown"),
        "path_count": len(paths),
        "artifact_blocked_count": int(artifact_validation.get("blocked_count") or 0),
        "private_warning_count": int(private_warnings.get("warning_count") or 0),
        "public_doc_blocked_count": int(public_docs.get("blocked_count") or 0),
        "warnings": warnings,
        "operator_summary": _operator_summary(status),
        **FILESYSTEM_SAFETY_FLAGS,
        "runtime_artifact_staged": bool(artifact_validation.get("runtime_artifact_staged")),
        "private_file_staged": bool(private_warnings.get("private_file_staged")),
        "public_doc_safe": bool(public_docs.get("public_doc_safe", True)),
    }


def build_filesystem_safety_dashboard_record(
    *,
    summary: dict[str, Any],
    paths: list[dict[str, Any]],
    artifact_validation: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "filesystem_safety_dashboard",
        "panel": "cross_platform_filesystem_export_safety",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "path_count": int(summary.get("path_count") or 0),
            "artifact_blocked_count": int(summary.get("artifact_blocked_count") or 0),
            "private_warning_count": int(summary.get("private_warning_count") or 0),
            "public_doc_blocked_count": int(summary.get("public_doc_blocked_count") or 0),
        },
        "path_rows": [
            {
                "path_kind": row.get("path_kind"),
                "platform_family": row.get("platform_family"),
                "path": row.get("path"),
                "sanitized": row.get("sanitized"),
            }
            for row in sorted(paths, key=lambda item: str(item.get("path_kind") or ""))
        ],
        "artifact_rows": [
            {
                "path_ref": row.get("path_ref"),
                "classification": row.get("classification"),
                "exclude_from_public_commit": row.get("exclude_from_public_commit"),
            }
            for row in artifact_validation.get("classifications") or []
            if isinstance(row, dict)
        ],
        "recommended_review": str(summary.get("status") or "") != "ok",
        **FILESYSTEM_SAFETY_FLAGS,
    }


def build_filesystem_safety_api_response(
    *,
    summary: dict[str, Any],
    platform_record: dict[str, Any],
    paths: list[dict[str, Any]],
    artifact_validation: dict[str, Any],
    private_warnings: dict[str, Any],
    public_docs: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "filesystem_safety_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "platform": dict(platform_record),
        "paths": sorted([dict(row) for row in paths], key=lambda item: str(item.get("path_kind") or "")),
        "artifact_validation": dict(artifact_validation),
        "private_file_warnings": dict(private_warnings),
        "public_doc_safety": dict(public_docs),
        "dashboard": dict(dashboard),
        **FILESYSTEM_SAFETY_FLAGS,
    }


def deterministic_filesystem_safety_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _placeholder_for(platform_family: str, path_kind: str) -> str:
    windows = platform_family == "windows"
    sep = "\\" if windows else "/"
    roots = {
        "log": "<portmap-log-dir>",
        "export": "<portmap-export-dir>",
        "cache": "<portmap-cache-dir>",
        "database": "<portmap-data-dir>",
        "data": "<portmap-data-dir>",
    }
    root = roots.get(path_kind, "<portmap-path>")
    leaf = {
        "log": "portmap.log",
        "export": "bundle.json",
        "cache": "runtime-cache",
        "database": "portmap.db",
    }.get(path_kind, "")
    return f"{root}{sep}{leaf}" if leaf else root


def _placeholder_with_name(placeholder: str, raw_path: str, *, platform_family: str) -> str:
    path_cls = PureWindowsPath if platform_family == "windows" else PurePosixPath
    name = path_cls(str(raw_path).replace("\\", "/") if platform_family != "windows" else str(raw_path).replace("/", "\\")).name
    if not name or "." not in name:
        return placeholder
    sep = "\\" if platform_family == "windows" else "/"
    base = placeholder.rsplit(sep, 1)[0] if sep in placeholder else placeholder
    return f"{base}{sep}{name}"


def _normalize_separator(path: str, *, platform_family: str) -> str:
    return str(path).replace("/", "\\") if platform_family == "windows" else str(path).replace("\\", "/")


def _is_absolute(path: str, *, platform_family: str) -> bool:
    text = str(path or "")
    if platform_family == "windows":
        return bool(len(text) >= 3 and text[1] == ":" and text[2] in {"\\", "/"}) or text.startswith("\\\\")
    return text.startswith("/")


def _looks_private(path: str, *, platform_family: str) -> bool:
    text = str(path or "")
    lowered = text.lower().replace("\\", "/")
    return any(marker in lowered for marker in ("/users/", "/appdata/", "/desktop/", "/downloads/", "/private/")) or lowered.startswith("//")


def _safe_path_ref(path: str) -> str:
    text = str(path or "")
    if "real_device_validation.md" in text:
        return "docs/real_device_validation.md"
    lowered = text.lower().replace("\\", "/")
    if any(marker in lowered for marker in ("logs/", "artifacts/", "dist/", "build/", "__pycache__", ".pytest_cache")):
        return "<runtime-artifact-path>"
    if _looks_private(text, platform_family="linux") or _looks_private(text, platform_family="windows"):
        return "<private-path>"
    return text


def _artifact_warnings(classification: str, *, private: bool, is_artifact: bool) -> list[str]:
    warnings = []
    if private:
        warnings.append("private_validation_file_must_remain_unstaged")
    if is_artifact:
        warnings.append(f"runtime_artifact_excluded:{classification}")
    return warnings


def _operator_summary(status: str) -> str:
    if status == "ok":
        return "Filesystem and export safety checks found no blocked public artifacts."
    if status == "blocked":
        return "Filesystem and export safety checks found files that must remain unstaged."
    return "Filesystem and export safety checks require operator review."


def _digest(payload: Any) -> str:
    return sha256(deterministic_filesystem_safety_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "ARTIFACT_DIR_MARKERS",
    "ARTIFACT_EXTENSIONS",
    "FILESYSTEM_SAFETY_FLAGS",
    "build_filesystem_safety_api_response",
    "build_filesystem_safety_dashboard_record",
    "build_filesystem_safety_report",
    "build_private_file_warning_records",
    "classify_runtime_artifact",
    "deterministic_filesystem_safety_json",
    "normalize_cross_platform_path",
    "summarize_filesystem_safety",
    "validate_artifact_exclusions",
    "validate_public_doc_safety",
]
