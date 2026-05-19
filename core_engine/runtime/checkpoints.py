from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.runtime.session_state import SAFETY_FLAGS, summarize_runtime_session


CHECKPOINT_RECORD_VERSION = 1
CHECKPOINT_STATUSES = frozenset({"complete", "incomplete", "failed"})


class RuntimeCheckpointError(ValueError):
    """Raised when a runtime checkpoint record is malformed."""


def build_runtime_checkpoint(
    *,
    checkpoint_id: str | None = None,
    session: dict[str, Any] | Any | None = None,
    session_summary: dict[str, Any] | None = None,
    profile_summary: dict[str, Any] | None = None,
    pipeline_result: dict[str, Any] | None = None,
    runtime_summary: dict[str, Any] | None = None,
    storage_summary: dict[str, Any] | None = None,
    review_summary: dict[str, Any] | None = None,
    export_summary: dict[str, Any] | None = None,
    status: str | None = None,
    created_at: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp = created_at or _now()
    session_row = session_summary or (summarize_runtime_session(session) if session is not None else {})
    pipeline_row = dict(pipeline_result or {})
    review_row = dict(review_summary or {})
    export_row = dict(export_summary or {})
    resolved_status = status or _infer_checkpoint_status(session_row, pipeline_row)
    payload = {
        "record_type": "runtime_checkpoint",
        "record_version": CHECKPOINT_RECORD_VERSION,
        "checkpoint_id": checkpoint_id or "",
        "status": resolved_status,
        "created_at": timestamp,
        "session_summary": session_row,
        "profile_summary": dict(profile_summary or {}),
        "pipeline_result": pipeline_row,
        "runtime_summary": dict(runtime_summary or {}),
        "storage_summary": dict(storage_summary or {}),
        "review_summary": review_row,
        "export_summary": export_row,
        "metadata": dict(metadata or {}),
        **SAFETY_FLAGS,
    }
    payload["checkpoint_id"] = payload["checkpoint_id"] or _stable_id("runtime-checkpoint", payload)
    validation = validate_runtime_checkpoint(payload)
    if not validation["ok"]:
        raise RuntimeCheckpointError("; ".join(validation["errors"]))
    return payload


def validate_runtime_checkpoint(checkpoint: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(checkpoint, dict):
        errors.append("checkpoint must be an object")
    else:
        if checkpoint.get("record_type") != "runtime_checkpoint":
            errors.append("record_type must be runtime_checkpoint")
        if checkpoint.get("record_version") != CHECKPOINT_RECORD_VERSION:
            errors.append(f"record_version must be {CHECKPOINT_RECORD_VERSION}")
        if not isinstance(checkpoint.get("checkpoint_id"), str) or not checkpoint.get("checkpoint_id"):
            errors.append("checkpoint_id is required")
        if checkpoint.get("status") not in CHECKPOINT_STATUSES:
            errors.append("status must be one of: complete, failed, incomplete")
        for key in (
            "session_summary",
            "profile_summary",
            "pipeline_result",
            "runtime_summary",
            "storage_summary",
            "review_summary",
            "export_summary",
            "metadata",
        ):
            if not isinstance(checkpoint.get(key), dict):
                errors.append(f"{key} must be an object")
    return {
        "ok": not errors,
        "status": "valid" if not errors else "invalid",
        "errors": errors,
        **SAFETY_FLAGS,
    }


def runtime_checkpoint_to_json(checkpoint: dict[str, Any]) -> str:
    validation = validate_runtime_checkpoint(checkpoint)
    if not validation["ok"]:
        raise RuntimeCheckpointError("; ".join(validation["errors"]))
    return json.dumps(checkpoint, sort_keys=True, indent=2, default=str)


def runtime_checkpoint_from_json(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeCheckpointError(f"invalid runtime checkpoint JSON: {exc}") from exc
    validation = validate_runtime_checkpoint(payload)
    if not validation["ok"]:
        raise RuntimeCheckpointError("; ".join(validation["errors"]))
    return payload


def write_runtime_checkpoint(path: str | Path, checkpoint: dict[str, Any]) -> dict[str, Any]:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    text = runtime_checkpoint_to_json(checkpoint)
    output_path.write_text(text + "\n", encoding="utf-8")
    return {
        "ok": True,
        "status": "written",
        "output_name": output_path.name,
        "bytes_written": len((text + "\n").encode("utf-8")),
        "path_stored": False,
        **SAFETY_FLAGS,
    }


def load_runtime_checkpoint(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        checkpoint = runtime_checkpoint_from_json(source.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "ok": False,
            "status": "invalid",
            "checkpoint": None,
            "error": str(exc),
            "input_name": source.name,
            "path_stored": False,
            **SAFETY_FLAGS,
        }
    return {
        "ok": True,
        "status": "loaded",
        "checkpoint": checkpoint,
        "input_name": source.name,
        "path_stored": False,
        **SAFETY_FLAGS,
    }


def summarize_runtime_checkpoints(checkpoints: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [row for row in checkpoints if isinstance(row, dict)]
    by_status: dict[str, int] = {status: 0 for status in sorted(CHECKPOINT_STATUSES)}
    for row in rows:
        status = str(row.get("status") or "incomplete")
        if status in by_status:
            by_status[status] += 1
    latest = sorted(rows, key=lambda row: (str(row.get("created_at") or ""), str(row.get("checkpoint_id") or "")))
    return {
        "checkpoint_count": len(rows),
        "by_status": by_status,
        "latest_checkpoint_id": str(latest[-1].get("checkpoint_id") or "") if latest else "",
        **SAFETY_FLAGS,
    }


def _infer_checkpoint_status(session_summary: dict[str, Any], pipeline_result: dict[str, Any]) -> str:
    if str(session_summary.get("status") or "") == "failed" or str(pipeline_result.get("status") or "") == "failed":
        return "failed"
    if str(session_summary.get("status") or "") == "running" or str(pipeline_result.get("status") or "") == "partial":
        return "incomplete"
    return "complete"


def _stable_id(prefix: str, payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
