"""Structured JSONL audit event helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core_engine import config_loader

AUDIT_EVENTS_FILENAME = "audit_events.jsonl"
DEFAULT_AUDIT_FILES = (
    AUDIT_EVENTS_FILENAME,
    "command_events.jsonl",
    "remediation_events.jsonl",
)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def build_audit_event(
    event_type: str,
    *,
    node_id: str | None = None,
    action: str | None = None,
    status: str | None = None,
    risk_score: float | int | None = None,
    source: str | None = None,
    details: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": timestamp or utc_timestamp(),
        "event_type": event_type,
    }
    if node_id:
        event["node_id"] = node_id
    if action:
        event["action"] = action
    if status:
        event["status"] = status
    if risk_score is not None:
        event["risk_score"] = risk_score
    if source:
        event["source"] = source
    if details:
        event["details"] = _json_safe(details)
    return event


def append_jsonl_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(_json_safe(event), sort_keys=True) + "\n")


def record_audit_event(
    event_type: str,
    *,
    filename: str = AUDIT_EVENTS_FILENAME,
    logger: Any | None = None,
    **fields: Any,
) -> dict[str, Any]:
    event = build_audit_event(event_type, **fields)
    try:
        config_loader.ensure_runtime_dirs()
        append_jsonl_event(Path(config_loader.LOG_DIR) / filename, event)
    except Exception as exc:
        if logger:
            logger.warning("Failed to write audit event: %s", exc)
    return event


def read_jsonl_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events


def filter_audit_events(
    *,
    log_dir: Path | None = None,
    filenames: Iterable[str] = DEFAULT_AUDIT_FILES,
    node_id: str | None = None,
    event_type: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    root = log_dir or Path(config_loader.LOG_DIR)
    events: list[dict[str, Any]] = []
    for filename in filenames:
        for event in read_jsonl_events(root / filename):
            if node_id and event.get("node_id") != node_id:
                continue
            if event_type and event.get("event_type") != event_type:
                continue
            events.append(event)
    events.sort(key=lambda item: str(item.get("timestamp", "")))
    if limit is not None and limit >= 0:
        return events[-limit:]
    return events


__all__ = [
    "AUDIT_EVENTS_FILENAME",
    "DEFAULT_AUDIT_FILES",
    "append_jsonl_event",
    "build_audit_event",
    "filter_audit_events",
    "read_jsonl_events",
    "record_audit_event",
    "utc_timestamp",
]
