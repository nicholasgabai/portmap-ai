# core_engine/command_audit.py

from __future__ import annotations

from pathlib import Path
from typing import Any

from core_engine.audit_events import AUDIT_EVENTS_FILENAME, append_jsonl_event, record_audit_event, utc_timestamp
from core_engine import config_loader

COMMAND_AUDIT_FILENAME = "command_events.jsonl"


def record_command_event(
    node_id: str,
    command: dict[str, Any],
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    logger: Any | None = None,
) -> dict[str, Any]:
    """
    Append a structured command outcome record to the runtime audit log.

    This should never break command execution; write errors are logged and the
    event is still returned to callers/tests.
    """

    event: dict[str, Any] = {
        "timestamp": utc_timestamp(),
        "event_type": "command_event",
        "node_id": node_id,
        "action": command.get("type", "unknown"),
        "command_type": command.get("type", "unknown"),
        "status": status,
        "command": command,
    }
    if result is not None:
        event["result"] = result
    if error:
        event["error"] = str(error)

    try:
        config_loader.ensure_runtime_dirs()
        path = Path(config_loader.LOG_DIR) / COMMAND_AUDIT_FILENAME
        append_jsonl_event(path, event)
        record_audit_event(
            "command_event",
            node_id=node_id,
            action=event["command_type"],
            status=status,
            source="command_audit",
            details=event,
            filename=AUDIT_EVENTS_FILENAME,
            logger=logger,
        )
    except Exception as exc:
        if logger:
            logger.warning("Failed to write command audit event: %s", exc)

    return event


__all__ = ["COMMAND_AUDIT_FILENAME", "record_command_event"]
