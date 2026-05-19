from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable
from uuid import uuid4


SESSION_MODES = frozenset({"dry-run", "local-write", "service-preview"})
SESSION_STATUSES = frozenset({"running", "stopped", "failed"})
SAFETY_FLAGS = {
    "local_only": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


class RuntimeSessionError(ValueError):
    """Raised when a runtime session record is invalid."""


@dataclass(slots=True)
class RuntimeSession:
    session_id: str
    mode: str = "dry-run"
    status: str = "running"
    started_at: str = field(default_factory=lambda: _now())
    stopped_at: str | None = None
    enabled_components: dict[str, dict[str, Any]] = field(default_factory=dict)
    pipeline_summary: dict[str, Any] = field(default_factory=dict)
    status_references: dict[str, dict[str, Any]] = field(default_factory=dict)
    event_summary: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    review_summary: dict[str, Any] = field(default_factory=dict)
    export_summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_session(self)
        self.enabled_components = _normalize_component_map(self.enabled_components)
        self.status_references = _normalize_reference_map(self.status_references)
        self.warnings = _strings(self.warnings)
        self.errors = _strings(self.errors)

    def stop(self, *, stopped_at: str | None = None, status: str = "stopped") -> None:
        if status not in {"stopped", "failed"}:
            raise RuntimeSessionError("stop status must be stopped or failed")
        self.status = status
        self.stopped_at = stopped_at or _now()

    def record_warning(self, message: str) -> None:
        text = str(message).strip()
        if text:
            self.warnings.append(text)

    def record_error(self, message: str) -> None:
        text = str(message).strip()
        if text:
            self.errors.append(text)
            self.status = "failed"

    def set_component(self, name: str, *, enabled: bool = True, status: str = "enabled", summary: dict[str, Any] | None = None) -> None:
        self.enabled_components[str(name)] = build_component_summary(name, enabled=enabled, status=status, summary=summary)

    def set_reference(self, name: str, reference: dict[str, Any]) -> None:
        self.status_references[str(name)] = build_status_reference(
            str(reference.get("name") or name),
            status=str(reference.get("status") or "available"),
            record_id=str(reference.get("record_id") or ""),
            summary=_dict(reference.get("summary")),
            source_ref=str(reference.get("source_ref") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return summarize_runtime_session(self)


def create_runtime_session(
    *,
    session_id: str | None = None,
    mode: str = "dry-run",
    started_at: str | None = None,
    enabled_components: Iterable[str] | dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> RuntimeSession:
    """Create a local runtime session record.

    The record is descriptive only; creating it does not start services, run
    jobs, execute the runtime pipeline, or write persistent storage.
    """
    normalized_components = _components_from_input(enabled_components)
    return RuntimeSession(
        session_id=session_id or f"runtime-session-{uuid4().hex}",
        mode=mode,
        started_at=started_at or _now(),
        enabled_components=normalized_components,
        metadata=metadata or {},
    )


def build_component_summary(
    name: str,
    *,
    enabled: bool = True,
    status: str = "enabled",
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "component": str(name),
        "enabled": bool(enabled),
        "status": str(status or "enabled"),
        "summary": dict(summary or {}),
        **SAFETY_FLAGS,
    }


def build_status_reference(
    name: str,
    *,
    status: str = "available",
    record_id: str | None = None,
    summary: dict[str, Any] | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    return {
        "name": str(name),
        "status": str(status or "available"),
        "record_id": str(record_id or ""),
        "source_ref": str(source_ref or ""),
        "summary": dict(summary or {}),
        **SAFETY_FLAGS,
    }


def summarize_runtime_session(session: RuntimeSession | dict[str, Any]) -> dict[str, Any]:
    row = session if isinstance(session, dict) else _session_to_raw_dict(session)
    components = _normalize_component_map(row.get("enabled_components") or {})
    references = _normalize_reference_map(row.get("status_references") or {})
    warnings = _strings(row.get("warnings") or [])
    errors = _strings(row.get("errors") or [])
    return {
        "session_id": str(row.get("session_id") or ""),
        "mode": str(row.get("mode") or "dry-run"),
        "status": str(row.get("status") or "running"),
        "started_at": str(row.get("started_at") or ""),
        "stopped_at": row.get("stopped_at"),
        "enabled_components": {key: components[key] for key in sorted(components)},
        "component_count": len(components),
        "pipeline_summary": _dict(row.get("pipeline_summary")),
        "status_references": {key: references[key] for key in sorted(references)},
        "event_summary": _dict(row.get("event_summary")),
        "storage_summary": _dict(row.get("storage_summary")),
        "review_summary": _dict(row.get("review_summary")),
        "export_summary": _dict(row.get("export_summary")),
        "warning_count": len(warnings),
        "error_count": len(errors),
        "last_warning": warnings[-1] if warnings else None,
        "last_error": errors[-1] if errors else None,
        "warnings": warnings,
        "errors": errors,
        "metadata": _dict(row.get("metadata")),
        **SAFETY_FLAGS,
    }


def runtime_session_to_api_summary(session: RuntimeSession | dict[str, Any]) -> dict[str, Any]:
    summary = summarize_runtime_session(session)
    return {
        "status": summary["status"],
        "session": summary,
        "generated_at": _now(),
        **SAFETY_FLAGS,
    }


def stable_session_reference(*parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return "runtime-session-ref-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _validate_session(session: RuntimeSession) -> None:
    if not isinstance(session.session_id, str) or not session.session_id.strip():
        raise RuntimeSessionError("session_id must be a non-empty string")
    if session.mode not in SESSION_MODES:
        raise RuntimeSessionError(f"unsupported session mode: {session.mode}")
    if session.status not in SESSION_STATUSES:
        raise RuntimeSessionError(f"unsupported session status: {session.status}")
    if not isinstance(session.enabled_components, dict):
        raise RuntimeSessionError("enabled_components must be an object")
    if not isinstance(session.status_references, dict):
        raise RuntimeSessionError("status_references must be an object")
    if not isinstance(session.metadata, dict):
        raise RuntimeSessionError("metadata must be an object")


def _components_from_input(value: Iterable[str] | dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return _normalize_component_map(value)
    result: dict[str, dict[str, Any]] = {}
    for name in value:
        result[str(name)] = build_component_summary(str(name))
    return result


def _normalize_component_map(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for key, item in value.items():
        name = str(key)
        if isinstance(item, dict):
            result[name] = build_component_summary(
                str(item.get("component") or name),
                enabled=bool(item.get("enabled", True)),
                status=str(item.get("status") or "enabled"),
                summary=_dict(item.get("summary")),
            )
        else:
            result[name] = build_component_summary(name)
    return result


def _normalize_reference_map(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for key, item in value.items():
        name = str(key)
        if isinstance(item, dict):
            result[name] = build_status_reference(
                str(item.get("name") or name),
                status=str(item.get("status") or "available"),
                record_id=str(item.get("record_id") or ""),
                summary=_dict(item.get("summary")),
                source_ref=str(item.get("source_ref") or ""),
            )
        else:
            result[name] = build_status_reference(name, record_id=str(item))
    return result


def _session_to_raw_dict(session: RuntimeSession) -> dict[str, Any]:
    return {
        "session_id": session.session_id,
        "mode": session.mode,
        "status": session.status,
        "started_at": session.started_at,
        "stopped_at": session.stopped_at,
        "enabled_components": session.enabled_components,
        "pipeline_summary": session.pipeline_summary,
        "status_references": session.status_references,
        "event_summary": session.event_summary,
        "storage_summary": session.storage_summary,
        "review_summary": session.review_summary,
        "export_summary": session.export_summary,
        "warnings": session.warnings,
        "errors": session.errors,
        "metadata": session.metadata,
    }


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _strings(value: Iterable[Any]) -> list[str]:
    return [str(item) for item in value if str(item).strip()]


def _now() -> str:
    return datetime.now(UTC).isoformat()
