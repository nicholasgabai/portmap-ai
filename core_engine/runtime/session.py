from __future__ import annotations

from typing import Any, Iterable

from core_engine.runtime.session_state import (
    SAFETY_FLAGS,
    RuntimeSession,
    RuntimeSessionError,
    build_status_reference,
    create_runtime_session,
    summarize_runtime_session,
)


class RuntimeSessionManager:
    """Local in-memory manager for operator-started runtime session records."""

    def __init__(self) -> None:
        self._sessions: dict[str, RuntimeSession] = {}

    @property
    def local_only(self) -> bool:
        return True

    def start_session(
        self,
        *,
        session_id: str | None = None,
        mode: str = "dry-run",
        started_at: str | None = None,
        enabled_components: Iterable[str] | dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RuntimeSession:
        session = create_runtime_session(
            session_id=session_id,
            mode=mode,
            started_at=started_at,
            enabled_components=enabled_components,
            metadata=metadata,
        )
        self._sessions[session.session_id] = session
        return session

    def stop_session(self, session_id: str, *, stopped_at: str | None = None, status: str = "stopped") -> bool:
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.stop(stopped_at=stopped_at, status=status)
        return True

    def get_session(self, session_id: str) -> RuntimeSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[RuntimeSession]:
        return [self._sessions[key] for key in sorted(self._sessions)]

    def remove_session(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    def summarize_sessions(self) -> dict[str, Any]:
        sessions = [summarize_runtime_session(session) for session in self.list_sessions()]
        by_status: dict[str, int] = {}
        by_mode: dict[str, int] = {}
        for session in sessions:
            by_status[session["status"]] = by_status.get(session["status"], 0) + 1
            by_mode[session["mode"]] = by_mode.get(session["mode"], 0) + 1
        return {
            "session_count": len(sessions),
            "sessions_by_status": dict(sorted(by_status.items())),
            "sessions_by_mode": dict(sorted(by_mode.items())),
            "items": sessions,
            **SAFETY_FLAGS,
        }

    def attach_pipeline_result(self, session_id: str, result: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(session_id)
        summary = dict(result.get("summary") or {})
        session.pipeline_summary = {
            "status": str(result.get("status") or "unknown"),
            "ok": bool(result.get("ok", False)),
            "summary": summary,
            **SAFETY_FLAGS,
        }
        session.set_reference(
            "pipeline",
            build_status_reference(
                "pipeline",
                status=session.pipeline_summary["status"],
                record_id=str(result.get("workflow_id") or result.get("generated_at") or ""),
                summary=summary,
                source_ref="runtime:pipeline",
            ),
        )
        if result.get("status") == "partial":
            session.record_warning("runtime pipeline completed with partial status")
        if result.get("status") == "failed":
            session.record_error("runtime pipeline failed")
        return summarize_runtime_session(session)

    def attach_event_summary(self, session_id: str, summary: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(session_id)
        session.event_summary = _summary("events", summary)
        session.set_reference("events", build_status_reference("events", summary=session.event_summary, source_ref="runtime:events"))
        return summarize_runtime_session(session)

    def attach_storage_summary(self, session_id: str, summary: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(session_id)
        session.storage_summary = _summary("storage", summary)
        session.set_reference("storage", build_status_reference("storage", summary=session.storage_summary, source_ref="runtime:storage"))
        return summarize_runtime_session(session)

    def attach_review_summary(self, session_id: str, summary: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(session_id)
        session.review_summary = _summary("reviews", summary)
        session.set_reference("reviews", build_status_reference("reviews", summary=session.review_summary, source_ref="runtime:reviews"))
        return summarize_runtime_session(session)

    def attach_export_summary(self, session_id: str, summary: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(session_id)
        session.export_summary = _summary("export", summary)
        session.set_reference("export", build_status_reference("export", summary=session.export_summary, source_ref="runtime:export"))
        return summarize_runtime_session(session)

    def attach_status_reference(self, session_id: str, name: str, summary: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(session_id)
        session.set_reference(name, build_status_reference(name, summary=summary, source_ref=f"runtime:{name}"))
        return summarize_runtime_session(session)

    def _require_session(self, session_id: str) -> RuntimeSession:
        session = self.get_session(session_id)
        if session is None:
            raise RuntimeSessionError(f"unknown runtime session: {session_id}")
        return session


def _summary(name: str, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        **dict(summary or {}),
        **SAFETY_FLAGS,
    }
