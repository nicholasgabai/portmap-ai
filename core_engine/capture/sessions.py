"""Capture session lifecycle helpers."""

from __future__ import annotations

from typing import Any, Dict

from .models import CaptureSession


def start_session(session: CaptureSession, *, at: Any = None) -> CaptureSession:
    return session.transition("running", at=at)


def pause_session(session: CaptureSession) -> CaptureSession:
    return session.transition("paused")


def resume_session(session: CaptureSession) -> CaptureSession:
    return session.transition("running")


def stop_session(session: CaptureSession, *, at: Any = None) -> CaptureSession:
    return session.transition("stopped", at=at)


def summarize_session_record(session: CaptureSession) -> Dict[str, Any]:
    return session.to_dict()
