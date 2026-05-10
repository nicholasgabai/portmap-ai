from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


MAX_TEXT_FIELD = 240


@dataclass
class DissectionResult:
    protocol: str
    status: str = "ok"
    confidence: float = 0.0
    summary: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    payload_bytes: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "status": self.status,
            "confidence": round(float(self.confidence), 3),
            "summary": self.summary,
            "fields": dict(self.fields),
            "evidence": list(self.evidence),
            "payload_bytes": int(self.payload_bytes),
            "error": self.error,
        }


def ok(protocol: str, *, confidence: float, summary: str, fields: dict[str, Any] | None = None, evidence: list[str] | None = None, payload: bytes = b"") -> dict[str, Any]:
    return DissectionResult(
        protocol=protocol,
        status="ok",
        confidence=confidence,
        summary=summary,
        fields=fields or {},
        evidence=evidence or [],
        payload_bytes=len(payload),
    ).to_dict()


def unknown(protocol: str = "unknown", *, reason: str = "no_matching_dissector", payload: bytes = b"") -> dict[str, Any]:
    return DissectionResult(
        protocol=protocol,
        status="unknown",
        confidence=0.0,
        summary=reason,
        evidence=[reason],
        payload_bytes=len(payload),
    ).to_dict()


def failed(protocol: str, *, error: str, payload: bytes = b"") -> dict[str, Any]:
    return DissectionResult(
        protocol=protocol,
        status="error",
        confidence=0.0,
        summary="dissection_failed",
        evidence=["parse_error"],
        payload_bytes=len(payload),
        error=error,
    ).to_dict()


def decode_text(data: bytes, *, limit: int = MAX_TEXT_FIELD) -> str:
    text = data[:limit].decode("utf-8", errors="replace")
    return text.replace("\x00", "").strip()


def first_line(data: bytes) -> str:
    text = decode_text(data)
    return text.splitlines()[0].strip() if text.splitlines() else text.strip()


def redact_token(value: str) -> str:
    if not value:
        return ""
    return "<redacted>"


def strip_query(path: str) -> str:
    return path.split("?", 1)[0] or "/"
