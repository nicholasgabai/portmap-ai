from __future__ import annotations

import base64
import hashlib
import math
import re
from collections import Counter
from typing import Any, Iterable

from core_engine.modules.packet_capture import extract_packet_metadata
from core_engine.protocols import classify_protocol, dissect_packet, dissect_payload, extract_transport_payload


DEFAULT_PREVIEW_BYTES = 160
AUTH_PATTERN = re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s\r\n]+")
SECRET_PATTERN = re.compile(r"(?i)((?:password|passwd|pwd|token|api[_-]?key|secret)=)[^&\s\r\n]+")
COMMAND_SECRET_PATTERN = re.compile(r"(?i)((?:PASS|AUTH)\s+).+")
EMAIL_PATTERN = re.compile(r"(?i)([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})")
SUSPICIOUS_PATTERNS = [
    ("credential_material", "medium", re.compile(rb"(?i)(authorization:\s*(bearer|basic)|password=|passwd=|pwd=|api[_-]?key=|token=|secret=|PASS\s+\S+|AUTH\s+\S+)")),
    ("script_injection_marker", "medium", re.compile(rb"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)")),
    ("sql_injection_marker", "high", re.compile(rb"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|sleep\s*\()")),
    ("shell_command_marker", "high", re.compile(rb"(?i)(cmd\.exe|powershell(?:\.exe)?|/bin/sh|/bin/bash|curl\s+https?://|wget\s+https?://)")),
]
SEVERITY_SCORES = {"info": 0.1, "low": 0.25, "medium": 0.55, "high": 0.8}


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    raw = bytes(data)
    if not raw:
        return 0.0
    counts = Counter(raw)
    length = len(raw)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def printable_ratio(data: bytes | bytearray | memoryview) -> float:
    raw = bytes(data)
    if not raw:
        return 0.0
    printable = sum(1 for byte in raw if byte in {9, 10, 13} or 32 <= byte <= 126)
    return printable / len(raw)


def redact_text(text: str) -> str:
    redacted = AUTH_PATTERN.sub(r"\1<redacted>", text)
    redacted = SECRET_PATTERN.sub(r"\1<redacted>", redacted)
    redacted = COMMAND_SECRET_PATTERN.sub(r"\1<redacted>", redacted)
    return EMAIL_PATTERN.sub(r"<redacted>@\2", redacted)


def payload_metadata(
    payload: bytes | bytearray | memoryview,
    *,
    include_preview: bool = False,
    preview_bytes: int = DEFAULT_PREVIEW_BYTES,
) -> dict[str, Any]:
    raw = bytes(payload)
    entropy = shannon_entropy(raw)
    ratio = printable_ratio(raw)
    category = "empty"
    if raw:
        if entropy >= 7.4 and len(raw) >= 128:
            category = "high_entropy"
        elif ratio >= 0.85:
            category = "text"
        else:
            category = "binary"
    result: dict[str, Any] = {
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
        "entropy": round(entropy, 3),
        "printable_ratio": round(ratio, 3),
        "null_bytes": raw.count(b"\x00"),
        "category": category,
        "preview_included": include_preview,
    }
    if include_preview and raw:
        preview = raw[: max(preview_bytes, 0)].decode("utf-8", errors="replace")
        result["preview"] = redact_text(preview)
    return result


def session_key(metadata: dict[str, Any]) -> str:
    protocol = str(metadata.get("protocol") or metadata.get("transport") or "unknown").upper()
    left = (str(metadata.get("src_ip") or ""), int(metadata.get("src_port") or 0))
    right = (str(metadata.get("dst_ip") or ""), int(metadata.get("dst_port") or 0))
    first, second = sorted([left, right])
    return f"{protocol}:{first[0]}:{first[1]}-{second[0]}:{second[1]}"


def extract_headers(metadata: dict[str, Any], dissection: dict[str, Any] | None = None) -> dict[str, Any]:
    fields = dict((dissection or {}).get("fields") or {})
    return {
        "network": {
            "src_ip": metadata.get("src_ip") or "",
            "dst_ip": metadata.get("dst_ip") or "",
            "src_port": metadata.get("src_port"),
            "dst_port": metadata.get("dst_port"),
            "transport": metadata.get("protocol") or "unknown",
            "ip_version": metadata.get("ip_version"),
        },
        "application": _redact_header_fields(fields),
    }


def _redact_header_fields(fields: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in fields.items():
        key_text = str(key)
        if any(marker in key_text.lower() for marker in ("password", "token", "secret", "authorization", "argument")):
            redacted[key_text] = "<redacted>" if value else value
        elif isinstance(value, str):
            redacted[key_text] = redact_text(value)
        else:
            redacted[key_text] = value
    return redacted


def detect_suspicious_patterns(payload: bytes | bytearray | memoryview, metadata: dict[str, Any], dissection: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    raw = bytes(payload)
    findings: list[dict[str, Any]] = []
    for finding_type, severity, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(raw):
            findings.append(_finding(finding_type, severity, "payload_pattern", "payload metadata matched a suspicious marker"))
    if len(raw) >= 128 and shannon_entropy(raw) >= 7.4:
        findings.append(_finding("high_entropy_payload", "medium", "payload_entropy", "payload entropy is elevated for its size"))

    protocol = str((dissection or {}).get("protocol") or "").upper()
    fields = (dissection or {}).get("fields") or {}
    if protocol == "FTP" and str(fields.get("command") or "").upper() in {"PASS", "USER"}:
        findings.append(_finding("cleartext_credential_protocol", "medium", "ftp_command", "FTP credential command observed in cleartext metadata"))
    if protocol == "SMTP" and str(fields.get("command") or "").upper() in {"AUTH", "MAIL", "RCPT"}:
        findings.append(_finding("cleartext_mail_auth_or_identity", "low", "smtp_command", "SMTP identity/auth command observed in cleartext metadata"))
    if protocol == "HTTP" and str(fields.get("method") or "").upper() == "POST" and any(word in str(fields.get("path") or "").lower() for word in ("login", "auth", "session")):
        findings.append(_finding("cleartext_login_flow", "medium", "http_path", "HTTP login-like POST observed without TLS context"))
    return _dedupe_findings(findings)


def detect_malformed_protocol(payload: bytes | bytearray | memoryview, dissection: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    raw = bytes(payload)
    result = dissection or {}
    findings: list[dict[str, Any]] = []
    if result.get("status") == "error":
        findings.append(_finding("malformed_protocol", "medium", "dissector_error", str(result.get("error") or "protocol parser returned an error")))
    if result.get("status") == "unknown" and raw and result.get("protocol") not in {"unknown", "UNKNOWN"}:
        findings.append(_finding("unrecognized_protocol_payload", "low", "unknown_dissection", str(result.get("summary") or "protocol payload could not be parsed")))
    if result.get("protocol") == "TLS":
        record_length = ((result.get("fields") or {}).get("record_length"))
        if isinstance(record_length, int) and record_length > max(len(raw) - 5, 0):
            findings.append(_finding("truncated_tls_record", "medium", "tls_record_length", "TLS record length exceeds captured payload bytes"))
    return findings


def analyze_packet(
    packet: bytes | bytearray | memoryview | None = None,
    *,
    metadata: dict[str, Any] | None = None,
    payload: bytes | bytearray | memoryview | None = None,
    dissection: dict[str, Any] | None = None,
    include_payload_preview: bool = False,
) -> dict[str, Any]:
    raw_packet = bytes(packet or b"")
    selected_metadata = dict(metadata or (extract_packet_metadata(raw_packet) if raw_packet else {}))
    selected_payload = bytes(payload if payload is not None else extract_transport_payload(raw_packet, selected_metadata) if raw_packet else b"")
    selected_dissection = dissection
    if selected_dissection is None:
        if raw_packet:
            selected_dissection = dissect_packet(raw_packet, metadata=selected_metadata)
        else:
            protocol = classify_protocol(selected_metadata, selected_payload)
            selected_dissection = dissect_payload(protocol, selected_payload, selected_metadata)

    suspicious = detect_suspicious_patterns(selected_payload, selected_metadata, selected_dissection)
    malformed = detect_malformed_protocol(selected_payload, selected_dissection)
    findings = _dedupe_findings([*suspicious, *malformed])
    return {
        "status": "ok",
        "protocol": selected_dissection.get("protocol", "unknown"),
        "session_key": session_key(selected_metadata),
        "headers": extract_headers(selected_metadata, selected_dissection),
        "payload": payload_metadata(selected_payload, include_preview=include_payload_preview),
        "dissection": {
            "protocol": selected_dissection.get("protocol"),
            "status": selected_dissection.get("status"),
            "confidence": selected_dissection.get("confidence"),
            "summary": selected_dissection.get("summary"),
            "evidence": selected_dissection.get("evidence") or [],
        },
        "findings": findings,
        "risk_score": _score_findings(findings),
        "redaction": {
            "payload_preview_included": include_payload_preview,
            "raw_payload_stored": False,
            "sensitive_fields_redacted": True,
        },
    }


def analyze_observation(observation: dict[str, Any], *, include_payload_preview: bool = False) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise ValueError("DPI observation must be a JSON object")
    metadata = dict(observation.get("metadata") or {})
    protocol = str(observation.get("protocol") or metadata.get("application_protocol") or "")
    payload = _payload_from_observation(observation)
    dissection = observation.get("dissection")
    if dissection is None and protocol:
        dissection = dissect_payload(protocol, payload, metadata)
    return analyze_packet(
        metadata=metadata,
        payload=payload,
        dissection=dissection,
        include_payload_preview=include_payload_preview,
    )


def group_sessions(events: Iterable[dict[str, Any]], *, window_seconds: float = 60.0) -> list[dict[str, Any]]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")
    sessions: dict[str, dict[str, Any]] = {}
    for event in events:
        metadata = event.get("metadata") if "metadata" in event else event
        if not isinstance(metadata, dict):
            continue
        key = session_key(metadata)
        timestamp = float(metadata.get("timestamp") or event.get("timestamp") or 0)
        payload_length = int(metadata.get("payload_bytes") or (event.get("payload") or {}).get("length") or 0)
        session = sessions.setdefault(
            key,
            {
                "session_key": key,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "packet_count": 0,
                "total_payload_bytes": 0,
                "protocols": set(),
                "findings": set(),
            },
        )
        if timestamp:
            session["first_seen"] = min(session["first_seen"] or timestamp, timestamp)
            session["last_seen"] = max(session["last_seen"] or timestamp, timestamp)
        session["packet_count"] += 1
        session["total_payload_bytes"] += payload_length
        if metadata.get("protocol"):
            session["protocols"].add(str(metadata["protocol"]))
        for finding in event.get("findings") or []:
            if isinstance(finding, dict) and finding.get("type"):
                session["findings"].add(str(finding["type"]))
    return [
        {
            **session,
            "protocols": sorted(session["protocols"]),
            "findings": sorted(session["findings"]),
            "duration_seconds": round(max(float(session["last_seen"]) - float(session["first_seen"]), 0.0), 3),
        }
        for session in sorted(sessions.values(), key=lambda item: str(item["session_key"]))
    ]


def _payload_from_observation(observation: dict[str, Any]) -> bytes:
    if "payload_b64" in observation:
        return base64.b64decode(str(observation["payload_b64"]), validate=True)
    if "payload_hex" in observation:
        return bytes.fromhex(str(observation["payload_hex"]))
    if "payload_text" in observation:
        return str(observation["payload_text"]).encode("utf-8")
    return b""


def _finding(finding_type: str, severity: str, evidence: str, detail: str) -> dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "evidence": evidence,
        "detail": detail,
    }


def _dedupe_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for finding in findings:
        key = (str(finding.get("type")), str(finding.get("evidence")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _score_findings(findings: Iterable[dict[str, Any]]) -> float:
    score = 0.0
    for finding in findings:
        score = max(score, SEVERITY_SCORES.get(str(finding.get("severity")), 0.0))
    return round(score, 3)


__all__ = [
    "analyze_observation",
    "analyze_packet",
    "detect_malformed_protocol",
    "detect_suspicious_patterns",
    "extract_headers",
    "group_sessions",
    "payload_metadata",
    "printable_ratio",
    "redact_text",
    "session_key",
    "shannon_entropy",
]
