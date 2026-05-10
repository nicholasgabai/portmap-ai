from __future__ import annotations

import base64
import ipaddress
import re
from statistics import mean
from typing import Any, Iterable

from core_engine.modules.dpi import payload_metadata, redact_text


DEFAULT_PREVIEW_BYTES = 120
LARGE_PAYLOAD_BYTES = 1024 * 1024
MEDIUM_PAYLOAD_BYTES = 4096
SEVERITY_SCORES = {"info": 0.1, "low": 0.3, "medium": 0.6, "high": 0.85}
SECRET_PATTERN = re.compile(r"(?i)(authorization:\s*(bearer|basic)|password=|passwd=|pwd=|api[_-]?key=|token=|secret=|PASS\s+\S+|AUTH\s+\S+)")
SCRIPT_PATTERN = re.compile(r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)")
SQL_PATTERN = re.compile(r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|sleep\s*\()")
COMMAND_PATTERN = re.compile(r"(?i)(cmd\.exe|powershell(?:\.exe)?|/bin/sh|/bin/bash|curl\s+https?://|wget\s+https?://)")
HTTP_MARKER = re.compile(r"(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+")


def classify_payload_observation(
    observation: dict[str, Any],
    *,
    include_payload_preview: bool = False,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise ValueError("payload observation must be an object")
    raw_payload = _payload_from_observation(observation)
    metadata = _payload_metadata(observation, raw_payload, include_payload_preview=include_payload_preview)
    protocol = _protocol(observation)
    network = _network_metadata(observation)
    findings = _content_findings(raw_payload, metadata, protocol)
    findings.extend(_metadata_findings(metadata, protocol, network))
    findings = _dedupe_findings(findings)
    label = _label(findings, metadata)
    confidence = _confidence(findings, metadata)
    result = {
        "status": "ok",
        "label": label,
        "confidence": confidence,
        "risk_score": _risk_score(findings),
        "protocol": protocol,
        "network": network,
        "payload": _safe_payload_metadata(metadata),
        "findings": findings,
        "raw_payload_stored": False,
        "model": "local_payload_classifier",
    }
    if include_payload_preview and raw_payload:
        result["payload"]["preview"] = redact_text(raw_payload[:DEFAULT_PREVIEW_BYTES].decode("utf-8", errors="replace"))
        result["payload"]["preview_included"] = True
    return result


def classify_payload_events(
    events: Iterable[dict[str, Any]],
    *,
    include_payload_preview: bool = False,
) -> dict[str, Any]:
    event_list = list(events)
    classifications = [
        classify_payload_observation(event, include_payload_preview=include_payload_preview)
        for event in event_list
    ]
    aggregate_findings = detect_beaconing(event_list)
    aggregate_findings.extend(detect_exfiltration(classifications))
    aggregate_findings = _dedupe_findings(aggregate_findings)
    return {
        "ok": True,
        "classification_count": len(classifications),
        "classifications": classifications,
        "aggregate_findings": aggregate_findings,
        "risk_score": max([_risk_score(aggregate_findings), *[item["risk_score"] for item in classifications]], default=0.1),
        "raw_payload_stored": False,
        "model": "local_payload_classifier",
    }


def detect_beaconing(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        network = _network_metadata(event)
        timestamp = _float(event.get("timestamp") or network.get("timestamp"))
        if timestamp <= 0:
            continue
        key = str(event.get("flow_id") or event.get("session_key") or f"{network.get('src_ip')}->{network.get('dst_ip')}:{network.get('dst_port')}")
        groups.setdefault(key, []).append({"timestamp": timestamp, "payload_bytes": _payload_length(event)})

    findings: list[dict[str, Any]] = []
    for key, rows in groups.items():
        if len(rows) < 4:
            continue
        rows.sort(key=lambda item: item["timestamp"])
        intervals = [rows[index]["timestamp"] - rows[index - 1]["timestamp"] for index in range(1, len(rows))]
        if not intervals or min(intervals) <= 0:
            continue
        avg_interval = mean(intervals)
        jitter = max(abs(interval - avg_interval) for interval in intervals)
        avg_payload = mean(max(int(row["payload_bytes"]), 0) for row in rows)
        if avg_interval >= 5 and jitter <= max(avg_interval * 0.15, 1.0) and avg_payload <= 512:
            findings.append(_finding("beaconing_candidate", "medium", "timing", f"regular small-payload interval observed for {key}"))
    return findings


def detect_exfiltration(classifications: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    by_destination: dict[str, int] = {}
    for item in classifications:
        network = item.get("network") or {}
        dst_ip = str(network.get("dst_ip") or "")
        if not _is_public_ip(dst_ip):
            continue
        payload = item.get("payload") or {}
        length = int(payload.get("length") or 0)
        by_destination[dst_ip] = by_destination.get(dst_ip, 0) + length
    for dst_ip, total in by_destination.items():
        if total >= LARGE_PAYLOAD_BYTES:
            findings.append(_finding("possible_exfiltration_volume", "high", "payload_volume", f"{total} payload bytes observed toward public destination {dst_ip}"))
    return findings


def _content_findings(raw_payload: bytes, metadata: dict[str, Any], protocol: str) -> list[dict[str, Any]]:
    text = raw_payload[:4096].decode("utf-8", errors="ignore") if raw_payload else ""
    findings: list[dict[str, Any]] = []
    if text and SECRET_PATTERN.search(text):
        findings.append(_finding("credential_marker", "high", "payload_pattern", "payload contains credential-like markers"))
    if text and SCRIPT_PATTERN.search(text):
        findings.append(_finding("script_injection_marker", "medium", "payload_pattern", "payload contains script injection markers"))
    if text and SQL_PATTERN.search(text):
        findings.append(_finding("sql_injection_marker", "high", "payload_pattern", "payload contains SQL injection markers"))
    if text and COMMAND_PATTERN.search(text):
        findings.append(_finding("command_marker", "high", "payload_pattern", "payload contains shell or command execution markers"))
    if protocol == "TLS" and text and HTTP_MARKER.search(text):
        findings.append(_finding("protocol_misuse", "medium", "protocol_marker", "HTTP-looking payload was labeled as TLS"))
    if protocol in {"HTTP", "FTP", "SMTP"} and any(item["type"] == "credential_marker" for item in findings):
        findings.append(_finding("cleartext_sensitive_payload", "high", "cleartext_protocol", f"{protocol} payload contains sensitive markers"))
    if metadata.get("category") == "high_entropy":
        findings.append(_finding("high_entropy_payload", "medium", "payload_entropy", "payload entropy is elevated"))
    return findings


def _metadata_findings(metadata: dict[str, Any], protocol: str, network: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    length = int(metadata.get("length") or 0)
    entropy = float(metadata.get("entropy") or 0)
    if length >= LARGE_PAYLOAD_BYTES:
        findings.append(_finding("large_payload", "medium", "payload_length", "payload is large enough to need review"))
    if length >= MEDIUM_PAYLOAD_BYTES and entropy >= 7.0 and protocol in {"HTTP", "DNS", "SMTP"}:
        findings.append(_finding("possible_tunneled_payload", "medium", "payload_metadata", f"{protocol} payload is large and high entropy"))
    if _is_public_ip(str(network.get("dst_ip") or "")) and length >= MEDIUM_PAYLOAD_BYTES and entropy >= 7.0:
        findings.append(_finding("possible_exfiltration_payload", "high", "payload_metadata", "high-entropy payload sent toward public destination"))
    return findings


def _payload_from_observation(observation: dict[str, Any]) -> bytes:
    if "payload_b64" in observation:
        return base64.b64decode(str(observation["payload_b64"]), validate=True)
    if "payload_hex" in observation:
        return bytes.fromhex(str(observation["payload_hex"]))
    if "payload_text" in observation:
        return str(observation["payload_text"]).encode("utf-8")
    return b""


def _payload_metadata(observation: dict[str, Any], raw_payload: bytes, *, include_payload_preview: bool) -> dict[str, Any]:
    existing = observation.get("payload")
    if isinstance(existing, dict) and not raw_payload:
        return {
            "length": int(existing.get("length") or 0),
            "sha256": str(existing.get("sha256") or ""),
            "entropy": float(existing.get("entropy") or 0),
            "printable_ratio": float(existing.get("printable_ratio") or 0),
            "null_bytes": int(existing.get("null_bytes") or 0),
            "category": str(existing.get("category") or "unknown"),
            "preview_included": False,
        }
    return payload_metadata(raw_payload, include_preview=False if not include_payload_preview else False)


def _safe_payload_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "length": int(metadata.get("length") or 0),
        "sha256": str(metadata.get("sha256") or ""),
        "entropy": float(metadata.get("entropy") or 0),
        "printable_ratio": float(metadata.get("printable_ratio") or 0),
        "null_bytes": int(metadata.get("null_bytes") or 0),
        "category": str(metadata.get("category") or "unknown"),
        "preview_included": False,
    }


def _network_metadata(observation: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(observation.get("metadata") or {})
    headers = observation.get("headers") or {}
    if isinstance(headers, dict) and isinstance(headers.get("network"), dict):
        metadata.update({key: value for key, value in headers["network"].items() if value not in {None, ""}})
    for key in ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "direction"):
        if observation.get(key) not in {None, ""}:
            metadata[key] = observation[key]
    return metadata


def _protocol(observation: dict[str, Any]) -> str:
    for value in (
        observation.get("application_protocol"),
        observation.get("protocol"),
        (observation.get("dissection") or {}).get("protocol") if isinstance(observation.get("dissection"), dict) else None,
        (observation.get("dpi") or {}).get("protocol") if isinstance(observation.get("dpi"), dict) else None,
    ):
        if value:
            return str(value).upper()
    return "unknown"


def _payload_length(event: dict[str, Any]) -> int:
    existing = event.get("payload")
    if isinstance(existing, dict):
        return int(existing.get("length") or 0)
    return len(_payload_from_observation(event))


def _label(findings: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    finding_types = {finding["type"] for finding in findings}
    if "credential_marker" in finding_types or "cleartext_sensitive_payload" in finding_types:
        return "sensitive_cleartext"
    if {"sql_injection_marker", "script_injection_marker", "command_marker"} & finding_types:
        return "suspicious_payload"
    if "possible_exfiltration_payload" in finding_types or "possible_exfiltration_volume" in finding_types:
        return "possible_exfiltration"
    if "possible_tunneled_payload" in finding_types:
        return "possible_tunnel"
    if metadata.get("category") == "high_entropy":
        return "encrypted_or_compressed"
    if metadata.get("category") == "text":
        return "text"
    if metadata.get("category") == "binary":
        return "binary"
    return "empty"


def _confidence(findings: list[dict[str, Any]], metadata: dict[str, Any]) -> float:
    score = 0.35
    if metadata.get("length"):
        score += 0.2
    if findings:
        score += min(len(findings) * 0.12, 0.35)
    return round(min(score, 0.95), 2)


def _risk_score(findings: list[dict[str, Any]]) -> float:
    score = 0.1
    for finding in findings:
        score = max(score, SEVERITY_SCORES.get(str(finding.get("severity") or "info"), 0.1))
    return round(score, 2)


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


def _is_public_ip(value: str) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved)


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
