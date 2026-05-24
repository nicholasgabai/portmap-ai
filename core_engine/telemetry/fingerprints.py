from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.flows import SERVICE_PORTS
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


PROTOCOL_FINGERPRINT_RECORD_VERSION = 1
DEFAULT_METADATA_FIELD_LIMIT = 96

SERVICE_PROTOCOL_HINTS = {
    "http": "http",
    "http-alt": "http",
    "https": "tls",
    "https-alt": "tls",
    "dns": "dns",
    "dns-over-tls": "tls",
    "ssh": "ssh",
    "smtp": "smtp",
}

PROTOCOL_DEFAULT_PORTS = {
    "http": {80, 8080},
    "tls": {443, 8443, 853},
    "dns": {53},
}

SENSITIVE_METADATA_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "body",
        "payload",
        "content",
        "raw_payload",
    }
)


def infer_protocol_hint(flow: dict[str, Any], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    service_name = str(service.get("service_name") or "").lower()
    service_port = _safe_port(service.get("service_port"))
    explicit = _explicit_protocol(metadata or {})
    if explicit:
        protocol = explicit
        confidence = 0.9
        evidence = ["metadata_protocol_hint"]
    elif service_name in SERVICE_PROTOCOL_HINTS:
        protocol = SERVICE_PROTOCOL_HINTS[service_name]
        confidence = float(service.get("confidence") or 0.7)
        evidence = [f"service_name:{service_name}"]
    elif service_port in SERVICE_PORTS:
        protocol = SERVICE_PROTOCOL_HINTS.get(SERVICE_PORTS[service_port], "unknown")
        confidence = 0.55 if protocol != "unknown" else 0.0
        evidence = [f"service_port:{service_port}"]
    else:
        protocol = "unknown"
        confidence = 0.0
        evidence = []
    return {
        "record_type": "application_layer_hint",
        "record_version": PROTOCOL_FINGERPRINT_RECORD_VERSION,
        "flow_ref": str(flow.get("flow_id") or ""),
        "protocol": protocol,
        "service_name": service_name or "unknown",
        "service_port": service_port,
        "confidence": round(min(max(confidence, 0.0), 1.0), 3),
        "evidence": evidence,
        **_governance_fields(),
    }


def build_protocol_fingerprint(
    *,
    flow: dict[str, Any],
    protocol: str,
    metadata_summary: dict[str, Any] | None = None,
    confidence: float | None = None,
    evidence: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    protocol_name = str(protocol or "unknown").lower()
    summary = metadata_summary if isinstance(metadata_summary, dict) else {}
    score = confidence if confidence is not None else score_protocol_confidence(flow=flow, protocol=protocol_name, metadata_summary=summary)
    record = {
        "record_type": "protocol_fingerprint",
        "record_version": PROTOCOL_FINGERPRINT_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "flow_ref": str(flow.get("flow_id") or ""),
        "protocol": protocol_name,
        "transport_protocol": str(flow.get("transport_protocol") or "unknown"),
        "service_association": dict(flow.get("service_association") or {}) if isinstance(flow.get("service_association"), dict) else {},
        "confidence": round(min(max(float(score), 0.0), 1.0), 3),
        "evidence": sorted(set(str(item) for item in (evidence or _fingerprint_evidence(flow, protocol_name, summary)) if str(item))),
        "metadata_digest": _digest(summary),
        **_governance_fields(),
    }
    record["fingerprint_id"] = "protocol-fingerprint-" + _digest(record)[:16]
    return record


def score_protocol_confidence(*, flow: dict[str, Any], protocol: str, metadata_summary: dict[str, Any] | None = None) -> float:
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    service_name = str(service.get("service_name") or "").lower()
    service_port = _safe_port(service.get("service_port"))
    summary = metadata_summary if isinstance(metadata_summary, dict) else {}
    score = 0.2 if protocol != "unknown" else 0.0
    if summary.get("status") == "ok":
        score += 0.35
    if service_name and SERVICE_PROTOCOL_HINTS.get(service_name) == protocol:
        score += 0.25
    if service_port in PROTOCOL_DEFAULT_PORTS.get(protocol, set()):
        score += 0.15
    if summary.get("field_count"):
        score += 0.05
    return round(min(max(score, 0.0), 1.0), 3)


def build_service_fingerprint_summary(fingerprints: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in fingerprints or [] if isinstance(row, dict)]
    return {
        "record_type": "service_fingerprint_summary",
        "record_version": PROTOCOL_FINGERPRINT_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "fingerprint_count": len(rows),
        "by_protocol": _count_by(rows, "protocol"),
        "highest_confidence": round(max((float(row.get("confidence") or 0.0) for row in rows), default=0.0), 3),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        **_governance_fields(),
    }


def sanitize_metadata_fields(
    metadata: dict[str, Any] | None,
    *,
    allowed_fields: Iterable[str],
    max_length: int = DEFAULT_METADATA_FIELD_LIMIT,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = metadata if isinstance(metadata, dict) else {}
    allowed = {str(field) for field in allowed_fields}
    sanitized: dict[str, Any] = {}
    removed_fields: list[str] = []
    truncated_fields: list[str] = []
    for key, value in sorted(source.items()):
        normalized_key = str(key)
        if normalized_key.lower() in SENSITIVE_METADATA_KEYS:
            removed_fields.append(normalized_key)
            continue
        if normalized_key not in allowed:
            continue
        sanitized_value, truncated = safe_truncate_metadata_value(value, max_length=max_length)
        sanitized[normalized_key] = sanitized_value
        if truncated:
            truncated_fields.append(normalized_key)
    governance = {
        "field_count": len(sanitized),
        "removed_sensitive_field_count": len(removed_fields),
        "removed_sensitive_fields": sorted(removed_fields),
        "truncated_field_count": len(truncated_fields),
        "truncated_fields": sorted(truncated_fields),
        **_governance_fields(),
    }
    return sanitized, governance


def safe_truncate_metadata_value(value: Any, *, max_length: int = DEFAULT_METADATA_FIELD_LIMIT) -> tuple[Any, bool]:
    if isinstance(value, (int, float, bool)) or value is None:
        return value, False
    if isinstance(value, list):
        output = []
        truncated = False
        for item in value[:16]:
            safe, did_truncate = safe_truncate_metadata_value(item, max_length=max_length)
            output.append(safe)
            truncated = truncated or did_truncate
        return output, truncated or len(value) > 16
    text = str(value)
    if len(text) <= max_length:
        return text, False
    return text[:max_length] + "...", True


def deterministic_protocol_fingerprint_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint_evidence(flow: dict[str, Any], protocol: str, metadata_summary: dict[str, Any]) -> list[str]:
    evidence = []
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    service_name = str(service.get("service_name") or "").lower()
    service_port = _safe_port(service.get("service_port"))
    if service_name:
        evidence.append(f"service_name:{service_name}")
    if service_port is not None:
        evidence.append(f"service_port:{service_port}")
    if metadata_summary.get("status") == "ok":
        evidence.append(f"{protocol}_metadata")
    return evidence


def _explicit_protocol(metadata: dict[str, Any]) -> str:
    for key in ("protocol", "application_protocol", "protocol_hint"):
        value = str(metadata.get(key) or "").strip().lower()
        if value:
            return value
    for key in ("http", "tls", "dns"):
        if isinstance(metadata.get(key), dict):
            return key
    return ""


def _safe_port(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _governance_fields() -> dict[str, Any]:
    return {
        **TELEMETRY_SAFETY_FLAGS,
        "credentials_retained": False,
        "payload_contents_retained": False,
        "decryption_performed": False,
        "traffic_injected": False,
        "automatic_blocking": False,
    }


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
