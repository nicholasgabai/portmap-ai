from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.fingerprints import DEFAULT_METADATA_FIELD_LIMIT
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


DNS_VISIBILITY_RECORD_VERSION = 1
DEFAULT_DOMAIN_LABEL_LIMIT = 63
DEFAULT_DOMAIN_TOTAL_LIMIT = 120
DNS_ERROR_CODES = {"NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "YXDOMAIN"}

DNS_VISIBILITY_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "metadata_only": True,
    "raw_payload_rendered": False,
    "payload_bytes_stored": 0,
    "credentials_retained": False,
    "content_retained": False,
    "traffic_interception": False,
    "dns_settings_modified": False,
    "automatic_blocking": False,
}


def build_dns_query_record(
    record: dict[str, Any],
    *,
    generated_at: str | None = None,
    max_domain_length: int = DEFAULT_DOMAIN_TOTAL_LIMIT,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    query_name, governance = sanitize_domain_name(record.get("query_name") or record.get("domain"), max_length=max_domain_length)
    row = {
        "record_type": "dns_query_metadata",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "generated_at": timestamp,
        "query_id": str(record.get("query_id") or _stable_query_id(record)),
        "query_name": query_name,
        "query_type": str(record.get("query_type") or "A").upper(),
        "timestamp": str(record.get("timestamp") or timestamp),
        "client_ref": str(record.get("client_ref") or record.get("source_ref") or ""),
        "resolver_ip": str(record.get("resolver_ip") or record.get("destination_ip") or ""),
        "transport_protocol": str(record.get("transport_protocol") or record.get("transport") or "udp").lower(),
        "flow_ref": str(record.get("flow_ref") or ""),
        "source_refs": sorted(str(item) for item in record.get("source_refs") or []),
        "domain_governance": governance,
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }
    row["query_record_id"] = "dns-query-" + _digest(row)[:16]
    return row


def build_dns_response_record(
    record: dict[str, Any],
    *,
    generated_at: str | None = None,
    max_domain_length: int = DEFAULT_DOMAIN_TOTAL_LIMIT,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    query_name, governance = sanitize_domain_name(record.get("query_name") or record.get("domain"), max_length=max_domain_length)
    response_code = str(record.get("response_code") or record.get("rcode") or "UNKNOWN").upper()
    answers = [
        normalize_dns_answer(item, max_domain_length=max_domain_length)
        for item in record.get("answers") or []
        if isinstance(item, dict)
    ]
    row = {
        "record_type": "dns_response_metadata",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "generated_at": timestamp,
        "query_id": str(record.get("query_id") or _stable_query_id(record)),
        "query_name": query_name,
        "query_type": str(record.get("query_type") or "A").upper(),
        "timestamp": str(record.get("timestamp") or timestamp),
        "resolver_ip": str(record.get("resolver_ip") or record.get("source_ip") or ""),
        "response_code": response_code,
        "answer_count": int(record.get("answer_count") if record.get("answer_count") is not None else len(answers)),
        "answers": answers,
        "error": response_code in DNS_ERROR_CODES,
        "nxdomain": response_code == "NXDOMAIN",
        "flow_ref": str(record.get("flow_ref") or ""),
        "source_refs": sorted(str(item) for item in record.get("source_refs") or []),
        "domain_governance": governance,
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }
    row["response_record_id"] = "dns-response-" + _digest(row)[:16]
    return row


def normalize_dns_answer(answer: dict[str, Any], *, max_domain_length: int = DEFAULT_DOMAIN_TOTAL_LIMIT) -> dict[str, Any]:
    value = str(answer.get("value") or answer.get("address") or answer.get("target") or "")
    if str(answer.get("answer_type") or answer.get("type") or "").upper() in {"CNAME", "PTR", "NS"}:
        value, governance = sanitize_domain_name(value, max_length=max_domain_length)
    else:
        value, governance = safe_dns_text(value, max_length=max_domain_length)
    return {
        "answer_type": str(answer.get("answer_type") or answer.get("type") or "A").upper(),
        "value": value,
        "ttl": _safe_int(answer.get("ttl")),
        "redacted": bool(governance.get("redacted")),
        "truncated": bool(governance.get("truncated")),
    }


def classify_resolver(query: dict[str, Any] | None = None, response: dict[str, Any] | None = None) -> dict[str, Any]:
    row = query if isinstance(query, dict) else response if isinstance(response, dict) else {}
    resolver_ip = str(row.get("resolver_ip") or "")
    transport = str(row.get("transport_protocol") or row.get("transport") or "udp").lower()
    resolver_type = "unknown"
    if resolver_ip in {"", "0.0.0.0", "::"}:
        resolver_type = "unknown"
    elif resolver_ip.startswith("203.0.113.") or resolver_ip.startswith("2001:db8:100:"):
        resolver_type = "local"
    elif transport in {"tls", "https", "doh", "dot"}:
        resolver_type = "encrypted"
    else:
        resolver_type = "remote"
    return {
        "record_type": "dns_resolver_classification",
        "resolver_ip": resolver_ip,
        "transport_protocol": transport,
        "resolver_type": resolver_type,
        "encrypted_dns_likely": resolver_type == "encrypted" or transport in {"tls", "https", "doh", "dot"},
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def build_dns_timing_summary(
    *,
    query: dict[str, Any] | None,
    response: dict[str, Any] | None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    query_ts = str((query or {}).get("timestamp") or "")
    response_ts = str((response or {}).get("timestamp") or "")
    return {
        "record_type": "dns_timing_summary",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "query_timestamp": query_ts,
        "response_timestamp": response_ts,
        "response_time_ms": _duration_ms(query_ts, response_ts),
        "response_observed": bool(response),
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def build_encrypted_dns_limitation_summary(
    *,
    encrypted_flow_count: int = 0,
    encrypted_dns_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    records = [dict(row) for row in encrypted_dns_records or [] if isinstance(row, dict)]
    count = int(encrypted_flow_count) + len(records)
    return {
        "record_type": "encrypted_dns_visibility_limitations",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "encrypted_dns_indicator_count": count,
        "visibility_limited": count > 0,
        "limitations": ["encrypted_dns_metadata_only"] if count > 0 else [],
        "decryption_performed": False,
        "interception_performed": False,
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def build_dns_anomaly_hints(
    *,
    query: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    timing: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    hints = []
    response_code = str((response or {}).get("response_code") or "")
    if response_code in DNS_ERROR_CODES:
        hints.append(_hint("dns_response_error", "medium" if response_code == "NXDOMAIN" else "low", f"DNS response code {response_code} observed.", query, response, timestamp))
    if response and int(response.get("answer_count") or 0) == 0 and response_code == "NOERROR":
        hints.append(_hint("empty_noerror_response", "low", "NOERROR response contained no answers.", query, response, timestamp))
    if timing and not timing.get("response_observed"):
        hints.append(_hint("dns_response_missing", "low", "DNS query did not have a paired response in the provided window.", query, response, timestamp))
    if timing and int(timing.get("response_time_ms") or 0) > 1000:
        hints.append(_hint("slow_dns_response", "low", "DNS response time exceeded the local advisory threshold.", query, response, timestamp))
    return hints


def summarize_dns_visibility_records(
    *,
    queries: Iterable[dict[str, Any]],
    responses: Iterable[dict[str, Any]],
    correlations: Iterable[dict[str, Any]] | None = None,
    encrypted_limitations: dict[str, Any] | None = None,
    anomaly_hints: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    query_rows = [dict(row) for row in queries or [] if isinstance(row, dict)]
    response_rows = [dict(row) for row in responses or [] if isinstance(row, dict)]
    correlation_rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    hint_rows = [dict(row) for row in anomaly_hints or [] if isinstance(row, dict)]
    return {
        "record_type": "dns_visibility_summary",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "query_count": len(query_rows),
        "response_count": len(response_rows),
        "correlated_flow_count": sum(1 for row in correlation_rows if row.get("status") == "matched"),
        "nxdomain_count": sum(1 for row in response_rows if row.get("nxdomain")),
        "error_response_count": sum(1 for row in response_rows if row.get("error")),
        "anomaly_hint_count": len(hint_rows),
        "truncated_domain_count": sum(1 for row in [*query_rows, *response_rows] if (row.get("domain_governance") or {}).get("truncated")),
        "redacted_domain_count": sum(1 for row in [*query_rows, *response_rows] if (row.get("domain_governance") or {}).get("redacted")),
        "encrypted_dns_visibility_limited": bool((encrypted_limitations or {}).get("visibility_limited")),
        "by_query_type": _count_by(query_rows, "query_type"),
        "by_response_code": _count_by(response_rows, "response_code"),
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def build_dns_visibility_dashboard_record(
    *,
    summary: dict[str, Any],
    queries: Iterable[dict[str, Any]],
    responses: Iterable[dict[str, Any]],
    anomaly_hints: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    query_rows = [dict(row) for row in queries or [] if isinstance(row, dict)]
    response_rows = [dict(row) for row in responses or [] if isinstance(row, dict)]
    hints = [dict(row) for row in anomaly_hints or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("anomaly_hint_count") or 0) else "ok"
    return {
        "record_type": "dns_visibility_dashboard",
        "panel": "dns_visibility",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "query_count": int(summary.get("query_count") or 0),
            "response_count": int(summary.get("response_count") or 0),
            "correlated_flow_count": int(summary.get("correlated_flow_count") or 0),
            "nxdomain_count": int(summary.get("nxdomain_count") or 0),
            "anomaly_hint_count": int(summary.get("anomaly_hint_count") or 0),
        },
        "by_query_type": dict(summary.get("by_query_type") or {}),
        "by_response_code": dict(summary.get("by_response_code") or {}),
        "rows": [
            {
                "query_id": row.get("query_id"),
                "query_name": row.get("query_name"),
                "query_type": row.get("query_type"),
                "response_code": _response_code_for_query(row, response_rows),
            }
            for row in sorted(query_rows, key=lambda item: (str(item.get("timestamp") or ""), str(item.get("query_id") or "")))
        ],
        "anomaly_rows": [
            {
                "hint_type": row.get("hint_type"),
                "severity": row.get("severity"),
                "query_ref": row.get("query_ref"),
            }
            for row in sorted(hints, key=lambda item: str(item.get("hint_id") or ""))
        ],
        "recommended_review": status == "review_required",
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def build_dns_visibility_api_response(
    *,
    summary: dict[str, Any],
    queries: Iterable[dict[str, Any]],
    responses: Iterable[dict[str, Any]],
    correlations: Iterable[dict[str, Any]],
    timing_summaries: Iterable[dict[str, Any]],
    encrypted_limitations: dict[str, Any],
    anomaly_hints: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "dns_visibility_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "queries": [dict(row) for row in queries or [] if isinstance(row, dict)],
        "responses": [dict(row) for row in responses or [] if isinstance(row, dict)],
        "correlations": [dict(row) for row in correlations or [] if isinstance(row, dict)],
        "timing_summaries": [dict(row) for row in timing_summaries or [] if isinstance(row, dict)],
        "encrypted_limitations": dict(encrypted_limitations),
        "anomaly_hints": [dict(row) for row in anomaly_hints or [] if isinstance(row, dict)],
        "dashboard": dict(dashboard),
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def sanitize_domain_name(value: Any, *, max_length: int = DEFAULT_DOMAIN_TOTAL_LIMIT) -> tuple[str, dict[str, Any]]:
    text = str(value or "").strip().lower().rstrip(".")
    redacted = False
    if not text:
        return "", _domain_governance(redacted=False, truncated=False)
    labels = []
    for label in text.split("."):
        safe = "".join(ch for ch in label if ch.isalnum() or ch == "-")
        if safe != label:
            redacted = True
        if not safe:
            safe = "redacted"
            redacted = True
        if len(safe) > DEFAULT_DOMAIN_LABEL_LIMIT:
            safe = safe[:DEFAULT_DOMAIN_LABEL_LIMIT]
            redacted = True
        labels.append(safe)
    sanitized = ".".join(labels)
    truncated = len(sanitized) > max_length
    if truncated:
        sanitized = sanitized[:max_length] + "..."
    return sanitized, _domain_governance(redacted=redacted, truncated=truncated)


def safe_dns_text(value: Any, *, max_length: int = DEFAULT_METADATA_FIELD_LIMIT) -> tuple[str, dict[str, Any]]:
    text = str(value or "")
    truncated = len(text) > max_length
    return (text[:max_length] + "..." if truncated else text), _domain_governance(redacted=False, truncated=truncated)


def deterministic_dns_visibility_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _response_code_for_query(query: dict[str, Any], responses: list[dict[str, Any]]) -> str:
    query_id = str(query.get("query_id") or "")
    for response in responses:
        if str(response.get("query_id") or "") == query_id:
            return str(response.get("response_code") or "UNKNOWN")
    return "UNOBSERVED"


def _hint(kind: str, severity: str, explanation: str, query: dict[str, Any] | None, response: dict[str, Any] | None, generated_at: str) -> dict[str, Any]:
    record = {
        "record_type": "dns_anomaly_hint",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "generated_at": generated_at,
        "hint_type": kind,
        "severity": severity,
        "explanation": explanation,
        "query_ref": str((query or {}).get("query_record_id") or ""),
        "response_ref": str((response or {}).get("response_record_id") or ""),
        "source_refs": sorted(set([*((query or {}).get("source_refs") or []), *((response or {}).get("source_refs") or [])])),
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }
    record["hint_id"] = "dns-hint-" + _digest(record)[:16]
    return record


def _domain_governance(*, redacted: bool, truncated: bool) -> dict[str, Any]:
    return {
        "redacted": redacted,
        "truncated": truncated,
        "raw_domain_stored": False,
        "safe_domain_output": True,
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def _stable_query_id(record: dict[str, Any]) -> str:
    return "query-" + _digest({"query_name": record.get("query_name") or record.get("domain"), "timestamp": record.get("timestamp"), "type": record.get("query_type")})[:12]


def _duration_ms(start: str, end: str) -> int:
    if not start or not end:
        return 0
    try:
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        last = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((last - first).total_seconds() * 1000))


def _safe_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer >= 0 else None


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
