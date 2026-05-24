from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.fingerprints import (
    DEFAULT_METADATA_FIELD_LIMIT,
    build_protocol_fingerprint,
    build_service_fingerprint_summary,
    infer_protocol_hint,
    sanitize_metadata_fields,
)
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


PROTOCOL_METADATA_RECORD_VERSION = 1

HTTP_ALLOWED_FIELDS = {"method", "host", "path", "status_code", "header_names", "content_type"}
TLS_ALLOWED_FIELDS = {"tls_version", "record_version", "sni", "alpn", "cipher_family", "handshake_type", "certificate_issuer"}
DNS_ALLOWED_FIELDS = {"query_name", "query_type", "response_code", "answer_count", "opcode"}


class ProtocolMetadataError(ValueError):
    """Raised when protocol metadata input is malformed."""


def extract_protocol_metadata(
    *,
    flow: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    generated_at: str | None = None,
    max_field_length: int = DEFAULT_METADATA_FIELD_LIMIT,
) -> dict[str, Any]:
    if not isinstance(flow, dict):
        raise ProtocolMetadataError("flow must be an object")
    timestamp = generated_at or _now()
    source = metadata if isinstance(metadata, dict) else {}
    hint = infer_protocol_hint(flow, source)
    protocol = str(hint.get("protocol") or "unknown").lower()
    http = extract_http_metadata(source.get("http") if isinstance(source.get("http"), dict) else source if protocol == "http" else {}, generated_at=timestamp, max_field_length=max_field_length)
    tls = extract_tls_metadata(source.get("tls") if isinstance(source.get("tls"), dict) else source if protocol == "tls" else {}, generated_at=timestamp, max_field_length=max_field_length)
    dns = extract_dns_metadata(source.get("dns") if isinstance(source.get("dns"), dict) else source if protocol == "dns" else {}, generated_at=timestamp, max_field_length=max_field_length)
    selected = _selected_metadata_summary(protocol=protocol, http=http, tls=tls, dns=dns)
    fingerprint = build_protocol_fingerprint(flow=flow, protocol=protocol, metadata_summary=selected, generated_at=timestamp)
    anomalies = build_protocol_anomaly_summaries(flow=flow, protocol=protocol, metadata_summary=selected, generated_at=timestamp)
    record = {
        "record_type": "protocol_metadata_record",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "generated_at": timestamp,
        "flow_ref": str(flow.get("flow_id") or ""),
        "protocol": protocol,
        "application_layer_hint": hint,
        "http_metadata": http,
        "tls_metadata": tls,
        "dns_metadata": dns,
        "selected_metadata": selected,
        "protocol_fingerprint": fingerprint,
        "protocol_anomalies": anomalies,
        "confidence": fingerprint["confidence"],
        "metadata_governance": build_metadata_governance_summary([http, tls, dns], generated_at=timestamp),
        **_governance_fields(),
    }
    record["protocol_metadata_id"] = "protocol-metadata-" + _digest(record)[:16]
    return record


def extract_protocol_metadata_report(
    *,
    flows: Iterable[dict[str, Any]],
    metadata_by_flow_id: dict[str, dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_field_length: int = DEFAULT_METADATA_FIELD_LIMIT,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in flows or [] if isinstance(row, dict)]
    metadata_index = metadata_by_flow_id or {}
    records = [
        extract_protocol_metadata(
            flow=flow,
            metadata=metadata_index.get(str(flow.get("flow_id") or ""), {}),
            generated_at=timestamp,
            max_field_length=max_field_length,
        )
        for flow in rows
    ]
    summary = summarize_protocol_metadata(records, generated_at=timestamp)
    dashboard = build_protocol_dashboard_record(summary=summary, records=records, generated_at=timestamp)
    api = build_protocol_api_response(summary=summary, records=records, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "protocol_metadata_report",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "report_id": "protocol-report-" + _digest({"generated_at": timestamp, "records": [row.get("protocol_metadata_id") for row in records]})[:16],
        "generated_at": timestamp,
        "records": records,
        "summary": summary,
        "service_fingerprint_summary": build_service_fingerprint_summary([row["protocol_fingerprint"] for row in records], generated_at=timestamp),
        "dashboard_status": dashboard,
        "api_status": api,
        **_governance_fields(),
    }


def extract_http_metadata(metadata: dict[str, Any] | None, *, generated_at: str | None = None, max_field_length: int = DEFAULT_METADATA_FIELD_LIMIT) -> dict[str, Any]:
    fields, governance = sanitize_metadata_fields(metadata, allowed_fields=HTTP_ALLOWED_FIELDS, max_length=max_field_length)
    if "path" in fields:
        fields["path"] = str(fields["path"]).split("?", 1)[0] or "/"
    if "header_names" in fields:
        fields["header_names"] = sorted(str(item).lower() for item in fields.get("header_names") or [])
    return _metadata_summary(
        protocol="http",
        fields=fields,
        governance=governance,
        generated_at=generated_at,
        evidence=["http_metadata_fields"] if fields else [],
    )


def extract_tls_metadata(metadata: dict[str, Any] | None, *, generated_at: str | None = None, max_field_length: int = DEFAULT_METADATA_FIELD_LIMIT) -> dict[str, Any]:
    fields, governance = sanitize_metadata_fields(metadata, allowed_fields=TLS_ALLOWED_FIELDS, max_length=max_field_length)
    fields["encrypted_session"] = True if fields else False
    fields["decryption_performed"] = False
    return _metadata_summary(
        protocol="tls",
        fields=fields,
        governance=governance,
        generated_at=generated_at,
        evidence=["tls_metadata_fields"] if fields.get("encrypted_session") else [],
    )


def extract_dns_metadata(metadata: dict[str, Any] | None, *, generated_at: str | None = None, max_field_length: int = DEFAULT_METADATA_FIELD_LIMIT) -> dict[str, Any]:
    fields, governance = sanitize_metadata_fields(metadata, allowed_fields=DNS_ALLOWED_FIELDS, max_length=max_field_length)
    return _metadata_summary(
        protocol="dns",
        fields=fields,
        governance=governance,
        generated_at=generated_at,
        evidence=["dns_metadata_fields"] if fields else [],
    )


def build_metadata_governance_summary(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    governance_rows = [dict(row.get("governance") or {}) for row in rows]
    return {
        "record_type": "metadata_governance_summary",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "metadata_record_count": len(rows),
        "removed_sensitive_field_count": sum(int(row.get("removed_sensitive_field_count") or 0) for row in governance_rows),
        "truncated_field_count": sum(int(row.get("truncated_field_count") or 0) for row in governance_rows),
        **_governance_fields(),
    }


def build_protocol_anomaly_summaries(
    *,
    flow: dict[str, Any],
    protocol: str,
    metadata_summary: dict[str, Any],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    anomalies: list[dict[str, Any]] = []
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    service_name = str(service.get("service_name") or "unknown").lower()
    expected = {"https": "tls", "https-alt": "tls", "http": "http", "http-alt": "http", "dns": "dns", "dns-over-tls": "tls"}.get(service_name)
    if expected and expected != protocol:
        anomalies.append(_anomaly("protocol_service_mismatch", "medium", f"Expected {expected} from service association but observed {protocol}.", flow, timestamp))
    if protocol == "tls" and not metadata_summary.get("fields", {}).get("encrypted_session"):
        anomalies.append(_anomaly("encrypted_session_metadata_missing", "low", "TLS was inferred but no encrypted-session metadata fields were present.", flow, timestamp))
    if metadata_summary.get("governance", {}).get("removed_sensitive_field_count"):
        anomalies.append(_anomaly("sensitive_metadata_removed", "low", "Sensitive metadata fields were removed before summary output.", flow, timestamp))
    if metadata_summary.get("governance", {}).get("truncated_field_count"):
        anomalies.append(_anomaly("metadata_truncated", "info", "One or more metadata fields were truncated for safe output.", flow, timestamp))
    return anomalies


def summarize_protocol_metadata(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "protocol_metadata_summary",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_count": len(rows),
        "by_protocol": _count_by(rows, "protocol"),
        "anomaly_count": sum(len(row.get("protocol_anomalies") or []) for row in rows),
        "highest_confidence": round(max((float(row.get("confidence") or 0.0) for row in rows), default=0.0), 3),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "removed_sensitive_field_count": sum(int((row.get("metadata_governance") or {}).get("removed_sensitive_field_count") or 0) for row in rows),
        "truncated_field_count": sum(int((row.get("metadata_governance") or {}).get("truncated_field_count") or 0) for row in rows),
        **_governance_fields(),
    }


def build_protocol_dashboard_record(*, summary: dict[str, Any], records: Iterable[dict[str, Any]], generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "protocol_metadata_dashboard",
        "panel": "protocol_metadata",
        "status": "ok" if int(summary.get("anomaly_count") or 0) == 0 else "review_required",
        "generated_at": generated_at or _now(),
        "metrics": {
            "record_count": int(summary.get("record_count") or 0),
            "anomaly_count": int(summary.get("anomaly_count") or 0),
            "highest_confidence": float(summary.get("highest_confidence") or 0.0),
            "removed_sensitive_field_count": int(summary.get("removed_sensitive_field_count") or 0),
            "truncated_field_count": int(summary.get("truncated_field_count") or 0),
        },
        "rows": [
            {
                "flow_ref": row.get("flow_ref"),
                "protocol": row.get("protocol"),
                "confidence": row.get("confidence"),
                "anomaly_count": len(row.get("protocol_anomalies") or []),
            }
            for row in sorted(rows, key=lambda item: str(item.get("flow_ref") or ""))
        ],
        "recommended_review": bool(int(summary.get("anomaly_count") or 0)),
        **_governance_fields(),
    }


def build_protocol_api_response(*, summary: dict[str, Any], records: Iterable[dict[str, Any]], dashboard: dict[str, Any], generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "protocol_metadata_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "records": rows,
        "dashboard": dict(dashboard),
        **_governance_fields(),
    }


def deterministic_protocol_metadata_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _metadata_summary(
    *,
    protocol: str,
    fields: dict[str, Any],
    governance: dict[str, Any],
    generated_at: str | None,
    evidence: list[str],
) -> dict[str, Any]:
    return {
        "record_type": f"{protocol}_metadata_summary",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "protocol": protocol,
        "status": "ok" if fields else "not_observed",
        "generated_at": generated_at or _now(),
        "fields": dict(fields),
        "field_count": len(fields),
        "evidence": evidence,
        "governance": dict(governance),
        **_governance_fields(),
    }


def _selected_metadata_summary(*, protocol: str, http: dict[str, Any], tls: dict[str, Any], dns: dict[str, Any]) -> dict[str, Any]:
    if protocol == "http":
        return dict(http)
    if protocol == "tls":
        return dict(tls)
    if protocol == "dns":
        return dict(dns)
    return {
        "record_type": "unknown_protocol_metadata_summary",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "protocol": protocol or "unknown",
        "status": "not_observed",
        "fields": {},
        "field_count": 0,
        "evidence": [],
        "governance": _governance_fields(),
        **_governance_fields(),
    }


def _anomaly(kind: str, severity: str, message: str, flow: dict[str, Any], generated_at: str) -> dict[str, Any]:
    record = {
        "record_type": "protocol_anomaly_summary",
        "record_version": PROTOCOL_METADATA_RECORD_VERSION,
        "anomaly_type": kind,
        "severity": severity,
        "message": message,
        "flow_ref": str(flow.get("flow_id") or ""),
        "generated_at": generated_at,
        "recommended_review": severity in {"medium", "high", "critical"},
        **_governance_fields(),
    }
    record["anomaly_id"] = "protocol-anomaly-" + _digest(record)[:16]
    return record


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
