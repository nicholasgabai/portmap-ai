from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.gateway.router_logs import (
    GATEWAY_LOG_RECORD_VERSION,
    GATEWAY_LOG_SAFETY_FLAGS,
    build_gateway_log_ingestion_report,
    malformed_gateway_log_record,
    normalize_gateway_log_record,
)


SYSLOG_PREFIX = re.compile(r"^(?P<timestamp>\S+T\S+|\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<device>\S+)\s+(?P<body>.*)$")
KEY_VALUE = re.compile(r"(?P<key>[A-Za-z_]+)=(?P<value>\"[^\"]*\"|\S+)")


def parse_gateway_log_lines(
    lines: Iterable[str],
    *,
    source_device_ref: str = "gateway-placeholder",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    records = []
    for index, line in enumerate(lines or [], start=1):
        parsed = parse_gateway_log_line(line, line_number=index, source_device_ref=source_device_ref, generated_at=timestamp)
        records.append(parsed)
    return build_gateway_log_ingestion_report(records, generated_at=timestamp)


def parse_gateway_log_line(
    line: str,
    *,
    line_number: int = 1,
    source_device_ref: str = "gateway-placeholder",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    text = str(line or "").strip()
    if not text:
        return malformed_gateway_log_record(line_ref=f"line:{line_number}", reason="empty log line", generated_at=timestamp)
    syslog = SYSLOG_PREFIX.match(text)
    device = source_device_ref
    body = text
    observed_ts = timestamp
    if syslog:
        observed_ts = _normalize_syslog_timestamp(syslog.group("timestamp"), fallback=timestamp)
        device = syslog.group("device") or source_device_ref
        body = syslog.group("body")
    fields = _parse_key_value_fields(body)
    if not fields:
        return malformed_gateway_log_record(line_ref=f"line:{line_number}", reason="no key/value fields found", generated_at=timestamp)
    mapped = map_gateway_log_fields(fields)
    mapped.update(
        {
            "timestamp": mapped.get("timestamp") or observed_ts,
            "source_device_ref": source_device_ref or device,
            "device": device,
            "source_refs": [f"line:{line_number}"],
            "parse_warnings": _parse_warnings(fields, mapped),
        }
    )
    return normalize_gateway_log_record(mapped, generated_at=timestamp)


def map_gateway_log_fields(fields: dict[str, str]) -> dict[str, Any]:
    lower = {str(key).lower(): value for key, value in fields.items()}
    return {
        "timestamp": lower.get("timestamp") or lower.get("time"),
        "action": lower.get("action") or lower.get("act") or lower.get("policy"),
        "event_type": lower.get("event") or lower.get("type") or "traffic",
        "protocol": lower.get("proto") or lower.get("protocol"),
        "source_ip": lower.get("src") or lower.get("src_ip") or lower.get("source"),
        "source_port": lower.get("spt") or lower.get("src_port") or lower.get("sport"),
        "destination_ip": lower.get("dst") or lower.get("dst_ip") or lower.get("destination"),
        "destination_port": lower.get("dpt") or lower.get("dst_port") or lower.get("dport"),
        "translated_source_ip": lower.get("nat_src") or lower.get("snat") or lower.get("translated_src"),
        "translated_source_port": lower.get("nat_spt") or lower.get("translated_sport"),
        "translated_destination_ip": lower.get("nat_dst") or lower.get("dnat") or lower.get("translated_dst"),
        "translated_destination_port": lower.get("nat_dpt") or lower.get("translated_dport"),
        "nat_event": _truthy(lower.get("nat")) or any(key in lower for key in {"nat_src", "snat", "nat_dst", "dnat"}),
    }


def _parse_key_value_fields(body: str) -> dict[str, str]:
    fields = {}
    for match in KEY_VALUE.finditer(body):
        value = match.group("value").strip('"')
        fields[match.group("key")] = value
    return fields


def _parse_warnings(fields: dict[str, str], mapped: dict[str, Any]) -> list[str]:
    warnings = []
    if not mapped.get("source_ip"):
        warnings.append("missing_source_ip")
    if not mapped.get("destination_ip"):
        warnings.append("missing_destination_ip")
    if not mapped.get("action"):
        warnings.append("missing_action")
    if not mapped.get("protocol"):
        warnings.append("missing_protocol")
    unknown = sorted(set(key.lower() for key in fields) - _known_field_names())
    if unknown:
        warnings.append("ignored_fields:" + ",".join(unknown[:8]))
    return warnings


def _known_field_names() -> set[str]:
    return {
        "timestamp",
        "time",
        "action",
        "act",
        "policy",
        "event",
        "type",
        "proto",
        "protocol",
        "src",
        "src_ip",
        "source",
        "spt",
        "src_port",
        "sport",
        "dst",
        "dst_ip",
        "destination",
        "dpt",
        "dst_port",
        "dport",
        "nat",
        "nat_src",
        "snat",
        "translated_src",
        "nat_spt",
        "translated_sport",
        "nat_dst",
        "dnat",
        "translated_dst",
        "nat_dpt",
        "translated_dport",
    }


def _normalize_syslog_timestamp(value: str, *, fallback: str) -> str:
    text = str(value or "")
    if "T" in text:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return fallback
    try:
        now = datetime.fromisoformat(fallback.replace("Z", "+00:00"))
        parsed = datetime.strptime(f"{now.year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
        return parsed.isoformat()
    except ValueError:
        return fallback


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "nat"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "GATEWAY_LOG_RECORD_VERSION",
    "GATEWAY_LOG_SAFETY_FLAGS",
    "map_gateway_log_fields",
    "parse_gateway_log_line",
    "parse_gateway_log_lines",
]
