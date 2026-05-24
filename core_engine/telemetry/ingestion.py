from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


PACKET_METADATA_RECORD_VERSION = 1
SUPPORTED_TRANSPORTS = frozenset({"tcp", "udp", "icmp"})
PAYLOAD_FIELD_NAMES = frozenset({"payload", "raw_payload", "raw_bytes", "packet_bytes", "content"})


class PacketIngestionError(ValueError):
    """Raised when packet metadata input cannot be normalized safely."""


def normalize_packet_metadata(
    packet: dict[str, Any],
    *,
    default_interface: str | None = None,
    source_node_id: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Normalize one metadata-only packet record.

    The input may contain payload-like fields from tests or external fixtures;
    those fields are never copied into the returned record.
    """
    if not isinstance(packet, dict):
        raise PacketIngestionError("packet metadata must be an object")
    timestamp = str(packet.get("timestamp") or generated_at or _now())
    interface_name = str(packet.get("interface_name") or packet.get("source_interface") or default_interface or "")
    node_id = str(packet.get("source_node_id") or source_node_id or "local-node")
    source_ip = str(packet.get("source_ip") or packet.get("src_ip") or packet.get("source_address") or "")
    destination_ip = str(packet.get("destination_ip") or packet.get("dst_ip") or packet.get("destination_address") or "")
    source_port = _safe_port(packet.get("source_port", packet.get("src_port")))
    destination_port = _safe_port(packet.get("destination_port", packet.get("dst_port")))
    transport = classify_transport_protocol(packet.get("transport") or packet.get("protocol") or packet.get("ip_protocol"))
    size_bytes, size_warning = _packet_size(packet)
    payload_present = _payload_present(packet)
    source_validation = validate_ip_address(source_ip)
    destination_validation = validate_ip_address(destination_ip)
    address_family = classify_packet_address_family(source_ip, destination_ip)
    malformed_reasons = _malformed_reasons(
        interface_name=interface_name,
        source_validation=source_validation,
        destination_validation=destination_validation,
        size_warning=size_warning,
    )
    unsupported_reasons = [] if transport in SUPPORTED_TRANSPORTS else [f"unsupported transport: {transport}"]
    classification = classify_packet_record(malformed_reasons=malformed_reasons, unsupported_reasons=unsupported_reasons)
    metadata = {
        "record_type": "packet_metadata",
        "record_version": PACKET_METADATA_RECORD_VERSION,
        "timestamp": timestamp,
        "interface_name": interface_name,
        "source_node_id": node_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "address_family": address_family,
        "transport_protocol": transport,
        "size_bytes": size_bytes,
        "classification": classification,
        "malformed_reasons": malformed_reasons,
        "unsupported_reasons": unsupported_reasons,
        "source_refs": _source_refs(interface_name, node_id),
        "packet_sequence": _safe_int(packet.get("packet_sequence", packet.get("sequence")), default=0),
        "payload_present": payload_present,
        "payload_discarded": payload_present,
        "payload_bytes_stored": 0,
        **TELEMETRY_SAFETY_FLAGS,
    }
    digest = packet_metadata_digest(metadata)
    metadata["packet_digest"] = digest
    metadata["packet_id"] = "packet-" + digest.removeprefix("sha256:")[:16]
    return metadata


def normalize_packet_metadata_batch(
    packets: Iterable[dict[str, Any]],
    *,
    default_interface: str | None = None,
    source_node_id: str | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    return [
        normalize_packet_metadata(
            packet,
            default_interface=default_interface,
            source_node_id=source_node_id,
            generated_at=generated_at,
        )
        for packet in packets or []
    ]


def classify_transport_protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"6", "tcp", "ipproto_tcp", "protocol.tcp"}:
        return "tcp"
    if text in {"17", "udp", "ipproto_udp", "protocol.udp"}:
        return "udp"
    if text in {"1", "58", "icmp", "icmpv4", "icmpv6", "ipproto_icmp", "ipproto_icmpv6"}:
        return "icmp"
    if not text:
        return "unknown"
    return text


def validate_ip_address(value: str) -> dict[str, Any]:
    try:
        parsed = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return {"valid": False, "version": "unknown", "reason": "missing" if not value else "invalid"}
    return {
        "valid": True,
        "version": f"ipv{parsed.version}",
        "is_multicast": parsed.is_multicast,
        "is_loopback": parsed.is_loopback,
        "is_link_local": parsed.is_link_local,
        "is_unspecified": parsed.is_unspecified,
    }


def classify_packet_address_family(source_ip: str, destination_ip: str) -> str:
    source = validate_ip_address(source_ip)
    destination = validate_ip_address(destination_ip)
    versions = {item["version"] for item in (source, destination) if item.get("valid")}
    if versions == {"ipv4"}:
        return "ipv4"
    if versions == {"ipv6"}:
        return "ipv6"
    if versions:
        return "mixed"
    return "unknown"


def classify_packet_record(*, malformed_reasons: list[str], unsupported_reasons: list[str]) -> str:
    if malformed_reasons:
        return "malformed"
    if unsupported_reasons:
        return "unsupported"
    return "accepted"


def summarize_packet_metadata_records(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "packet_metadata_summary",
        "record_version": PACKET_METADATA_RECORD_VERSION,
        "generated_at": timestamp,
        "packet_count": len(rows),
        "accepted_count": sum(1 for row in rows if row.get("classification") == "accepted"),
        "malformed_count": sum(1 for row in rows if row.get("classification") == "malformed"),
        "unsupported_count": sum(1 for row in rows if row.get("classification") == "unsupported"),
        "payload_present_count": sum(1 for row in rows if row.get("payload_present")),
        "payload_bytes_stored": 0,
        "by_transport": _count_by(rows, "transport_protocol"),
        "by_address_family": _count_by(rows, "address_family"),
        "by_interface": _count_by(rows, "interface_name"),
        "packet_size_summary": summarize_packet_sizes(rows),
        **TELEMETRY_SAFETY_FLAGS,
    }


def summarize_packet_sizes(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    sizes = [int(row.get("size_bytes") or 0) for row in records or [] if isinstance(row, dict)]
    total = sum(sizes)
    return {
        "record_type": "packet_size_summary",
        "packet_count": len(sizes),
        "total_bytes": total,
        "min_size_bytes": min(sizes) if sizes else 0,
        "max_size_bytes": max(sizes) if sizes else 0,
        "average_size_bytes": round(total / len(sizes), 2) if sizes else 0.0,
        **TELEMETRY_SAFETY_FLAGS,
    }


def packet_metadata_digest(record: dict[str, Any]) -> str:
    material = {
        "timestamp": record.get("timestamp"),
        "interface_name": record.get("interface_name"),
        "source_node_id": record.get("source_node_id"),
        "source_ip": record.get("source_ip"),
        "destination_ip": record.get("destination_ip"),
        "source_port": record.get("source_port"),
        "destination_port": record.get("destination_port"),
        "address_family": record.get("address_family"),
        "transport_protocol": record.get("transport_protocol"),
        "size_bytes": record.get("size_bytes"),
        "packet_sequence": record.get("packet_sequence"),
    }
    return "sha256:" + sha256(deterministic_packet_metadata_json(material).encode("utf-8")).hexdigest()


def deterministic_packet_metadata_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _packet_size(packet: dict[str, Any]) -> tuple[int, str | None]:
    raw_size = packet.get("size_bytes", packet.get("packet_size", packet.get("length", packet.get("len", 0))))
    try:
        size = int(raw_size or 0)
    except (TypeError, ValueError):
        return 0, "packet size is not an integer"
    if size < 0:
        return 0, "packet size cannot be negative"
    return size, None


def _payload_present(packet: dict[str, Any]) -> bool:
    for name in PAYLOAD_FIELD_NAMES:
        if name not in packet:
            continue
        value = packet.get(name)
        if value is None or value == "" or value == b"":
            continue
        return True
    return False


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


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _malformed_reasons(
    *,
    interface_name: str,
    source_validation: dict[str, Any],
    destination_validation: dict[str, Any],
    size_warning: str | None,
) -> list[str]:
    reasons: list[str] = []
    if not interface_name:
        reasons.append("missing interface attribution")
    if not source_validation.get("valid"):
        reasons.append(f"source IP {source_validation.get('reason')}")
    if not destination_validation.get("valid"):
        reasons.append(f"destination IP {destination_validation.get('reason')}")
    if size_warning:
        reasons.append(size_warning)
    return reasons


def _source_refs(interface_name: str, source_node_id: str) -> list[str]:
    refs = []
    if source_node_id:
        refs.append(f"node:{source_node_id}")
    if interface_name:
        refs.append(f"interface:{interface_name}")
    return refs


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _now() -> str:
    return datetime.now(UTC).isoformat()
