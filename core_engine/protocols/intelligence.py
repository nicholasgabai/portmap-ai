"""Deterministic protocol intelligence from packet metadata only."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List

from core_engine.capture import PacketMetadata


PROTOCOL_PORTS = {
    22: "ssh",
    53: "dns",
    80: "http",
    139: "smb",
    443: "https",
    445: "smb",
    8080: "http",
    8443: "https",
}

PAYLOAD_FIELD_NAMES = {
    "payload",
    "payload_body",
    "payload_bytes",
    "raw_packet",
    "raw_bytes",
    "packet_bytes",
    "body",
    "content",
}


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _stable_id(prefix: str, value: Any, *, length: int = 16) -> str:
    digest = hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"


def _safe_text(value: Any, default: str = "-") -> str:
    text = " ".join(str(value or "").replace("\n", " ").replace("\r", " ").split())
    return text or default


def _safe_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): item
        for key, item in sorted(value.items())
        if str(key).lower() not in PAYLOAD_FIELD_NAMES
        and (isinstance(item, (str, int, float, bool)) or item is None)
    }


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


@dataclass(frozen=True)
class ProtocolRecord:
    protocol_id: str
    packet_id: str
    session_id: str
    flow_key: str
    protocol: str
    protocol_family: str
    application_protocol: str
    transport_protocol: str
    confidence: float
    detection_method: str
    evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    observed_at: str = "-"
    src_ip: str = "-"
    dst_ip: str = "-"
    src_port: int = 0
    dst_port: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_id": self.protocol_id,
            "packet_id": self.packet_id,
            "session_id": self.session_id,
            "flow_key": self.flow_key,
            "protocol": self.protocol,
            "protocol_family": self.protocol_family,
            "application_protocol": self.application_protocol,
            "transport_protocol": self.transport_protocol,
            "confidence": round(float(self.confidence), 3),
            "detection_method": self.detection_method,
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
            "observed_at": self.observed_at,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "metadata": _safe_metadata(self.metadata),
        }


@dataclass(frozen=True)
class ConversationSummary:
    conversation_id: str
    flow_key: str
    protocol: str
    packet_count: int
    byte_count: int
    first_observed: str
    last_observed: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    direction: str
    confidence: float
    evidence_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "flow_key": self.flow_key,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_observed": self.first_observed,
            "last_observed": self.last_observed,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "direction": self.direction,
            "confidence": round(float(self.confidence), 3),
            "evidence_summary": self.evidence_summary,
        }


def classify_packet_protocol(packet: PacketMetadata | Dict[str, Any]) -> ProtocolRecord:
    metadata = PacketMetadata.from_dict(packet)
    protocol_field = _safe_text(metadata.protocol).lower()
    tags = {str(tag).lower() for tag in metadata.tags}
    evidence: list[str] = []
    limitations: list[str] = ["metadata_only_no_payload_inspection"]

    transport = "-"
    protocol = "unknown"
    family = "unknown"
    app = "-"
    confidence = 0.2
    method = "unknown_fallback"

    ether_type = _safe_text(metadata.ether_type).lower()
    if protocol_field == "arp" or ether_type in {"0x0806", "0806", "2054"}:
        protocol, family, app, transport = "arp", "arp", "-", "-"
        confidence, method = 0.86, "ether_type"
        evidence.append("ether_type:arp")
    elif protocol_field in {"icmp", "icmpv6"}:
        protocol, family, app, transport = "icmp", "icmp", "-", protocol_field
        confidence, method = 0.82, "protocol_field"
        evidence.append(f"protocol:{protocol_field}")
    else:
        if protocol_field in {"tcp", "udp"}:
            transport = protocol_field
            protocol = protocol_field
            family = protocol_field
            confidence = 0.72
            method = "protocol_field"
            evidence.append(f"protocol:{protocol_field}")
        elif metadata.ip_version == 4 or ether_type in {"0x0800", "0800", "2048"}:
            protocol, family = "ipv4", "ipv4"
            confidence, method = 0.55, "ip_version"
            evidence.append("ip_version:4")
        elif metadata.ip_version == 6 or ether_type in {"0x86dd", "86dd", "34525"}:
            protocol, family = "ipv6", "ipv6"
            confidence, method = 0.55, "ip_version"
            evidence.append("ip_version:6")
        elif metadata.link_type == "ethernet" and (metadata.eth_src != "-" or metadata.eth_dst != "-"):
            protocol, family = "ethernet", "ethernet"
            confidence, method = 0.45, "link_metadata"
            evidence.append("link_type:ethernet")

        app_candidate = _application_protocol_from_metadata(metadata, tags)
        if app_candidate != "-":
            app = app_candidate
            protocol = app_candidate
            family = app_candidate
            confidence = 0.84 if method == "protocol_field" else 0.78
            method = "port_and_metadata" if transport != "-" else "port_metadata"
            evidence.extend(_application_evidence(metadata, app_candidate, tags))

    evidence = sorted(set(evidence)) or ["insufficient_metadata"]
    limitations = sorted(set(limitations))
    record_basis = {
        "packet_id": metadata.packet_id,
        "flow_key": metadata.flow_key,
        "protocol": protocol,
        "evidence": evidence,
    }
    return ProtocolRecord(
        protocol_id=_stable_id("protocol", record_basis),
        packet_id=metadata.packet_id,
        session_id=metadata.session_id,
        flow_key=metadata.flow_key,
        protocol=protocol,
        protocol_family=family,
        application_protocol=app,
        transport_protocol=transport,
        confidence=max(0.0, min(1.0, confidence)),
        detection_method=method,
        evidence=evidence,
        limitations=limitations,
        observed_at=metadata.observed_at,
        src_ip=metadata.src_ip,
        dst_ip=metadata.dst_ip,
        src_port=metadata.src_port,
        dst_port=metadata.dst_port,
        metadata={
            "ip_version": metadata.ip_version,
            "ether_type": metadata.ether_type,
            "tcp_flags": ",".join(metadata.tcp_flags) if metadata.tcp_flags else "-",
            **_safe_metadata(metadata.metadata),
        },
    )


def classify_packets(packets: Iterable[PacketMetadata | Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = [classify_packet_protocol(packet).to_dict() for packet in packets]
    return sorted(records, key=lambda row: (row["observed_at"], row["flow_key"], row["packet_id"]))


def summarize_conversations(packets: Iterable[PacketMetadata | Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = [PacketMetadata.from_dict(packet) for packet in packets]
    if not normalized:
        return []
    records = {record["packet_id"]: record for record in classify_packets(normalized)}
    groups: dict[str, list[PacketMetadata]] = defaultdict(list)
    for packet in normalized:
        groups[packet.flow_key].append(packet)

    summaries: list[ConversationSummary] = []
    for flow_key in sorted(groups):
        group = sorted(groups[flow_key], key=lambda item: (item.observed_at, item.packet_id))
        first = group[0]
        observed = [_parse_time(packet.observed_at) for packet in group]
        observed = [value for value in observed if value is not None]
        first_observed = min(observed).isoformat() if observed else "-"
        last_observed = max(observed).isoformat() if observed else "-"
        group_records = [records[packet.packet_id] for packet in group]
        protocol = _dominant_protocol(group_records)
        confidence = sum(float(record["confidence"]) for record in group_records) / len(group_records)
        evidence = sorted({item for record in group_records for item in record["evidence"]})
        summaries.append(
            ConversationSummary(
                conversation_id=_stable_id("conversation", {"flow_key": flow_key, "protocol": protocol}),
                flow_key=flow_key,
                protocol=protocol,
                packet_count=len(group),
                byte_count=sum(packet.length for packet in group),
                first_observed=first_observed,
                last_observed=last_observed,
                src_ip=first.src_ip,
                dst_ip=first.dst_ip,
                src_port=first.src_port,
                dst_port=first.dst_port,
                direction=first.direction,
                confidence=max(0.0, min(1.0, confidence)),
                evidence_summary=", ".join(evidence[:5]) if evidence else "insufficient_metadata",
            )
        )
    return [summary.to_dict() for summary in summaries]


def protocol_intelligence_summary(packets: Iterable[PacketMetadata | Dict[str, Any]]) -> Dict[str, Any]:
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    return {
        "protocol_record_count": len(records),
        "conversation_count": len(conversations),
        "protocols": sorted({record["protocol"] for record in records}),
        "records": records,
        "conversations": conversations,
    }


def _application_protocol_from_metadata(metadata: PacketMetadata, tags: set[str]) -> str:
    if "tls" in tags:
        return "tls"
    if "https" in tags:
        return "https"
    ports = [metadata.dst_port, metadata.src_port]
    for port in ports:
        if port in PROTOCOL_PORTS:
            return PROTOCOL_PORTS[port]
    return "-"


def _application_evidence(metadata: PacketMetadata, app: str, tags: set[str]) -> List[str]:
    evidence = []
    if app in tags:
        evidence.append(f"tag:{app}")
    for port in (metadata.src_port, metadata.dst_port):
        if PROTOCOL_PORTS.get(port) == app:
            evidence.append(f"port:{port}")
    if metadata.protocol != "-":
        evidence.append(f"transport:{metadata.protocol.lower()}")
    return evidence


def _dominant_protocol(records: List[Dict[str, Any]]) -> str:
    ranked = sorted(
        records,
        key=lambda row: (-float(row["confidence"]), row["protocol"], row["protocol_id"]),
    )
    return ranked[0]["protocol"] if ranked else "unknown"


__all__ = [
    "ConversationSummary",
    "ProtocolRecord",
    "classify_packet_protocol",
    "classify_packets",
    "protocol_intelligence_summary",
    "summarize_conversations",
]
