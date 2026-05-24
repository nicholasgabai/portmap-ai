from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


FLOW_RECORD_VERSION = 1
DEFAULT_EPHEMERAL_PORT_MIN = 49152
DEFAULT_PERSISTENT_PACKET_THRESHOLD = 3
DEFAULT_PERSISTENT_BYTE_THRESHOLD = 512

SERVICE_PORTS = {
    22: "ssh",
    53: "dns",
    80: "http",
    123: "ntp",
    443: "https",
    853: "dns-over-tls",
    1883: "mqtt",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
}


class FlowReconstructionError(ValueError):
    """Raised when flow reconstruction inputs are malformed."""


def normalize_flow_key(packet: dict[str, Any]) -> dict[str, Any]:
    """Build a bidirectional flow key from one metadata-only packet record."""
    if not isinstance(packet, dict):
        raise FlowReconstructionError("packet must be an object")
    transport = str(packet.get("transport_protocol") or packet.get("transport") or "unknown").lower()
    source = _endpoint(packet.get("source_ip"), packet.get("source_port"))
    destination = _endpoint(packet.get("destination_ip"), packet.get("destination_port"))
    malformed_reasons = []
    if not source["ip"]:
        malformed_reasons.append("missing source endpoint")
    if not destination["ip"]:
        malformed_reasons.append("missing destination endpoint")
    canonical = sorted([source, destination], key=lambda item: (item["ip"], item["port"] if item["port"] is not None else -1))
    key_material = {
        "transport_protocol": transport,
        "endpoint_a": canonical[0] if canonical else {},
        "endpoint_b": canonical[1] if len(canonical) > 1 else {},
    }
    flow_key = "flow-key-" + _digest(key_material)[:16]
    return {
        "record_type": "flow_key",
        "record_version": FLOW_RECORD_VERSION,
        "flow_key": flow_key,
        "transport_protocol": transport,
        "endpoint_a": key_material["endpoint_a"],
        "endpoint_b": key_material["endpoint_b"],
        "source_endpoint": source,
        "destination_endpoint": destination,
        "malformed_reasons": malformed_reasons,
        **TELEMETRY_SAFETY_FLAGS,
    }


def reconstruct_flow_record(
    *,
    packets: Iterable[dict[str, Any]],
    flow_key: dict[str, Any] | None = None,
    session_index: int = 1,
    timeout_seconds: int = 300,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = sorted([dict(row) for row in packets or [] if isinstance(row, dict)], key=lambda item: (str(item.get("timestamp") or ""), int(item.get("window_sequence") or 0)))
    if not rows:
        raise FlowReconstructionError("flow packets are required")
    key = flow_key or normalize_flow_key(rows[0])
    initiator = _endpoint(rows[0].get("source_ip"), rows[0].get("source_port"))
    responder = _endpoint(rows[0].get("destination_ip"), rows[0].get("destination_port"))
    first_seen = str(rows[0].get("timestamp") or generated_at or _now())
    last_seen = str(rows[-1].get("timestamp") or first_seen)
    transport = str(key.get("transport_protocol") or "unknown")
    forward_count = 0
    reverse_count = 0
    malformed_reasons = list(key.get("malformed_reasons") or [])
    unsupported_count = 0
    total_bytes = 0
    packet_digests = []
    interfaces = set()
    source_nodes = set()
    for row in rows:
        total_bytes += int(row.get("size_bytes") or 0)
        digest = str(row.get("packet_digest") or "")
        if digest:
            packet_digests.append(digest)
        if row.get("interface_name"):
            interfaces.add(str(row.get("interface_name")))
        if row.get("source_node_id"):
            source_nodes.add(str(row.get("source_node_id")))
        classification = str(row.get("classification") or row.get("window_classification") or "")
        if classification == "malformed" or row.get("malformed_reasons"):
            malformed_reasons.extend(str(item) for item in row.get("malformed_reasons") or [])
        if classification == "unsupported" or row.get("unsupported_reasons"):
            unsupported_count += 1
        row_source = _endpoint(row.get("source_ip"), row.get("source_port"))
        row_destination = _endpoint(row.get("destination_ip"), row.get("destination_port"))
        if row_source == initiator and row_destination == responder:
            forward_count += 1
        elif row_source == responder and row_destination == initiator:
            reverse_count += 1
    service = associate_flow_service(transport=transport, initiator=initiator, responder=responder)
    partial_reasons = []
    if reverse_count == 0:
        partial_reasons.append("single_direction_observed")
    if unsupported_count:
        partial_reasons.append("unsupported_packet_metadata_present")
    classification = classify_flow_record(
        packet_count=len(rows),
        byte_count=total_bytes,
        reverse_packet_count=reverse_count,
        malformed_reasons=malformed_reasons,
        partial_reasons=partial_reasons,
    )
    record = {
        "record_type": "bidirectional_flow",
        "record_version": FLOW_RECORD_VERSION,
        "flow_key": str(key.get("flow_key") or ""),
        "session_index": int(session_index),
        "transport_protocol": transport,
        "address_family": _flow_address_family(rows),
        "initiator": initiator,
        "responder": responder,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": _duration_seconds(first_seen, last_seen),
        "timeout_seconds": int(timeout_seconds),
        "packet_count": len(rows),
        "byte_count": total_bytes,
        "forward_packet_count": forward_count,
        "reverse_packet_count": reverse_count,
        "classification": classification,
        "ephemeral_or_persistent": classify_flow_persistence(packet_count=len(rows), byte_count=total_bytes, duration_seconds=_duration_seconds(first_seen, last_seen)),
        "service_association": service,
        "packet_digests": sorted(set(packet_digests)),
        "interface_names": sorted(interfaces),
        "source_node_ids": sorted(source_nodes),
        "malformed_reasons": sorted(set(malformed_reasons)),
        "partial_reasons": sorted(set(partial_reasons)),
        "source_refs": _flow_source_refs(rows),
        "payload_bytes_stored": 0,
        **TELEMETRY_SAFETY_FLAGS,
    }
    digest = flow_digest(record)
    record["flow_digest"] = digest
    record["flow_id"] = "flow-" + digest.removeprefix("sha256:")[:16]
    record["topology_edge"] = flow_to_topology_edge(record)
    return record


def classify_flow_record(
    *,
    packet_count: int,
    byte_count: int,
    reverse_packet_count: int,
    malformed_reasons: Iterable[str] | None = None,
    partial_reasons: Iterable[str] | None = None,
) -> str:
    if list(malformed_reasons or []):
        return "malformed"
    if int(packet_count) <= 0 or int(byte_count) <= 0:
        return "malformed"
    if list(partial_reasons or []) or int(reverse_packet_count) == 0:
        return "partial"
    return "complete"


def classify_flow_persistence(
    *,
    packet_count: int,
    byte_count: int,
    duration_seconds: int,
    persistent_packet_threshold: int = DEFAULT_PERSISTENT_PACKET_THRESHOLD,
    persistent_byte_threshold: int = DEFAULT_PERSISTENT_BYTE_THRESHOLD,
) -> str:
    if int(packet_count) >= persistent_packet_threshold or int(byte_count) >= persistent_byte_threshold or int(duration_seconds) >= 60:
        return "persistent"
    return "ephemeral"


def associate_flow_service(
    *,
    transport: str,
    initiator: dict[str, Any],
    responder: dict[str, Any],
) -> dict[str, Any]:
    source_port = initiator.get("port")
    destination_port = responder.get("port")
    service_port = _service_port(source_port, destination_port)
    service_name = SERVICE_PORTS.get(service_port, "unknown") if service_port is not None else "unknown"
    direction = "responder" if service_port == destination_port else "initiator" if service_port == source_port else "unknown"
    return {
        "record_type": "flow_service_association",
        "transport_protocol": str(transport or "unknown"),
        "service_port": service_port,
        "service_name": service_name,
        "service_endpoint": direction,
        "confidence": 0.9 if service_name != "unknown" else 0.45 if service_port is not None else 0.0,
        **TELEMETRY_SAFETY_FLAGS,
    }


def flow_to_topology_edge(flow: dict[str, Any]) -> dict[str, Any]:
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    initiator = flow.get("initiator") if isinstance(flow.get("initiator"), dict) else {}
    responder = flow.get("responder") if isinstance(flow.get("responder"), dict) else {}
    label_parts = [str(flow.get("transport_protocol") or "unknown")]
    if service.get("service_name") and service.get("service_name") != "unknown":
        label_parts.append(str(service["service_name"]))
    return {
        "record_type": "topology_edge",
        "record_version": FLOW_RECORD_VERSION,
        "edge_id": "edge-" + _digest({"flow_id": flow.get("flow_id"), "src": initiator.get("ip"), "dst": responder.get("ip")})[:16],
        "src": str(initiator.get("ip") or ""),
        "dst": str(responder.get("ip") or ""),
        "source_asset": str(initiator.get("ip") or ""),
        "target_asset": str(responder.get("ip") or ""),
        "relationship_type": "observed_flow",
        "protocol": "/".join(label_parts),
        "flow_count": 1,
        "observation_count": int(flow.get("packet_count") or 0),
        "byte_count": int(flow.get("byte_count") or 0),
        "flow_ref": str(flow.get("flow_id") or ""),
        "source_ref": str(flow.get("flow_id") or ""),
        "confidence": 0.85 if flow.get("classification") == "complete" else 0.6 if flow.get("classification") == "partial" else 0.2,
        **TELEMETRY_SAFETY_FLAGS,
    }


def summarize_flows(flows: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in flows or [] if isinstance(row, dict)]
    return {
        "record_type": "flow_reconstruction_summary",
        "record_version": FLOW_RECORD_VERSION,
        "generated_at": timestamp,
        "flow_count": len(rows),
        "complete_flow_count": sum(1 for row in rows if row.get("classification") == "complete"),
        "partial_flow_count": sum(1 for row in rows if row.get("classification") == "partial"),
        "malformed_flow_count": sum(1 for row in rows if row.get("classification") == "malformed"),
        "ephemeral_flow_count": sum(1 for row in rows if row.get("ephemeral_or_persistent") == "ephemeral"),
        "persistent_flow_count": sum(1 for row in rows if row.get("ephemeral_or_persistent") == "persistent"),
        "packet_count": sum(int(row.get("packet_count") or 0) for row in rows),
        "byte_count": sum(int(row.get("byte_count") or 0) for row in rows),
        "by_transport": _count_by(rows, "transport_protocol"),
        "by_address_family": _count_by(rows, "address_family"),
        "by_service": _count_by_service(rows),
        "topology_edge_count": len([row for row in rows if isinstance(row.get("topology_edge"), dict)]),
        "payload_bytes_stored": 0,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_flow_dashboard_record(*, summary: dict[str, Any], flows: Iterable[dict[str, Any]], generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in flows or [] if isinstance(row, dict)]
    return {
        "record_type": "flow_reconstruction_dashboard",
        "panel": "flow_reconstruction",
        "status": "ok" if int(summary.get("malformed_flow_count") or 0) == 0 else "review_required",
        "generated_at": generated_at or _now(),
        "metrics": {
            "flow_count": int(summary.get("flow_count") or 0),
            "complete_flow_count": int(summary.get("complete_flow_count") or 0),
            "partial_flow_count": int(summary.get("partial_flow_count") or 0),
            "malformed_flow_count": int(summary.get("malformed_flow_count") or 0),
            "topology_edge_count": int(summary.get("topology_edge_count") or 0),
        },
        "rows": [
            {
                "flow_id": row.get("flow_id"),
                "transport_protocol": row.get("transport_protocol"),
                "classification": row.get("classification"),
                "ephemeral_or_persistent": row.get("ephemeral_or_persistent"),
                "packet_count": row.get("packet_count"),
                "byte_count": row.get("byte_count"),
                "service_name": (row.get("service_association") or {}).get("service_name") if isinstance(row.get("service_association"), dict) else "unknown",
            }
            for row in sorted(rows, key=lambda item: str(item.get("flow_id") or ""))
        ],
        "recommended_review": bool(int(summary.get("malformed_flow_count") or 0)),
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_flow_api_response(*, summary: dict[str, Any], flows: Iterable[dict[str, Any]], dashboard: dict[str, Any], generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in flows or [] if isinstance(row, dict)]
    return {
        "record_type": "flow_reconstruction_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "flows": rows,
        "topology_edges": [dict(row["topology_edge"]) for row in rows if isinstance(row.get("topology_edge"), dict)],
        "dashboard": dict(dashboard),
        **TELEMETRY_SAFETY_FLAGS,
    }


def flow_digest(record: dict[str, Any]) -> str:
    material = {
        "flow_key": record.get("flow_key"),
        "session_index": record.get("session_index"),
        "transport_protocol": record.get("transport_protocol"),
        "initiator": record.get("initiator"),
        "responder": record.get("responder"),
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "packet_digests": record.get("packet_digests"),
    }
    return "sha256:" + sha256(deterministic_flow_json(material).encode("utf-8")).hexdigest()


def deterministic_flow_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _endpoint(ip: Any, port: Any) -> dict[str, Any]:
    return {"ip": str(ip or ""), "port": _safe_port(port)}


def _service_port(source_port: Any, destination_port: Any) -> int | None:
    ports = [port for port in (_safe_port(destination_port), _safe_port(source_port)) if port is not None]
    if not ports:
        return None
    known = [port for port in ports if port in SERVICE_PORTS]
    if known:
        return known[0]
    below_ephemeral = [port for port in ports if port < DEFAULT_EPHEMERAL_PORT_MIN]
    if below_ephemeral:
        return min(below_ephemeral)
    return min(ports)


def _flow_address_family(rows: list[dict[str, Any]]) -> str:
    families = {str(row.get("address_family") or "unknown") for row in rows}
    if families == {"ipv4"}:
        return "ipv4"
    if families == {"ipv6"}:
        return "ipv6"
    if families:
        return "mixed"
    return "unknown"


def _flow_source_refs(rows: list[dict[str, Any]]) -> list[str]:
    refs = set()
    for row in rows:
        for ref in row.get("source_refs") or []:
            refs.add(str(ref))
        if row.get("packet_id"):
            refs.add(f"packet:{row['packet_id']}")
    return sorted(refs)


def _duration_seconds(first_seen: str, last_seen: str) -> int:
    try:
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((last - first).total_seconds()))


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


def _count_by_service(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        service = row.get("service_association") if isinstance(row.get("service_association"), dict) else {}
        name = str(service.get("service_name") or "unknown")
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
