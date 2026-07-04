"""Correlation helpers for packet intelligence integration."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List

from .models import safe_float, safe_int, safe_metadata, safe_text


SENSITIVE_PORTS = {22, 53, 80, 139, 443, 445, 3389, 5432, 6379, 9200}
KNOWN_PROTOCOL_HINTS = {
    "dns": "likely_dns",
    "http": "likely_http",
    "https": "likely_https",
    "tls": "likely_https",
    "ssh": "likely_ssh",
    "smb": "likely_smb",
}
KNOWN_SERVICE_CANDIDATES = {
    "dns": "dns",
    "http": "http_service",
    "https": "https_service",
    "tls": "https_service",
    "ssh": "ssh",
    "smb": "smb",
}


def derive_attribution_hints(
    protocol_records: Iterable[Dict[str, Any]],
    conversations: Iterable[Dict[str, Any]],
) -> List[str]:
    records = [safe_metadata(dict(row or {})) for row in protocol_records]
    conversation_rows = [safe_metadata(dict(row or {})) for row in conversations]
    hints: set[str] = set()
    for row in records:
        protocol = safe_text(row.get("protocol"), "unknown").lower()
        hints.add(KNOWN_PROTOCOL_HINTS.get(protocol, "unknown_application_protocol" if protocol == "unknown" else f"likely_{protocol}"))
        method = safe_text(row.get("detection_method")).lower()
        evidence = [safe_text(item).lower() for item in row.get("evidence") or []]
        if "port" in method or any(item.startswith("port:") for item in evidence):
            hints.add("protocol_by_port")
        if "metadata" in method or any(item.startswith("tag:") for item in evidence):
            hints.add("protocol_by_metadata_tag")
    flow_counts = Counter(safe_text(row.get("flow_key")) for row in conversation_rows if safe_text(row.get("flow_key")) != "-")
    if any(count > 1 for count in flow_counts.values()) or any(safe_int(row.get("packet_count")) > 1 for row in conversation_rows):
        hints.add("repeated_flow_observation")
    return sorted(hints)


def derive_service_candidates(
    protocol_records: Iterable[Dict[str, Any]],
    conversations: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    records = [safe_metadata(dict(row or {})) for row in protocol_records]
    conversation_rows = [safe_metadata(dict(row or {})) for row in conversations]
    by_service: dict[str, dict[str, Any]] = {}
    for row in [*records, *conversation_rows]:
        protocol = safe_text(row.get("application_protocol") or row.get("protocol"), "unknown").lower()
        service = KNOWN_SERVICE_CANDIDATES.get(protocol)
        if not service:
            for port in (safe_int(row.get("src_port")), safe_int(row.get("dst_port"))):
                if port == 53:
                    service = "dns"
                elif port == 22:
                    service = "ssh"
                elif port == 80:
                    service = "http_service"
                elif port == 443:
                    service = "https_service"
                if service:
                    break
        if not service:
            continue
        item = by_service.setdefault(
            service,
            {
                "service_candidate": service,
                "protocols": set(),
                "ports": set(),
                "flow_keys": set(),
                "evidence": set(),
            },
        )
        if protocol != "unknown":
            item["protocols"].add(protocol)
            item["evidence"].add(f"protocol:{protocol}")
        for port in (safe_int(row.get("src_port")), safe_int(row.get("dst_port"))):
            if port and _port_supports_service(port, service):
                item["ports"].add(port)
                item["evidence"].add(f"port:{port}")
        flow_key = safe_text(row.get("flow_key"))
        if flow_key != "-":
            item["flow_keys"].add(flow_key)
    rows = []
    for service, item in by_service.items():
        rows.append(
            {
                "service_candidate": service,
                "protocols": sorted(item["protocols"]),
                "ports": sorted(item["ports"]),
                "flow_count": len(item["flow_keys"]),
                "evidence": sorted(item["evidence"]),
            }
        )
    return sorted(rows, key=lambda row: (row["service_candidate"], row["ports"], row["protocols"]))


def _port_supports_service(port: int, service: str) -> bool:
    return (
        (service == "dns" and port == 53)
        or (service == "ssh" and port == 22)
        or (service == "http_service" and port in {80, 8080})
        or (service == "https_service" and port in {443, 8443})
        or (service == "smb" and port in {139, 445})
    )


def derive_risk_relevant_signals(
    protocol_records: Iterable[Dict[str, Any]],
    timeline_events: Iterable[Dict[str, Any]],
    hunt_results: Iterable[Dict[str, Any]],
    conversations: Iterable[Dict[str, Any]],
) -> List[str]:
    records = [safe_metadata(dict(row or {})) for row in protocol_records]
    events = [safe_metadata(dict(row or {})) for row in timeline_events]
    hunts = [safe_metadata(dict(row or {})) for row in hunt_results]
    conversation_rows = [safe_metadata(dict(row or {})) for row in conversations]
    signals: set[str] = set()
    protocols = [safe_text(row.get("protocol"), "unknown").lower() for row in records]
    if "unknown" in protocols:
        signals.add("unknown_protocol_observed")
    ports = [port for row in records for port in (safe_int(row.get("src_port")), safe_int(row.get("dst_port"))) if port]
    port_counts = Counter(ports)
    if len(port_counts) >= 5:
        signals.add("high_port_activity")
    if any(port in SENSITIVE_PORTS and count >= 2 for port, count in port_counts.items()):
        signals.add("repeated_sensitive_port")
    if any(safe_text(row.get("dst_ip")) == "-" or safe_text(row.get("src_ip")) == "-" for row in conversation_rows):
        signals.add("one_way_conversation")
    if any(safe_text(row.get("event_type")) == "protocol_changed" for row in events):
        signals.add("protocol_transition")
    host_pairs = {
        tuple(sorted([safe_text(row.get("src_ip")), safe_text(row.get("dst_ip"))]))
        for row in conversation_rows
        if safe_text(row.get("src_ip")) != "-" and safe_text(row.get("dst_ip")) != "-"
    }
    if len(conversation_rows) >= 4 and len(host_pairs) <= 2:
        signals.add("high_conversation_density")
    if sum(1 for row in conversation_rows if safe_int(row.get("packet_count")) <= 1) >= 3:
        signals.add("short_lived_flow_burst")
    if not hunts:
        signals.add("federated_packet_context_unavailable")
    if len(records) <= 1 or len(conversation_rows) <= 1:
        signals.add("insufficient_packet_history")
    return sorted(signals)


def derive_behavior_graph_hints(
    protocol_records: Iterable[Dict[str, Any]],
    timeline_events: Iterable[Dict[str, Any]],
    conversations: Iterable[Dict[str, Any]],
) -> List[str]:
    records = [safe_metadata(dict(row or {})) for row in protocol_records]
    events = [safe_metadata(dict(row or {})) for row in timeline_events]
    conversation_rows = [safe_metadata(dict(row or {})) for row in conversations]
    hints: set[str] = set()
    if any(safe_text(row.get("src_ip")) != "-" and safe_text(row.get("dst_ip")) != "-" for row in conversation_rows):
        hints.add("host_pair_observed")
    if records:
        hints.add("protocol_relationship_observed")
    if any(safe_text(row.get("flow_key")) != "-" for row in conversation_rows):
        hints.add("flow_relationship_observed")
    if conversation_rows:
        hints.add("conversation_relationship_observed")
    if events:
        hints.add("timeline_relationship_observed")
    return sorted(hints)


def correlate_hunt_results(hunt_results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [safe_metadata(dict(row or {})) for row in hunt_results]
    related_hosts = sorted({host for row in rows for host in (row.get("metadata") or {}).get("related_hosts", [])})
    related_flows = sorted({flow for row in rows for flow in (row.get("metadata") or {}).get("related_flows", [])})
    return {
        "hunt_result_count": len(rows),
        "related_hosts": related_hosts,
        "related_flows": related_flows,
        "average_confidence": round(sum(safe_float(row.get("confidence")) for row in rows) / len(rows), 3) if rows else 0.0,
    }


def correlate_visualizations(visualization_models: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [safe_metadata(dict(row or {})) for row in visualization_models]
    node_count = sum(safe_int(row.get("host_count")) for row in rows)
    event_count = sum(safe_int(row.get("event_count")) for row in rows)
    return {
        "visualization_model_count": len(rows),
        "visual_host_count": node_count,
        "visual_event_count": event_count,
    }
