"""Graph visualization model builders for hosts and flows."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List

from core_engine.timeline import export_timeline
from core_engine.timeline.models import TimelineEvent

from .models import FlowGraph, HostGraph, safe_float, safe_int, safe_text, stable_id


def build_host_graph(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, Any]:
    rows = export_timeline(events)
    hosts: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    conversations_by_host: dict[str, set[str]] = defaultdict(set)
    protocols_by_host: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        src = safe_text(row.get("src_ip"))
        dst = safe_text(row.get("dst_ip"))
        protocol = safe_text(row.get("protocol"), "unknown")
        timestamp = safe_text(row.get("timestamp"))
        for host in (src, dst):
            if host == "-":
                continue
            hosts.setdefault(
                host,
                {
                    "host_id": stable_id("host", {"ip": host}),
                    "ip": host,
                    "mac": "-",
                    "hostname": "-",
                    "roles": set(),
                    "packet_count": 0,
                },
            )
            hosts[host]["packet_count"] += 1
            protocols_by_host[host].add(protocol)
            conversation_id = safe_text(row.get("conversation_id"))
            if conversation_id != "-":
                conversations_by_host[host].add(conversation_id)
        if src != "-" and dst != "-":
            key = (src, dst, protocol)
            edge = edges.setdefault(
                key,
                {
                    "src": stable_id("host", {"ip": src}),
                    "dst": stable_id("host", {"ip": dst}),
                    "protocol": protocol,
                    "count": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                },
            )
            edge["count"] += 1
            edge["first_seen"] = _min_time(edge["first_seen"], timestamp)
            edge["last_seen"] = _max_time(edge["last_seen"], timestamp)

    nodes = []
    for host in sorted(hosts):
        node = hosts[host]
        packet_count = safe_int(node["packet_count"])
        roles = sorted(node["roles"] or _infer_host_roles(host, rows))
        nodes.append(
            {
                "host_id": node["host_id"],
                "ip": node["ip"],
                "mac": node["mac"],
                "hostname": node["hostname"],
                "roles": roles,
                "packet_count": packet_count,
                "conversation_count": len(conversations_by_host[host]),
                "protocols": sorted(protocols_by_host[host]),
                "metadata": {},
            }
        )

    edge_rows = []
    max_count = max((safe_int(edge["count"]) for edge in edges.values()), default=0)
    for key in sorted(edges):
        edge = edges[key]
        count = safe_int(edge["count"])
        edge_rows.append(
            {
                **edge,
                "importance": "high" if count == max_count and max_count > 1 else "normal",
                "weight": round(count / max_count, 3) if max_count else 0.0,
            }
        )
    return HostGraph(
        graph_id=stable_id("host-graph", {"nodes": nodes, "edges": edge_rows}),
        nodes=nodes,
        edges=edge_rows,
        host_count=len(nodes),
        edge_count=len(edge_rows),
    ).to_dict()


def build_flow_graph(conversations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [dict(row or {}) for row in conversations]
    edges: list[Dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: (safe_text(item.get("flow_key")), safe_text(item.get("conversation_id")))):
        first = safe_text(row.get("first_observed"))
        last = safe_text(row.get("last_observed"))
        duration = _duration_seconds(first, last)
        edges.append(
            {
                "flow_key": safe_text(row.get("flow_key")),
                "protocol": safe_text(row.get("protocol"), "unknown"),
                "src": safe_text(row.get("src_ip")),
                "dst": safe_text(row.get("dst_ip")),
                "ports": [safe_int(row.get("src_port")), safe_int(row.get("dst_port"))],
                "packets": safe_int(row.get("packet_count")),
                "bytes": safe_int(row.get("byte_count")),
                "duration": duration,
                "confidence": safe_float(row.get("confidence")),
            }
        )
    return FlowGraph(
        graph_id=stable_id("flow-graph", edges),
        edges=edges,
        flow_count=len(edges),
    ).to_dict()


def _infer_host_roles(host: str, rows: List[Dict[str, Any]]) -> set[str]:
    roles: set[str] = set()
    for row in rows:
        if safe_text(row.get("dst_ip")) == host and safe_int(row.get("dst_port")):
            roles.add("server")
        if safe_text(row.get("src_ip")) == host and safe_int(row.get("src_port")):
            roles.add("client")
    return roles or {"unknown"}


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _min_time(left: Any, right: Any) -> str:
    left_time = _parse_time(left)
    right_time = _parse_time(right)
    if not left_time:
        return safe_text(right)
    if not right_time:
        return safe_text(left)
    return safe_text(left) if left_time <= right_time else safe_text(right)


def _max_time(left: Any, right: Any) -> str:
    left_time = _parse_time(left)
    right_time = _parse_time(right)
    if not left_time:
        return safe_text(right)
    if not right_time:
        return safe_text(left)
    return safe_text(left) if left_time >= right_time else safe_text(right)


def _duration_seconds(start: Any, end: Any) -> int:
    parsed_start = _parse_time(start)
    parsed_end = _parse_time(end)
    if not parsed_start or not parsed_end:
        return 0
    return max(0, int((parsed_end - parsed_start).total_seconds()))
