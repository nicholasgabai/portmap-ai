"""Protocol and port visualization model builders."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List

from .models import ProtocolDistribution, PortDistribution, safe_int, safe_text, stable_id


def build_protocol_distribution(
    protocol_records: Iterable[Dict[str, Any]],
    *,
    conversations: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    records = [dict(record or {}) for record in protocol_records]
    conversation_rows = [dict(row or {}) for row in conversations or []]
    total = len(records)
    protocol_counts = Counter(safe_text(row.get("protocol"), "unknown") for row in records)
    conversation_counts = Counter(safe_text(row.get("protocol"), "unknown") for row in conversation_rows)
    flow_counts: dict[str, set[str]] = defaultdict(set)
    byte_counts: Counter = Counter()
    for row in records:
        protocol = safe_text(row.get("protocol"), "unknown")
        flow_key = safe_text(row.get("flow_key"))
        if flow_key != "-":
            flow_counts[protocol].add(flow_key)
    for row in conversation_rows:
        byte_counts[safe_text(row.get("protocol"), "unknown")] += safe_int(row.get("byte_count"))

    rows: list[Dict[str, Any]] = []
    for protocol in sorted(protocol_counts, key=lambda item: (-protocol_counts[item], item)):
        count = protocol_counts[protocol]
        rows.append(
            {
                "protocol": protocol,
                "count": count,
                "percentage": round((count / total) * 100, 3) if total else 0.0,
                "conversation_count": conversation_counts[protocol],
                "flow_count": len(flow_counts[protocol]),
                "byte_count": byte_counts[protocol],
            }
        )
    return ProtocolDistribution(
        distribution_id=stable_id("protocol-distribution", rows),
        protocols=rows,
        total_count=total,
    ).to_dict()


def build_port_distribution(
    protocol_records: Iterable[Dict[str, Any]],
    *,
    conversations: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    records = [dict(record or {}) for record in protocol_records]
    conversation_rows = [dict(row or {}) for row in conversations or []]
    counters: Counter = Counter()
    host_sets: dict[tuple[int, str], set[str]] = defaultdict(set)
    conversation_sets: dict[tuple[int, str], set[str]] = defaultdict(set)

    for row in records:
        protocol = safe_text(row.get("protocol"), "unknown")
        for port in (safe_int(row.get("src_port")), safe_int(row.get("dst_port"))):
            if not port:
                continue
            key = (port, protocol)
            counters[key] += 1
            for host in (safe_text(row.get("src_ip")), safe_text(row.get("dst_ip"))):
                if host != "-":
                    host_sets[key].add(host)

    for row in conversation_rows:
        protocol = safe_text(row.get("protocol"), "unknown")
        conversation_id = safe_text(row.get("conversation_id"))
        for port in (safe_int(row.get("src_port")), safe_int(row.get("dst_port"))):
            if port and conversation_id != "-":
                conversation_sets[(port, protocol)].add(conversation_id)

    rows = [
        {
            "port": port,
            "protocol": protocol,
            "count": counters[(port, protocol)],
            "host_count": len(host_sets[(port, protocol)]),
            "conversation_count": len(conversation_sets[(port, protocol)]),
        }
        for port, protocol in sorted(counters, key=lambda item: (-counters[item], item[0], item[1]))
    ]
    return PortDistribution(
        distribution_id=stable_id("port-distribution", rows),
        ports=rows,
        total_count=sum(counters.values()),
    ).to_dict()
