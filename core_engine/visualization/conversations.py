"""Conversation-oriented visualization model builders."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List

from .models import (
    BandwidthModel,
    CommunicationMatrix,
    ConversationGraph,
    ConversationVisualization,
    SessionVisualization,
    TopTalkerModel,
    safe_float,
    safe_int,
    safe_text,
    stable_id,
)


def build_conversation_graph(conversations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = _conversation_rows(conversations)
    nodes: list[Dict[str, Any]] = []
    edges: list[Dict[str, Any]] = []
    for row in rows:
        participants = _participants(row)
        nodes.append(
            {
                "conversation_id": row["conversation_id"],
                "protocol": row["protocol"],
                "participants": participants,
                "start": row["first_observed"],
                "end": row["last_observed"],
                "summary": _conversation_summary(row),
            }
        )
        if len(participants) == 2:
            edges.append(
                {
                    "src": participants[0],
                    "dst": participants[1],
                    "conversation_id": row["conversation_id"],
                    "relationship_type": "conversation_transition",
                    "protocol": row["protocol"],
                    "packet_count": row["packet_count"],
                    "byte_count": row["byte_count"],
                    "confidence": row["confidence"],
                }
            )
    return ConversationGraph(
        graph_id=stable_id("conversation-graph", {"nodes": nodes, "edges": edges}),
        nodes=nodes,
        edges=edges,
        conversation_count=len(nodes),
    ).to_dict()


def build_conversation_visualizations(conversations: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        ConversationVisualization(
            conversation_id=row["conversation_id"],
            protocol=row["protocol"],
            participants=_participants(row),
            start=row["first_observed"],
            end=row["last_observed"],
            summary=_conversation_summary(row),
            packet_count=row["packet_count"],
            byte_count=row["byte_count"],
        ).to_dict()
        for row in _conversation_rows(conversations)
    ]


def build_session_visualizations(timeline_events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: dict[str, list[Dict[str, Any]]] = defaultdict(list)
    for event in [dict(row or {}) for row in timeline_events]:
        session_id = safe_text(event.get("session_id"))
        if session_id != "-":
            groups[session_id].append(event)
    sessions = []
    for session_id in sorted(groups):
        rows = sorted(groups[session_id], key=lambda item: (safe_text(item.get("timestamp")), safe_text(item.get("event_id"))))
        conversations = sorted({safe_text(row.get("conversation_id")) for row in rows if safe_text(row.get("conversation_id")) != "-"})
        protocols = sorted({safe_text(row.get("protocol"), "unknown") for row in rows if safe_text(row.get("protocol"), "unknown") != "-"})
        sessions.append(
            SessionVisualization(
                session_id=session_id,
                packet_count=sum(1 for row in rows if safe_text(row.get("event_type")) == "packet_observed"),
                byte_count=sum(
                    safe_int((row.get("metadata") or {}).get("length"))
                    for row in rows
                    if safe_text(row.get("event_type")) == "packet_observed"
                ),
                first_seen=safe_text(rows[0].get("timestamp")),
                last_seen=safe_text(rows[-1].get("timestamp")),
                protocols=protocols,
                conversations=conversations,
            ).to_dict()
        )
    return sessions


def build_communication_matrix(conversations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = _conversation_rows(conversations)
    matrix: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        src = row["src_ip"]
        dst = row["dst_ip"]
        if src == "-" or dst == "-":
            continue
        key = (src, dst)
        entry = matrix.setdefault(
            key,
            {
                "src": src,
                "dst": dst,
                "packet_count": 0,
                "flow_count": 0,
                "protocols": set(),
                "bytes": 0,
            },
        )
        entry["packet_count"] += row["packet_count"]
        entry["flow_count"] += 1
        entry["protocols"].add(row["protocol"])
        entry["bytes"] += row["byte_count"]
    matrix_rows = [
        {
            "src": entry["src"],
            "dst": entry["dst"],
            "packet_count": entry["packet_count"],
            "flow_count": entry["flow_count"],
            "protocols": sorted(entry["protocols"]),
            "bytes": entry["bytes"],
        }
        for key, entry in sorted(matrix.items())
    ]
    hosts = sorted({host for row in matrix_rows for host in (row["src"], row["dst"])})
    return CommunicationMatrix(
        matrix_id=stable_id("communication-matrix", matrix_rows),
        rows=matrix_rows,
        host_count=len(hosts),
    ).to_dict()


def build_top_talkers(conversations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = _conversation_rows(conversations)
    hosts: dict[str, dict[str, Any]] = defaultdict(lambda: {"bytes": 0, "packets": 0, "flows": set(), "conversations": set()})
    for row in rows:
        for host in (row["src_ip"], row["dst_ip"]):
            if host == "-":
                continue
            hosts[host]["bytes"] += row["byte_count"]
            hosts[host]["packets"] += row["packet_count"]
            hosts[host]["flows"].add(row["flow_key"])
            hosts[host]["conversations"].add(row["conversation_id"])
    talkers = []
    for rank, host in enumerate(sorted(hosts, key=lambda item: (-hosts[item]["bytes"], -hosts[item]["packets"], item)), start=1):
        stats = hosts[host]
        talkers.append(
            {
                "host": host,
                "bytes": stats["bytes"],
                "packets": stats["packets"],
                "flows": len(stats["flows"]),
                "conversations": len(stats["conversations"]),
                "rank": rank,
            }
        )
    return TopTalkerModel(
        model_id=stable_id("top-talkers", talkers),
        talkers=talkers,
        host_count=len(talkers),
    ).to_dict()


def build_bandwidth_model(conversations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = _conversation_rows(conversations)
    by_host: Counter = Counter()
    by_protocol: Counter = Counter()
    by_flow: Counter = Counter()
    for row in rows:
        by_protocol[row["protocol"]] += row["byte_count"]
        by_flow[row["flow_key"]] += row["byte_count"]
        for host in (row["src_ip"], row["dst_ip"]):
            if host != "-":
                by_host[host] += row["byte_count"]
    host_rows = _counter_rows(by_host, "host")
    protocol_rows = _counter_rows(by_protocol, "protocol")
    flow_rows = _counter_rows(by_flow, "flow_key")
    return BandwidthModel(
        bandwidth_id=stable_id("bandwidth", {"host": host_rows, "protocol": protocol_rows, "flow": flow_rows}),
        total_bytes=sum(row["byte_count"] for row in rows),
        by_host=host_rows,
        by_protocol=protocol_rows,
        by_flow=flow_rows,
    ).to_dict()


def _conversation_rows(conversations: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for row in conversations:
        item = dict(row or {})
        normalized = {
            "conversation_id": safe_text(item.get("conversation_id"), stable_id("conversation", item)),
            "flow_key": safe_text(item.get("flow_key")),
            "protocol": safe_text(item.get("protocol"), "unknown"),
            "packet_count": safe_int(item.get("packet_count")),
            "byte_count": safe_int(item.get("byte_count")),
            "first_observed": safe_text(item.get("first_observed")),
            "last_observed": safe_text(item.get("last_observed")),
            "src_ip": safe_text(item.get("src_ip")),
            "dst_ip": safe_text(item.get("dst_ip")),
            "src_port": safe_int(item.get("src_port")),
            "dst_port": safe_int(item.get("dst_port")),
            "direction": safe_text(item.get("direction"), "unknown"),
            "confidence": safe_float(item.get("confidence")),
            "evidence_summary": safe_text(item.get("evidence_summary"), "metadata_only"),
        }
        rows.append(normalized)
    return sorted(rows, key=lambda item: (item["first_observed"], item["conversation_id"], item["flow_key"]))


def _participants(row: Dict[str, Any]) -> List[str]:
    return sorted({row["src_ip"], row["dst_ip"]} - {"-"})


def _conversation_summary(row: Dict[str, Any]) -> str:
    return f"{row['protocol']} conversation with {row['packet_count']} packets and {row['byte_count']} bytes."


def _counter_rows(counter: Counter, label: str) -> List[Dict[str, Any]]:
    total = sum(counter.values())
    rows = []
    for key in sorted(counter, key=lambda item: (-counter[item], str(item))):
        rows.append({label: key, "bytes": counter[key], "percentage": round((counter[key] / total) * 100, 3) if total else 0.0})
    return rows
