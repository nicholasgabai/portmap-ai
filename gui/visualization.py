from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from core_engine.modules.flow_tracker import build_flow_report

RISK_BUCKETS = (
    ("critical", 0.9),
    ("high", 0.75),
    ("medium", 0.5),
    ("low", 0.0),
)


def read_jsonl(path: Path, *, limit: int = 200) -> list[dict[str, Any]]:
    """Read recent JSONL objects without raising on missing or malformed rows."""
    if limit <= 0:
        return []
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text().splitlines()[-limit:]
    except Exception:
        return []
    for line in lines:
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def risk_bucket(value: Any) -> str:
    """Map a numeric score to a dashboard risk bucket."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "unknown"
    for name, floor in RISK_BUCKETS:
        if score >= floor:
            return name
    return "unknown"


def score_from_event(event: dict[str, Any]) -> float | None:
    """Return the most relevant numeric score from a scan/remediation event."""
    for key in ("risk_score", "score", "confidence"):
        try:
            return float(event[key])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def build_risk_timeline(
    events: Iterable[dict[str, Any]],
    *,
    bucket_seconds: int = 300,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Group scored events into compact time buckets for terminal rendering."""
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be greater than 0")
    grouped: dict[int, dict[str, Any]] = defaultdict(_new_timeline_bucket)
    for event in events:
        timestamp = _timestamp_float(event.get("timestamp"))
        score = score_from_event(event)
        bucket_start = int(timestamp // bucket_seconds * bucket_seconds) if timestamp else 0
        bucket = grouped[bucket_start]
        bucket["bucket_start"] = bucket_start
        bucket["event_count"] += 1
        if score is not None:
            bucket["score_total"] += score
            bucket["scored_events"] += 1
            bucket["max_score"] = max(bucket["max_score"], score)
            bucket["buckets"][risk_bucket(score)] += 1
        action = str(event.get("action") or "").lower()
        if action:
            bucket["actions"][action] += 1

    timeline: list[dict[str, Any]] = []
    for bucket in sorted(grouped.values(), key=lambda item: item["bucket_start"]):
        scored = bucket.pop("scored_events")
        score_total = bucket.pop("score_total")
        bucket["average_score"] = round(score_total / scored, 3) if scored else None
        bucket["max_score"] = round(bucket["max_score"], 3) if scored else None
        bucket["buckets"] = dict(sorted(bucket["buckets"].items()))
        bucket["actions"] = dict(sorted(bucket["actions"].items()))
        timeline.append(bucket)
    if limit <= 0:
        return []
    return timeline[-limit:]


def render_risk_timeline(timeline: Iterable[dict[str, Any]]) -> str:
    """Render risk buckets as a compact ASCII timeline."""
    rows = []
    for bucket in timeline:
        counts = bucket.get("buckets") or {}
        actions = bucket.get("actions") or {}
        rows.append(
            " ".join(
                [
                    _format_bucket_time(bucket.get("bucket_start")),
                    f"events={bucket.get('event_count', 0)}",
                    f"avg={_format_score(bucket.get('average_score'))}",
                    f"max={_format_score(bucket.get('max_score'))}",
                    f"L/M/H/C={counts.get('low', 0)}/{counts.get('medium', 0)}/"
                    f"{counts.get('high', 0)}/{counts.get('critical', 0)}",
                    f"review={actions.get('prompt_operator', actions.get('review', 0))}",
                    f"block={actions.get('block', 0)}",
                ]
            )
        )
    return "\n".join(rows) if rows else "No scored events yet."


def build_flow_visualization(events: Iterable[dict[str, Any]], *, window_seconds: float = 60.0) -> dict[str, Any]:
    """Build flow and topology data for dashboard panels from passive event rows."""
    report = build_flow_report(events, window_seconds=window_seconds)
    return {
        "ok": report.get("ok", False),
        "window_seconds": report.get("window_seconds"),
        "flows": report.get("flows") or [],
        "topology": report.get("topology") or {"nodes": [], "edges": []},
        "raw_payload_stored": False,
    }


def topology_edge_rows(topology: dict[str, Any] | None, *, limit: int = 12) -> list[dict[str, Any]]:
    """Return sorted edge rows suitable for a Textual DataTable."""
    edges = []
    for edge in (topology or {}).get("edges") or []:
        if not isinstance(edge, dict):
            continue
        edges.append(
            {
                "src_ip": edge.get("src_ip") or "-",
                "dst_ip": edge.get("dst_ip") or "-",
                "flow_count": int(edge.get("flow_count") or 0),
                "packet_count": int(edge.get("packet_count") or 0),
                "payload_bytes": int(edge.get("payload_bytes") or 0),
                "protocols": ", ".join(str(item) for item in edge.get("protocols") or []) or "-",
                "application_protocols": ", ".join(str(item) for item in edge.get("application_protocols") or []) or "-",
            }
        )
    edges.sort(key=lambda item: (-item["payload_bytes"], -item["packet_count"], item["src_ip"], item["dst_ip"]))
    return edges[: max(limit, 0)]


def flow_rows(flows: Iterable[dict[str, Any]], *, limit: int = 12) -> list[dict[str, Any]]:
    """Return sorted flow rows for recent flow visualization."""
    rows = []
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        initiator = flow.get("initiator") or {}
        responder = flow.get("responder") or {}
        rows.append(
            {
                "first_seen": flow.get("first_seen", "-"),
                "last_seen": flow.get("last_seen", "-"),
                "flow": _endpoint_label(initiator) + " -> " + _endpoint_label(responder),
                "application_protocols": ", ".join(str(item) for item in flow.get("application_protocols") or []) or "-",
                "packet_count": int(flow.get("packet_count") or 0),
                "payload_bytes": int(flow.get("payload_bytes") or 0),
                "findings": ", ".join(str(item) for item in flow.get("findings") or []) or "-",
            }
        )
    rows.sort(key=lambda item: _timestamp_float(item.get("last_seen")), reverse=True)
    return rows[: max(limit, 0)]


def visualization_summary(
    *,
    nodes: Iterable[dict[str, Any]],
    risk_timeline: Iterable[dict[str, Any]],
    flows: Iterable[dict[str, Any]],
    topology: dict[str, Any] | None,
) -> dict[str, Any]:
    """Create one compact summary for the dashboard metrics area."""
    node_count = len(list(nodes))
    timeline_rows = list(risk_timeline)
    flow_rows_list = list(flows)
    topology_nodes = len((topology or {}).get("nodes") or [])
    topology_edges = len((topology or {}).get("edges") or [])
    latest_bucket = timeline_rows[-1] if timeline_rows else {}
    return {
        "dashboard_mode": "terminal",
        "node_count": node_count,
        "flow_count": len(flow_rows_list),
        "topology_nodes": topology_nodes,
        "topology_edges": topology_edges,
        "latest_event_count": latest_bucket.get("event_count", 0),
        "latest_max_score": latest_bucket.get("max_score"),
        "raw_payload_stored": False,
        "automatic_changes": False,
    }


def _new_timeline_bucket() -> dict[str, Any]:
    return {
        "bucket_start": 0,
        "event_count": 0,
        "scored_events": 0,
        "score_total": 0.0,
        "max_score": 0.0,
        "buckets": defaultdict(int),
        "actions": defaultdict(int),
    }


def _timestamp_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return 0.0
    return 0.0


def _format_bucket_time(value: Any) -> str:
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return "time=-"
    if timestamp <= 0:
        return "time=unknown"
    return f"time={timestamp}"


def _format_score(value: Any) -> str:
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "-"


def _endpoint_label(endpoint: dict[str, Any]) -> str:
    ip = endpoint.get("ip") or "?"
    port = endpoint.get("port")
    return f"{ip}:{port}" if port not in {None, ""} else str(ip)
