from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from typing import Any, Iterable


DEFAULT_FLOW_WINDOW_SECONDS = 60.0


@dataclass
class FlowEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    transport: str = "unknown"
    application_protocol: str = "unknown"
    payload_bytes: int = 0
    captured_bytes: int = 0
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    observation_id: str = ""
    source_flow_key: str = ""
    session_id: str = ""
    evidence_origin: str = ""
    observation_type: str = ""
    identity_scope: str = ""
    telemetry_source: str = ""

    @property
    def src_endpoint(self) -> dict[str, Any]:
        return {"ip": self.src_ip, "port": self.src_port}

    @property
    def dst_endpoint(self) -> dict[str, Any]:
        return {"ip": self.dst_ip, "port": self.dst_port}


def event_to_flow_event(event: dict[str, Any]) -> FlowEvent | None:
    if not isinstance(event, dict):
        return None
    metadata = _metadata_from_event(event)
    src_ip = str(metadata.get("src_ip") or "")
    dst_ip = str(metadata.get("dst_ip") or "")
    if not src_ip or not dst_ip:
        return None
    return FlowEvent(
        timestamp=_timestamp_float(metadata.get("timestamp"), event.get("timestamp"), event.get("generated_at")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_optional_int(metadata.get("src_port")),
        dst_port=_optional_int(metadata.get("dst_port")),
        transport=str(metadata.get("protocol") or metadata.get("transport") or "unknown").upper(),
        application_protocol=_application_protocol(event, metadata),
        payload_bytes=_payload_bytes(event, metadata),
        captured_bytes=_captured_bytes(event, metadata),
        findings=_finding_types(event),
        evidence=_evidence_markers(event),
        observation_id=_safe_text(event.get("observation_id") or metadata.get("observation_id")),
        source_flow_key=_safe_text(event.get("flow_key") or metadata.get("flow_key")),
        session_id=_safe_text(event.get("session_id") or metadata.get("session_id")),
        evidence_origin=_safe_text(event.get("evidence_origin") or metadata.get("evidence_origin")),
        observation_type=_safe_text(event.get("observation_type") or metadata.get("observation_type")),
        identity_scope=_safe_text(event.get("identity_scope") or metadata.get("identity_scope")),
        telemetry_source=_safe_text(event.get("telemetry_source") or metadata.get("telemetry_source") or event.get("source_mode")),
    )


def flow_key(event: FlowEvent | dict[str, Any]) -> str:
    flow_event = event if isinstance(event, FlowEvent) else event_to_flow_event(event)
    if flow_event is None:
        return "unknown"
    endpoints = sorted([
        (flow_event.src_ip, int(flow_event.src_port or 0)),
        (flow_event.dst_ip, int(flow_event.dst_port or 0)),
    ])
    return (
        f"{flow_event.transport}:"
        f"{endpoints[0][0]}:{endpoints[0][1]}-"
        f"{endpoints[1][0]}:{endpoints[1][1]}"
    )


def reconstruct_flows(
    events: Iterable[dict[str, Any]],
    *,
    window_seconds: float = DEFAULT_FLOW_WINDOW_SECONDS,
) -> list[dict[str, Any]]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")
    normalized = [event for event in (event_to_flow_event(item) for item in events) if event is not None]
    normalized.sort(key=lambda item: (flow_key(item), item.timestamp))

    flows: list[dict[str, Any]] = []
    active: dict[str, dict[str, Any]] = {}
    for event in normalized:
        key = flow_key(event)
        current = active.get(key)
        if current is None or (event.timestamp and current["last_seen"] and event.timestamp - current["last_seen"] > window_seconds):
            if current is not None:
                flows.append(_finalize_flow(current))
            current = _new_flow(key, event)
            active[key] = current
        _apply_event(current, event)

    flows.extend(_finalize_flow(flow) for flow in active.values())
    return sorted(flows, key=lambda item: (item["first_seen"], item["flow_key"], item["flow_id"]))


def build_flow_report(
    events: Iterable[dict[str, Any]],
    *,
    window_seconds: float = DEFAULT_FLOW_WINDOW_SECONDS,
) -> dict[str, Any]:
    flows = reconstruct_flows(events, window_seconds=window_seconds)
    return {
        "ok": True,
        "window_seconds": float(window_seconds),
        "flow_count": len(flows),
        "flows": flows,
        "topology": topology_from_flows(flows),
        "raw_payload_stored": False,
    }


def topology_from_flows(flows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    node_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"ip": "", "flow_count": 0, "packet_count": 0, "payload_bytes": 0})
    edge_stats: dict[tuple[str, str], dict[str, Any]] = {}
    for flow in flows:
        initiator = str((flow.get("initiator") or {}).get("ip") or "")
        responder = str((flow.get("responder") or {}).get("ip") or "")
        if not initiator or not responder:
            continue
        for ip in (initiator, responder):
            node = node_stats[ip]
            node["ip"] = ip
            node["flow_count"] += 1
            node["packet_count"] += int(flow.get("packet_count") or 0)
            node["payload_bytes"] += int(flow.get("payload_bytes") or 0)
        edge_key = (initiator, responder)
        edge = edge_stats.setdefault(
            edge_key,
            {
                "src_ip": initiator,
                "dst_ip": responder,
                "flow_count": 0,
                "packet_count": 0,
                "payload_bytes": 0,
                "protocols": set(),
                "application_protocols": set(),
            },
        )
        edge["flow_count"] += 1
        edge["packet_count"] += int(flow.get("packet_count") or 0)
        edge["payload_bytes"] += int(flow.get("payload_bytes") or 0)
        edge["protocols"].update(flow.get("transports") or [])
        edge["application_protocols"].update(flow.get("application_protocols") or [])

    return {
        "nodes": sorted(node_stats.values(), key=lambda item: item["ip"]),
        "edges": [
            {
                **edge,
                "protocols": sorted(edge["protocols"]),
                "application_protocols": sorted(edge["application_protocols"]),
            }
            for edge in sorted(edge_stats.values(), key=lambda item: (item["src_ip"], item["dst_ip"]))
        ],
    }


def _metadata_from_event(event: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if isinstance(event.get("metadata"), dict):
        metadata.update(event["metadata"])
    headers = event.get("headers") or {}
    if isinstance(headers, dict) and isinstance(headers.get("network"), dict):
        metadata.update(headers["network"])
    if isinstance(event.get("dpi"), dict):
        dpi_headers = event["dpi"].get("headers") or {}
        if isinstance(dpi_headers, dict) and isinstance(dpi_headers.get("network"), dict):
            metadata.update({key: value for key, value in dpi_headers["network"].items() if value not in {None, ""}})
    for key in ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "transport", "payload_bytes", "captured_len"):
        if event.get(key) not in {None, ""}:
            metadata[key] = event[key]
    return metadata


def _application_protocol(event: dict[str, Any], metadata: dict[str, Any]) -> str:
    for value in (
        event.get("application_protocol"),
        (event.get("dissection") or {}).get("protocol") if isinstance(event.get("dissection"), dict) else None,
        (event.get("dpi") or {}).get("protocol") if isinstance(event.get("dpi"), dict) else None,
        event.get("protocol") if str(event.get("protocol") or "").upper() not in {"TCP", "UDP", "ICMP", "ICMPV6", "ARP"} else None,
        metadata.get("application_protocol"),
    ):
        if value:
            return str(value).upper()
    return "unknown"


def _payload_bytes(event: dict[str, Any], metadata: dict[str, Any]) -> int:
    candidates = [
        metadata.get("payload_bytes"),
        (event.get("payload") or {}).get("length") if isinstance(event.get("payload"), dict) else None,
        ((event.get("dpi") or {}).get("payload") or {}).get("length") if isinstance(event.get("dpi"), dict) else None,
    ]
    for candidate in candidates:
        value = _optional_int(candidate)
        if value is not None:
            return max(value, 0)
    return 0


def _captured_bytes(event: dict[str, Any], metadata: dict[str, Any]) -> int:
    for candidate in (metadata.get("captured_len"), metadata.get("original_len"), event.get("captured_len")):
        value = _optional_int(candidate)
        if value is not None:
            return max(value, 0)
    return 0


def _finding_types(event: dict[str, Any]) -> list[str]:
    findings = []
    for source in (event.get("findings"), (event.get("dpi") or {}).get("findings") if isinstance(event.get("dpi"), dict) else None):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict) and item.get("type"):
                findings.append(str(item["type"]))
            elif item:
                findings.append(str(item))
    return sorted(set(findings))


def _evidence_markers(event: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for source in (event.get("evidence"), (event.get("dissection") or {}).get("evidence") if isinstance(event.get("dissection"), dict) else None):
        if isinstance(source, list):
            evidence.extend(str(item) for item in source if item)
    return sorted(set(evidence))


def _new_flow(key: str, event: FlowEvent) -> dict[str, Any]:
    return {
        "flow_key": key,
        "initiator": event.src_endpoint,
        "responder": event.dst_endpoint,
        "first_seen": event.timestamp,
        "last_seen": event.timestamp,
        "packet_count": 0,
        "payload_bytes": 0,
        "captured_bytes": 0,
        "directions": {
            "initiator_to_responder": {"packets": 0, "payload_bytes": 0},
            "responder_to_initiator": {"packets": 0, "payload_bytes": 0},
        },
        "transports": set(),
        "application_protocols": set(),
        "findings": set(),
        "evidence": set(),
        "observation_ids": set(),
        "source_flow_keys": set(),
        "session_ids": set(),
        "evidence_origins": set(),
        "observation_types": set(),
        "identity_scopes": set(),
        "telemetry_sources": set(),
    }


def _apply_event(flow: dict[str, Any], event: FlowEvent) -> None:
    if event.timestamp:
        flow["first_seen"] = min(flow["first_seen"] or event.timestamp, event.timestamp)
        flow["last_seen"] = max(flow["last_seen"] or event.timestamp, event.timestamp)
    flow["packet_count"] += 1
    flow["payload_bytes"] += event.payload_bytes
    flow["captured_bytes"] += event.captured_bytes
    flow["transports"].add(event.transport)
    if event.application_protocol and event.application_protocol != "unknown":
        flow["application_protocols"].add(event.application_protocol)
    flow["findings"].update(event.findings)
    flow["evidence"].update(event.evidence)
    if event.observation_id:
        flow["observation_ids"].add(event.observation_id)
    if event.source_flow_key:
        flow["source_flow_keys"].add(event.source_flow_key)
    if event.session_id:
        flow["session_ids"].add(event.session_id)
    if event.evidence_origin:
        flow["evidence_origins"].add(event.evidence_origin)
    if event.observation_type:
        flow["observation_types"].add(event.observation_type)
    if event.identity_scope:
        flow["identity_scopes"].add(event.identity_scope)
    if event.telemetry_source:
        flow["telemetry_sources"].add(event.telemetry_source)

    initiator = flow["initiator"]
    direction = "initiator_to_responder"
    if event.src_ip == initiator["ip"] and event.src_port == initiator["port"]:
        direction = "initiator_to_responder"
    else:
        direction = "responder_to_initiator"
    flow["directions"][direction]["packets"] += 1
    flow["directions"][direction]["payload_bytes"] += event.payload_bytes


def _finalize_flow(flow: dict[str, Any]) -> dict[str, Any]:
    duration = max(float(flow["last_seen"] or 0) - float(flow["first_seen"] or 0), 0.0)
    finalized = {
        **flow,
        "duration_seconds": round(duration, 3),
        "transports": sorted(flow["transports"]),
        "application_protocols": sorted(flow["application_protocols"]),
        "findings": sorted(flow["findings"]),
        "evidence": sorted(flow["evidence"]),
        "observation_ids": sorted(flow["observation_ids"]),
        "source_flow_keys": sorted(flow["source_flow_keys"]),
        "session_ids": sorted(flow["session_ids"]),
        "evidence_origins": sorted(flow["evidence_origins"]),
        "observation_types": sorted(flow["observation_types"]),
        "identity_scopes": sorted(flow["identity_scopes"]),
        "telemetry_sources": sorted(flow["telemetry_sources"]),
    }
    finalized["observation_id"] = finalized["observation_ids"][0] if len(finalized["observation_ids"]) == 1 else ", ".join(finalized["observation_ids"])
    finalized["session_id"] = finalized["session_ids"][0] if len(finalized["session_ids"]) == 1 else ", ".join(finalized["session_ids"])
    finalized["source_flow_key"] = finalized["source_flow_keys"][0] if len(finalized["source_flow_keys"]) == 1 else ", ".join(finalized["source_flow_keys"])
    finalized["evidence_origin"] = finalized["evidence_origins"][0] if len(finalized["evidence_origins"]) == 1 else ", ".join(finalized["evidence_origins"])
    finalized["observation_type"] = finalized["observation_types"][0] if len(finalized["observation_types"]) == 1 else ", ".join(finalized["observation_types"])
    finalized["identity_scope"] = finalized["identity_scopes"][0] if len(finalized["identity_scopes"]) == 1 else ", ".join(finalized["identity_scopes"])
    finalized["telemetry_source"] = finalized["telemetry_sources"][0] if len(finalized["telemetry_sources"]) == 1 else ", ".join(finalized["telemetry_sources"])
    finalized["flow_id"] = sha256(
        f"{finalized['flow_key']}:{finalized['first_seen']}:{finalized['last_seen']}".encode("utf-8")
    ).hexdigest()[:16]
    return finalized


def _timestamp_float(*values: Any) -> float:
    for value in values:
        timestamp = _single_timestamp_float(value)
        if timestamp > 0:
            return timestamp
    return 0.0


def _single_timestamp_float(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return _normalize_epoch(float(value))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped in {"", "-", "0"}:
            return 0.0
        try:
            return _normalize_epoch(float(stripped))
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(stripped.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _normalize_epoch(value: float) -> float:
    if value <= 0:
        return 0.0
    if value > 10_000_000_000:
        return value / 1000.0
    return value


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_text(value: Any) -> str:
    if value in {None, ""}:
        return ""
    text = str(value).strip()
    return "" if text == "-" else text
