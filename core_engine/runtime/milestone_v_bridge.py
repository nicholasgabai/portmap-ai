from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.attribution.probabilistic_apps import build_application_attribution_report
from core_engine.behavior.drift_detection import build_behavior_drift_report
from core_engine.flows.flow_reconstruction import reconstruct_bidirectional_flows
from core_engine.flows.metadata_correlation import build_metadata_correlation_report
from core_engine.flows.process_correlation import build_process_correlation_report
from core_engine.modules.scanner import _address_class, _split_host_port, normalize_scan_snapshot
from core_engine.risky_ports import service_name_for_port
from core_engine.topology.dependency_mapping import build_dependency_map
from core_engine.topology.lateral_analysis import build_lateral_analysis_report
from core_engine.topology.relationship_graphs import build_node_relationship_graph
from core_engine.topology.trust_zones import build_trust_zone_report

DEFAULT_MAX_RUNTIME_OBSERVATIONS = 64

MILESTONE_V_COUNTER_NAMES = (
    "observations_seen",
    "sessions_reconstructed",
    "flows_reconstructed",
    "metadata_correlations",
    "process_correlations",
    "relationship_edges",
    "attribution_candidates",
    "drift_records",
    "topology_records",
)

SAFETY_FLAGS = {
    "metadata_only": True,
    "raw_payload_stored": False,
    "raw_packet_stored": False,
    "packet_payload_inspected": False,
    "pcap_generated": False,
    "raw_dns_history_stored": False,
    "credential_material_stored": False,
    "hardcoded_live_dummy_labels": False,
    "threat_verdict_generated": False,
    "enforcement_enabled": False,
    "automatic_changes": False,
}


def build_milestone_v_runtime_bridge(
    observations: Iterable[dict[str, Any]],
    *,
    node_id: str = "",
    generated_at: str | None = None,
    max_observations: int = DEFAULT_MAX_RUNTIME_OBSERVATIONS,
) -> dict[str, Any]:
    """Build bounded Milestone V runtime summaries from a current socket snapshot."""
    timestamp = generated_at or _now()
    current_rows = normalize_scan_snapshot(
        observations or [],
        node_id=node_id,
        max_observations=max_observations,
        prune_transient=True,
    )
    socket_rows = [_socket_observation(row, node_id=node_id, generated_at=timestamp) for row in current_rows]
    socket_rows = [row for row in socket_rows if row is not None]

    flow_report = reconstruct_bidirectional_flows(socket_rows, generated_at=timestamp)
    sessions = flow_report.get("normalized_sessions") or []
    flow_pairs = flow_report.get("flow_pairs") or []
    socket_rows = _enrich_socket_identities(socket_rows=socket_rows, sessions=sessions, flow_pairs=flow_pairs)

    metadata_report = build_metadata_correlation_report(
        _metadata_inputs(socket_rows=socket_rows, sessions=sessions, flow_pairs=flow_pairs),
        generated_at=timestamp,
    )
    process_report = build_process_correlation_report(sessions, generated_at=timestamp)
    relationship_graph = build_node_relationship_graph(
        _relationship_inputs(flow_pairs, node_id=node_id),
        generated_at=timestamp,
        label=f"{node_id or 'worker'}-live-runtime-relationships",
    )
    relationships = relationship_graph.get("relationships") or []
    lateral_report = build_lateral_analysis_report(relationships, generated_at=timestamp)
    attribution_report = build_application_attribution_report(flow_pairs, generated_at=timestamp)
    drift_report = build_behavior_drift_report(
        [
            {
                "baseline_record": {},
                "current_record": row,
                "drift_class": _drift_class_for(row),
            }
            for row in flow_pairs
        ],
        generated_at=timestamp,
    )
    trust_zone_report = build_trust_zone_report(relationships, generated_at=timestamp)
    dependency_map = build_dependency_map(relationships, generated_at=timestamp)
    flow_events = _flow_visualization_events(socket_rows, generated_at=timestamp)
    topology_edges = _topology_edge_records(flow_events)

    counters = {
        "observations_seen": len(socket_rows),
        "sessions_reconstructed": len(sessions),
        "flows_reconstructed": len(flow_pairs),
        "metadata_correlations": len(metadata_report.get("metadata_correlations") or []),
        "process_correlations": len(process_report.get("process_correlations") or []),
        "relationship_edges": len(relationships),
        "attribution_candidates": len(attribution_report.get("attributions") or []),
        "drift_records": len(drift_report.get("drift_records") or []),
        "topology_records": len(trust_zone_report.get("trust_zones") or []) + len(dependency_map.get("dependencies") or []),
    }
    source_modes = sorted({str(row.get("source_mode") or "unknown") for row in socket_rows}) or ["unknown"]
    return {
        "record_type": "milestone_v_live_runtime_bridge",
        "generated_at": timestamp,
        "node_id": str(node_id or "unknown-node"),
        "source_modes": source_modes,
        "runtime_counters": counters,
        "flow_events": flow_events,
        "topology_edges": topology_edges,
        "operator_summary": {
            "record_type": "milestone_v_live_runtime_operator_summary",
            "generated_at": timestamp,
            "node_id": str(node_id or "unknown-node"),
            "source_modes": source_modes,
            "counters": counters,
            "flow_summary": flow_report.get("summary") or {},
            "metadata_summary": metadata_report.get("summary") or {},
            "process_summary": process_report.get("summary") or {},
            "relationship_summary": relationship_graph.get("summary") or {},
            "lateral_summary": lateral_report.get("summary") or {},
            "attribution_summary": attribution_report.get("summary") or {},
            "drift_summary": drift_report.get("summary") or {},
            "trust_zone_summary": trust_zone_report.get("summary") or {},
            "dependency_summary": dependency_map.get("summary") or {},
            "socket_only_limitations": [
                "ICMP ping may not appear in socket-only runtime views.",
                "Listener-only socket observations do not create packet-activity rows because no remote flow endpoint is available.",
                "Short-lived TCP or UDP activity may require scan timing alignment until packet capture is explicitly enabled.",
            ],
            **SAFETY_FLAGS,
        },
        "dashboard_status": {
            "flows": flow_report.get("dashboard_status") or {},
            "metadata_correlations": metadata_report.get("dashboard_status") or {},
            "process_correlations": process_report.get("dashboard_status") or {},
            "relationships": relationship_graph.get("dashboard_status") or {},
            "lateral_analysis": lateral_report.get("dashboard_status") or {},
            "attribution": attribution_report.get("dashboard_status") or {},
            "drift": drift_report.get("dashboard_status") or {},
            "trust_zones": trust_zone_report.get("dashboard_status") or {},
            "dependencies": dependency_map.get("dashboard_status") or {},
        },
        "api_status": {
            "flows": flow_report.get("api_status") or {},
            "metadata_correlations": metadata_report.get("api_status") or {},
            "process_correlations": process_report.get("api_status") or {},
            "relationships": relationship_graph.get("api_status") or {},
            "lateral_analysis": lateral_report.get("api_status") or {},
            "attribution": attribution_report.get("api_status") or {},
            "drift": drift_report.get("api_status") or {},
            "trust_zones": trust_zone_report.get("api_status") or {},
            "dependencies": dependency_map.get("api_status") or {},
        },
        **SAFETY_FLAGS,
    }


def empty_milestone_v_runtime_bridge(
    *,
    node_id: str = "",
    generated_at: str | None = None,
    error_summary: str = "",
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    counters = {name: 0 for name in MILESTONE_V_COUNTER_NAMES}
    return {
        "record_type": "milestone_v_live_runtime_bridge",
        "generated_at": timestamp,
        "node_id": str(node_id or "unknown-node"),
        "source_modes": ["unknown"],
        "runtime_counters": counters,
        "flow_events": [],
        "topology_edges": [],
        "operator_summary": {
            "record_type": "milestone_v_live_runtime_operator_summary",
            "generated_at": timestamp,
            "node_id": str(node_id or "unknown-node"),
            "source_modes": ["unknown"],
            "counters": counters,
            "error_summary": str(error_summary or ""),
            **SAFETY_FLAGS,
        },
        "dashboard_status": {},
        "api_status": {},
        **SAFETY_FLAGS,
    }


def format_runtime_counter_summary(counters: dict[str, Any]) -> str:
    return " ".join(f"{name}={int(counters.get(name) or 0)}" for name in MILESTONE_V_COUNTER_NAMES)


def _socket_observation(row: dict[str, Any], *, node_id: str, generated_at: str) -> dict[str, Any] | None:
    local_host, local_port = _split_host_port(row.get("local"))
    remote_host, remote_port = _split_host_port(row.get("remote"))
    local_port = _safe_port(row.get("local_port") or row.get("port") or local_port)
    remote_port = _safe_port(row.get("remote_port") or remote_port)
    protocol = _transport(row.get("protocol") or row.get("transport"))
    if protocol not in {"tcp", "udp", "icmp"}:
        protocol = "tcp" if str(row.get("status") or "").upper() in {"LISTEN", "ESTABLISHED"} else "unknown"
    source_mode = _source_mode(row)
    return {
        "record_type": "live_socket_observation",
        "node_id": str(node_id or row.get("node_id") or "unknown-node"),
        "timestamp": str(row.get("timestamp") or row.get("observed_at") or generated_at),
        "local": row.get("local") or "",
        "remote": row.get("remote") or "",
        "local_address": local_host or "",
        "remote_address": remote_host or "",
        "local_port": local_port,
        "remote_port": remote_port,
        "protocol": protocol,
        "transport": protocol,
        "transport_state": str(row.get("status") or row.get("state") or "unknown").lower(),
        "local_endpoint_class": _flow_endpoint_class(row.get("local_address_class") or _address_class(row.get("local"))),
        "remote_endpoint_class": _flow_endpoint_class(row.get("remote_address_class") or _address_class(row.get("remote"))),
        "process_attribution": _safe_process(row, source_mode=source_mode),
        "service_attribution": _safe_service(row, local_port=local_port, remote_port=remote_port, source_mode=source_mode),
        "source_mode": source_mode,
        "data_source": source_mode,
        "telemetry_source": "socket_inventory",
        "scan_snapshot_key": row.get("scan_snapshot_key") or "",
        "current_snapshot": True,
        "observation_count": 1,
        "local_host_present": bool(local_host),
        "remote_host_present": bool(remote_host),
        **SAFETY_FLAGS,
    }


def _enrich_socket_identities(
    *,
    socket_rows: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    flow_pairs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    flow_by_session = {str(row.get("session_ref") or ""): row for row in flow_pairs if isinstance(row, dict)}
    enriched: list[dict[str, Any]] = []
    for socket_row in socket_rows:
        row = dict(socket_row)
        matching_session = _matching_session(row, sessions)
        matching_flow = flow_by_session.get(str((matching_session or {}).get("session_id") or "")) or _matching_flow(row, flow_pairs)
        if matching_session:
            row["observation_id"] = matching_session.get("observation_id") or row.get("observation_id") or ""
            row["source_observation_id"] = matching_session.get("source_observation_id") or row.get("source_observation_id") or ""
            row["session_id"] = matching_session.get("session_id") or ""
            row["session_reference"] = matching_session.get("session_id") or ""
            row["flow_key"] = matching_session.get("flow_key") or row.get("flow_key") or ""
            row["evidence_origin"] = matching_session.get("evidence_origin") or row.get("evidence_origin") or ""
            row["observation_type"] = matching_session.get("observation_type") or row.get("observation_type") or ""
            row["identity_scope"] = matching_session.get("identity_scope") or row.get("identity_scope") or ""
        if matching_flow:
            row["flow_pair_id"] = matching_flow.get("flow_pair_id") or ""
            row["flow_reference"] = matching_flow.get("flow_pair_id") or ""
            row["flow_key"] = matching_flow.get("flow_key") or row.get("flow_key") or ""
        enriched.append(row)
    return enriched


def _metadata_inputs(
    *,
    socket_rows: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    flow_pairs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    session_by_ref = {str(row.get("session_id") or ""): row for row in sessions}
    flow_by_ref = {str(row.get("session_ref") or ""): row for row in flow_pairs}
    inputs = []
    for socket_row in socket_rows:
        matching_session = _matching_session(socket_row, sessions)
        session_ref = str((matching_session or {}).get("session_id") or "")
        flow_pair = flow_by_ref.get(session_ref) or _matching_flow(socket_row, flow_pairs)
        inputs.append(
            {
                "socket_observation": socket_row,
                "reconstructed_session": matching_session or session_by_ref.get(session_ref) or {},
                "flow_pair": flow_pair or {},
                "protocol_metadata": {
                    "record_type": "runtime_protocol_hint",
                    "protocol_hint": _application_protocol(socket_row),
                    "source_mode": socket_row.get("source_mode"),
                },
                "topology_relationship": {
                    "record_type": "runtime_topology_hint",
                    "relationship_type": "socket_flow",
                    "source_mode": socket_row.get("source_mode"),
                    "observation_id": socket_row.get("observation_id"),
                    "flow_key": socket_row.get("flow_key"),
                    "session_id": socket_row.get("session_id"),
                    "evidence_origin": socket_row.get("evidence_origin"),
                    "observation_type": socket_row.get("observation_type"),
                    "identity_scope": socket_row.get("identity_scope"),
                    "topology_correlation_state": "correlated" if socket_row.get("remote_port") is not None else "unknown",
                },
            }
        )
    return inputs


def _relationship_inputs(flow_pairs: Iterable[dict[str, Any]], *, node_id: str) -> list[dict[str, Any]]:
    rows = []
    for pair in flow_pairs or []:
        if not isinstance(pair, dict):
            continue
        remote_class = str(pair.get("remote_endpoint_class") or "unknown")
        local_class = str(pair.get("local_endpoint_class") or "unknown")
        rows.append(
            {
                "source_node_class": "worker",
                "target_node_class": _target_node_class(remote_class),
                "relationship_type": _relationship_type(pair),
                "flow_reference": pair.get("flow_pair_id"),
                "session_reference": pair.get("session_ref"),
                "observation_id": pair.get("observation_id"),
                "flow_key": pair.get("flow_key"),
                "session_id": pair.get("session_id") or pair.get("session_ref"),
                "evidence_origin": pair.get("evidence_origin"),
                "observation_type": pair.get("observation_type"),
                "identity_scope": pair.get("identity_scope"),
                "shared_service_state": "shared" if pair.get("service_attribution") not in {"Unknown", "Unattributed"} else "unknown",
                "recurring_interaction_score": pair.get("recurrence_score"),
                "topology_distance": 0 if local_class == "loopback" and remote_class == "loopback" else 1,
                "relationship_strength": pair.get("relationship_strength"),
                "relationship_confidence": pair.get("reconstruction_confidence"),
                "relationship_state": pair.get("session_classification"),
                "drift_detected": pair.get("drift_detected"),
                "source_mode": pair.get("source_mode"),
                "source_node_reference": str(node_id or "worker"),
                "target_node_reference": remote_class,
            }
        )
    return rows


def _flow_visualization_events(socket_rows: Iterable[dict[str, Any]], *, generated_at: str) -> list[dict[str, Any]]:
    events = []
    seen: set[tuple[Any, ...]] = set()
    for row in socket_rows or []:
        if row.get("remote_port") is None or not row.get("remote_host_present"):
            continue
        local_host, _ = _split_host_port(row.get("local"))
        remote_host, _ = _split_host_port(row.get("remote"))
        if not local_host or not remote_host:
            continue
        src_host, src_port, dst_host, dst_port = local_host, row.get("local_port"), remote_host, row.get("remote_port")
        if row.get("flow_direction") == "inbound" or str(row.get("transport_state") or "").lower() in {"listen", "listening"}:
            src_host, src_port, dst_host, dst_port = remote_host, row.get("remote_port"), local_host, row.get("local_port")
        key = (
            src_host,
            int(src_port or 0),
            dst_host,
            int(dst_port or 0),
            row.get("protocol"),
            row.get("source_mode"),
        )
        if key in seen:
            continue
        seen.add(key)
        events.append(
            {
                "event_type": "traffic_flow",
                "timestamp": generated_at,
                "src_ip": src_host,
                "src_port": src_port,
                "dst_ip": dst_host,
                "dst_port": dst_port,
                "protocol": str(row.get("protocol") or "unknown").upper(),
                "application_protocol": _application_protocol(row),
                "observation_id": row.get("observation_id") or "",
                "flow_key": row.get("flow_key") or "",
                "session_id": row.get("session_id") or "",
                "evidence_origin": row.get("evidence_origin") or "reconstructed_socket_flow",
                "observation_type": row.get("observation_type") or "socket_conversation",
                "identity_scope": row.get("identity_scope") or "flow",
                "telemetry_source": "socket_reconstruction",
                "payload_bytes": 0,
                "captured_len": 0,
                "source_mode": row.get("source_mode") or "unknown",
                "data_source": row.get("source_mode") or "unknown",
                "raw_payload_stored": False,
                "packet_payload_inspected": False,
                "pcap_generated": False,
            }
        )
    return sorted(events, key=lambda item: (str(item.get("src_ip")), int(item.get("src_port") or 0), str(item.get("dst_ip")), int(item.get("dst_port") or 0)))


def _topology_edge_records(flow_events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in flow_events or []:
        key = (str(event.get("src_ip") or ""), str(event.get("dst_ip") or ""), str(event.get("source_mode") or "unknown"))
        if not key[0] or not key[1]:
            continue
        edge = grouped.setdefault(
            key,
            {
                "src_ip": key[0],
                "dst_ip": key[1],
                "source_mode": key[2],
                "flow_count": 0,
                "packet_count": 0,
                "payload_bytes": 0,
                "protocols": set(),
                "application_protocols": set(),
            },
        )
        edge["flow_count"] += 1
        edge["packet_count"] += 1
        edge["protocols"].add(str(event.get("protocol") or "unknown").upper())
        app = str(event.get("application_protocol") or "unknown").upper()
        if app != "UNKNOWN":
            edge["application_protocols"].add(app)
    return [
        {
            **edge,
            "protocols": sorted(edge["protocols"]),
            "application_protocols": sorted(edge["application_protocols"]),
        }
        for edge in sorted(grouped.values(), key=lambda item: (item["src_ip"], item["dst_ip"], item["source_mode"]))
    ]


def _matching_session(socket_row: dict[str, Any], sessions: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    for session in sessions or []:
        if (
            session.get("local_port") == socket_row.get("local_port")
            and session.get("remote_port") == socket_row.get("remote_port")
            and session.get("protocol") == socket_row.get("protocol")
            and session.get("source_mode") == socket_row.get("source_mode")
        ):
            return session
    return None


def _matching_flow(socket_row: dict[str, Any], flow_pairs: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    for flow in flow_pairs or []:
        if (
            flow.get("local_port") == socket_row.get("local_port")
            and flow.get("remote_port") == socket_row.get("remote_port")
            and flow.get("protocol") == socket_row.get("protocol")
            and flow.get("source_mode") == socket_row.get("source_mode")
        ):
            return flow
    return None


def _source_mode(row: dict[str, Any]) -> str:
    mode = str(row.get("source_mode") or row.get("data_source") or "live").strip().lower()
    return mode if mode in {"live", "simulated", "fixture", "replay", "unknown"} else "unknown"


def _safe_process(row: dict[str, Any], *, source_mode: str) -> str:
    value = str(row.get("process_attribution") or row.get("program") or "").strip()
    if value in {"dummy_app", "dummy_db"} and source_mode not in {"fixture", "simulated"}:
        return "Unknown"
    return value or "Unknown"


def _safe_service(row: dict[str, Any], *, local_port: int | None, remote_port: int | None, source_mode: str) -> str:
    value = str(row.get("service_attribution") or row.get("service_name") or "").strip()
    if value in {"dummy_app", "dummy_db"} and source_mode not in {"fixture", "simulated"}:
        return "Unattributed"
    if value:
        return value
    service_port = _service_port(local_port=local_port, remote_port=remote_port)
    return service_name_for_port(service_port) or "Unattributed"


def _application_protocol(row: dict[str, Any]) -> str:
    service = str(row.get("service_attribution") or "").strip()
    if service and service != "Unattributed":
        return service.upper()
    port = _service_port(local_port=_safe_port(row.get("local_port")), remote_port=_safe_port(row.get("remote_port")))
    service = service_name_for_port(port)
    return service.upper() if service else str(row.get("protocol") or "unknown").upper()


def _service_port(*, local_port: int | None, remote_port: int | None) -> int | None:
    for port in (remote_port, local_port):
        if port is not None and 0 < int(port) < 49152:
            return int(port)
    return local_port or remote_port


def _flow_endpoint_class(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    if text in {"loopback"}:
        return "loopback"
    if text in {"private_or_documentation", "link_local", "unspecified", "multicast", "other"}:
        return "private"
    if text in {"global"}:
        return "public"
    if text in {"none"}:
        return "unknown"
    if text in {"local", "private", "remote", "external", "public", "edge", "unknown"}:
        return text
    return "unknown"


def _target_node_class(remote_endpoint_class: str) -> str:
    if remote_endpoint_class in {"public", "external", "remote"}:
        return "external"
    if remote_endpoint_class == "loopback":
        return "worker"
    if remote_endpoint_class in {"private", "edge", "local"}:
        return "edge"
    return "unknown"


def _relationship_type(pair: dict[str, Any]) -> str:
    service = str(pair.get("service_attribution") or "")
    if service not in {"", "Unknown", "Unattributed"}:
        return "service_dependency"
    if pair.get("flow_direction") in {"inbound", "outbound"}:
        return "socket_flow"
    return "topology_adjacency"


def _drift_class_for(pair: dict[str, Any]) -> str:
    service = str(pair.get("service_attribution") or "")
    if service not in {"", "Unknown", "Unattributed"}:
        return "service_behavior"
    if pair.get("protocol") not in {None, "", "unknown"}:
        return "protocol_behavior"
    return "flow_behavior"


def _transport(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    if text in {"tcp", "udp", "icmp"}:
        return text
    if text in {"tcp6"}:
        return "tcp"
    if text in {"udp6"}:
        return "udp"
    return "unknown"


def _safe_port(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _now() -> str:
    return datetime.now(UTC).isoformat()
