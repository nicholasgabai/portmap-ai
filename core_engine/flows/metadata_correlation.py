from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, Iterable

from core_engine.time_utils import normalize_timestamp, utc_now_iso
from core_engine.flows.process_correlation import build_process_correlation_record
from core_engine.flows.session_tracking import FLOW_SAFETY_FLAGS
from core_engine.telemetry.process_attribution import normalize_source_mode


METADATA_CORRELATION_RECORD_VERSION = 1
METADATA_CORRELATION_STATES = {"correlated", "partially_correlated", "uncorrelated", "conflicting", "unknown"}
PAYLOAD_FIELD_NAMES = {
    "payload",
    "payload_bytes",
    "payload_content",
    "raw_payload",
    "raw_packet",
    "packet_bytes",
    "pcap",
    "pcap_path",
    "query_payload",
    "dns_payload",
}


class MetadataCorrelationError(ValueError):
    """Raised when packet metadata correlation inputs are malformed."""


def build_metadata_correlation_record(
    *,
    packet_metadata: dict[str, Any] | None = None,
    socket_observation: dict[str, Any] | None = None,
    reconstructed_session: dict[str, Any] | None = None,
    flow_pair: dict[str, Any] | None = None,
    dns_destination_behavior: dict[str, Any] | None = None,
    protocol_metadata: dict[str, Any] | None = None,
    topology_relationship: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = normalize_timestamp(generated_at or _now(), preserve_ambiguous=True)
    _validate_optional_dicts(
        packet_metadata=packet_metadata,
        socket_observation=socket_observation,
        reconstructed_session=reconstructed_session,
        flow_pair=flow_pair,
        dns_destination_behavior=dns_destination_behavior,
        protocol_metadata=protocol_metadata,
        topology_relationship=topology_relationship,
    )
    packet = dict(packet_metadata or {})
    socket = dict(socket_observation or {})
    session = dict(reconstructed_session or {})
    flow = dict(flow_pair or {})
    dns = dict(dns_destination_behavior or {})
    protocol = dict(protocol_metadata or {})
    topology = dict(topology_relationship or {})
    identity = _identity_context(packet=packet, socket=socket, session=session, flow=flow, topology=topology)
    mode = normalize_source_mode(
        session.get("source_mode")
        or flow.get("source_mode")
        or socket.get("source_mode")
        or packet.get("source_mode")
        or dns.get("source_mode")
        or protocol.get("source_mode")
        or topology.get("source_mode")
        or "unknown"
    )
    protocol_hint = _protocol_hint(packet=packet, session=session, flow=flow, protocol=protocol)
    destination_class = _destination_class(dns=dns, session=session, flow=flow, socket=socket, packet=packet, topology=topology)
    dns_state = _dns_state(dns)
    topology_state = _topology_state(topology)
    conflict_reason = _conflict_reason(packet=packet, session=session, flow=flow, dns=dns, protocol_hint=protocol_hint, topology=topology)
    state = classify_metadata_correlation_state(
        packet=packet,
        socket=socket,
        session=session,
        flow=flow,
        dns_state=dns_state,
        topology_state=topology_state,
        conflict_reason=conflict_reason,
    )
    confidence = score_metadata_confidence(
        packet=packet,
        socket=socket,
        session=session,
        flow=flow,
        dns_state=dns_state,
        topology_state=topology_state,
        conflict_reason=conflict_reason,
    )
    payload_keys = _payload_keys(packet, socket, session, flow, dns, protocol, topology)
    record = {
        "record_type": "packet_metadata_correlation",
        "record_version": METADATA_CORRELATION_RECORD_VERSION,
        "correlation_id": "metadata-correlation-"
        + _digest(
            {
                "packet_reference": _record_ref(packet, "packet"),
                "socket_reference": _record_ref(socket, "socket"),
                "session_reference": _session_ref(session, flow),
                "flow_reference": _flow_ref(flow),
                "dns_reference": _record_ref(dns, "dns"),
                "protocol_hint": protocol_hint,
                "topology_reference": _record_ref(topology, "topology"),
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "correlation_type": _correlation_type(packet=packet, socket=socket, session=session, flow=flow, dns=dns, protocol=protocol, topology=topology),
        "correlation_state": state,
        "source_mode": mode,
        "data_source": mode,
        "observation_id": identity["observation_id"],
        "flow_key": identity["flow_key"],
        "session_id": identity["session_id"],
        "local_address": identity["local_address"],
        "remote_address": identity["remote_address"],
        "local_port": identity["local_port"],
        "remote_port": identity["remote_port"],
        "protocol": identity["protocol"],
        "socket_state": identity["socket_state"],
        "evidence_origin": identity["evidence_origin"],
        "observation_type": identity["observation_type"],
        "identity_scope": identity["identity_scope"],
        "packet_reference": _record_ref(packet, "packet"),
        "socket_reference": _record_ref(socket, "socket"),
        "session_reference": _session_ref(session, flow),
        "flow_reference": _flow_ref(flow),
        "protocol_hint": protocol_hint,
        "destination_class": destination_class,
        "dns_correlation_state": dns_state,
        "topology_correlation_state": topology_state,
        "metadata_confidence": confidence,
        "drift_detected": bool(session.get("drift_detected") or flow.get("drift_detected") or dns.get("drift_detected") or topology.get("drift_detected")),
        "conflict_reason": conflict_reason,
        "advisory_notes": _advisory_notes(state=state, conflict_reason=conflict_reason, payload_keys=payload_keys),
        "payload_fields_ignored": payload_keys,
        "process_correlation": build_process_correlation_record(session or flow or socket or None, generated_at=timestamp),
        **FLOW_SAFETY_FLAGS,
    }
    return record


def build_metadata_correlation_report(
    correlation_inputs: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = normalize_timestamp(generated_at or _now(), preserve_ambiguous=True)
    try:
        bundles = [dict(row) for row in correlation_inputs or [] if isinstance(row, dict)]
    except TypeError as exc:
        raise MetadataCorrelationError("correlation_inputs must be iterable") from exc
    correlations = [
        build_metadata_correlation_record(
            packet_metadata=bundle.get("packet_metadata") or bundle.get("packet"),
            socket_observation=bundle.get("socket_observation") or bundle.get("socket"),
            reconstructed_session=bundle.get("reconstructed_session") or bundle.get("session"),
            flow_pair=bundle.get("flow_pair") or bundle.get("flow"),
            dns_destination_behavior=bundle.get("dns_destination_behavior") or bundle.get("dns") or bundle.get("destination_behavior"),
            protocol_metadata=bundle.get("protocol_metadata") or bundle.get("protocol"),
            topology_relationship=bundle.get("topology_relationship") or bundle.get("topology"),
            generated_at=timestamp,
        )
        for bundle in bundles
    ]
    summary = summarize_metadata_correlations(correlations, generated_at=timestamp)
    return {
        "record_type": "packet_metadata_correlation_report",
        "record_version": METADATA_CORRELATION_RECORD_VERSION,
        "report_id": "metadata-correlation-report-" + _digest({"generated_at": timestamp, "correlations": [row["correlation_id"] for row in correlations]})[:16],
        "generated_at": timestamp,
        "metadata_correlations": correlations,
        "summary": summary,
        "dashboard_status": build_metadata_correlation_dashboard_record(summary=summary, correlations=correlations, generated_at=timestamp),
        "api_status": build_metadata_correlation_api_response(summary=summary, correlations=correlations, generated_at=timestamp),
        **FLOW_SAFETY_FLAGS,
    }


def summarize_metadata_correlations(correlations: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    return {
        "record_type": "packet_metadata_correlation_summary",
        "record_version": METADATA_CORRELATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "correlation_count": len(rows),
        "correlated_count": _count_state(rows, "correlated"),
        "partially_correlated_count": _count_state(rows, "partially_correlated"),
        "uncorrelated_count": _count_state(rows, "uncorrelated"),
        "conflicting_count": _count_state(rows, "conflicting"),
        "unknown_count": _count_state(rows, "unknown"),
        "dns_correlated_count": sum(1 for row in rows if row.get("dns_correlation_state") == "correlated"),
        "topology_correlated_count": sum(1 for row in rows if row.get("topology_correlation_state") == "correlated"),
        "drift_detected_count": sum(1 for row in rows if row.get("drift_detected")),
        "average_metadata_confidence": _average(rows, "metadata_confidence"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **FLOW_SAFETY_FLAGS,
    }


def build_metadata_correlation_dashboard_record(
    *,
    summary: dict[str, Any],
    correlations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("conflicting_count") or 0) or int(summary.get("drift_detected_count") or 0) else "degraded" if int(summary.get("uncorrelated_count") or 0) else "ok"
    return {
        "record_type": "packet_metadata_correlation_dashboard",
        "panel": "packet_metadata_correlation",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "correlation_count": int(summary.get("correlation_count") or 0),
            "correlated_count": int(summary.get("correlated_count") or 0),
            "partially_correlated_count": int(summary.get("partially_correlated_count") or 0),
            "conflicting_count": int(summary.get("conflicting_count") or 0),
            "average_metadata_confidence": float(summary.get("average_metadata_confidence") or 0.0),
        },
        "rows": [
            {
                "correlation_id": row.get("correlation_id"),
                "observation_id": row.get("observation_id"),
                "flow_key": row.get("flow_key"),
                "session_id": row.get("session_id"),
                "evidence_origin": row.get("evidence_origin"),
                "observation_type": row.get("observation_type"),
                "identity_scope": row.get("identity_scope"),
                "correlation_state": row.get("correlation_state"),
                "session_reference": row.get("session_reference"),
                "flow_reference": row.get("flow_reference"),
                "protocol_hint": row.get("protocol_hint"),
                "destination_class": row.get("destination_class"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **FLOW_SAFETY_FLAGS,
    }


def build_metadata_correlation_api_response(
    *,
    summary: dict[str, Any],
    correlations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    return {
        "record_type": "packet_metadata_correlation_api",
        "status": "review_required" if int(summary.get("conflicting_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "metadata_correlations": rows,
        **FLOW_SAFETY_FLAGS,
    }


def classify_metadata_correlation_state(
    *,
    packet: dict[str, Any],
    socket: dict[str, Any],
    session: dict[str, Any],
    flow: dict[str, Any],
    dns_state: str,
    topology_state: str,
    conflict_reason: str = "",
) -> str:
    if conflict_reason:
        return "conflicting"
    present = sum(1 for item in (packet, socket, session, flow) if item)
    if not present:
        return "unknown"
    linked = present
    if dns_state == "correlated":
        linked += 1
    if topology_state == "correlated":
        linked += 1
    if present >= 3 and linked >= 5:
        return "correlated"
    if linked >= 2:
        return "partially_correlated"
    return "uncorrelated"


def score_metadata_confidence(
    *,
    packet: dict[str, Any],
    socket: dict[str, Any],
    session: dict[str, Any],
    flow: dict[str, Any],
    dns_state: str,
    topology_state: str,
    conflict_reason: str = "",
) -> float:
    if conflict_reason:
        return 0.1
    score = 0.0
    if packet:
        score += 0.16
    if socket:
        score += 0.14
    if session:
        score += 0.22
    if flow:
        score += 0.18
    if dns_state == "correlated":
        score += 0.12
    elif dns_state == "partially_correlated":
        score += 0.06
    if topology_state == "correlated":
        score += 0.12
    elif topology_state == "partially_correlated":
        score += 0.06
    if session.get("protocol") not in {None, "", "unknown"} or flow.get("protocol") not in {None, "", "unknown"}:
        score += 0.06
    return round(max(0.0, min(1.0, score)), 3)


def deterministic_metadata_correlation_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _validate_optional_dicts(**records: Any) -> None:
    for name, record in records.items():
        if record is not None and not isinstance(record, dict):
            raise MetadataCorrelationError(f"{name} must be an object")


def _correlation_type(**records: dict[str, Any]) -> str:
    names = sorted(name for name, record in records.items() if record)
    if not names:
        return "unknown"
    mapping = {
        "packet": "packet_metadata",
        "socket": "socket_observation",
        "session": "reconstructed_session",
        "flow": "flow_pair",
        "dns": "dns_destination",
        "protocol": "protocol_metadata",
        "topology": "topology_relationship",
    }
    return "+".join(mapping.get(name, name) for name in names)


def _protocol_hint(*, packet: dict[str, Any], session: dict[str, Any], flow: dict[str, Any], protocol: dict[str, Any]) -> str:
    for row, fields in (
        (protocol, ("application_protocol", "service_hint", "protocol_hint", "protocol")),
        (flow, ("protocol", "transport_protocol")),
        (session, ("protocol", "transport_protocol")),
        (packet, ("protocol", "transport", "transport_protocol")),
    ):
        for field in fields:
            value = row.get(field)
            if value not in {None, ""}:
                return _safe_token(value)
    return "unknown"


def _identity_context(
    *,
    packet: dict[str, Any],
    socket: dict[str, Any],
    session: dict[str, Any],
    flow: dict[str, Any],
    topology: dict[str, Any],
) -> dict[str, Any]:
    sources = (flow, session, socket, packet, topology)
    remote_port = _first_value(sources, ("remote_port", "dst_port", "destination_port"))
    state = _first_text(sources, ("transport_state", "socket_state", "state", "status"))
    identity_scope = _first_text(sources, ("identity_scope",))
    if not identity_scope:
        identity_scope = "listener" if remote_port in {None, ""} or state.lower() in {"listen", "listening"} else "flow"
    evidence_origin = _first_text(sources, ("evidence_origin", "telemetry_source"))
    if not evidence_origin:
        evidence_origin = "listener_socket_observation" if identity_scope == "listener" else "reconstructed_flow"
    observation_type = _first_text(sources, ("observation_type",))
    if not observation_type:
        observation_type = "listener" if identity_scope == "listener" else "socket_conversation"
    return {
        "observation_id": _first_text(sources, ("observation_id", "event_id", "packet_id", "record_id")),
        "flow_key": _first_text(sources, ("flow_key", "flow_id")),
        "session_id": _first_text(sources, ("session_id", "session_ref", "session_reference")),
        "local_address": _first_text(sources, ("local_address", "source_ip", "src_ip")),
        "remote_address": _first_text(sources, ("remote_address", "destination_ip", "dst_ip")),
        "local_port": _first_value(sources, ("local_port", "src_port", "source_port", "port")),
        "remote_port": remote_port,
        "protocol": _first_text(sources, ("protocol", "transport", "transport_protocol")),
        "socket_state": state,
        "evidence_origin": evidence_origin,
        "observation_type": observation_type,
        "identity_scope": identity_scope,
    }


def _first_text(sources: Iterable[dict[str, Any]], fields: tuple[str, ...]) -> str:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for field in fields:
            value = source.get(field)
            if value in {None, ""}:
                continue
            text = str(value).strip()
            if text and text != "-":
                return text
    return ""


def _first_value(sources: Iterable[dict[str, Any]], fields: tuple[str, ...]) -> Any:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for field in fields:
            value = source.get(field)
            if value not in {None, ""}:
                return value
    return None


def _destination_class(
    *,
    dns: dict[str, Any],
    session: dict[str, Any],
    flow: dict[str, Any],
    socket: dict[str, Any],
    packet: dict[str, Any],
    topology: dict[str, Any],
) -> str:
    for row, fields in (
        (dns, ("destination_class", "destination_type", "domain_class")),
        (topology, ("remote_endpoint_class", "target_class", "destination_class")),
        (flow, ("remote_endpoint_class", "destination_class")),
        (session, ("remote_endpoint_class", "destination_class")),
        (socket, ("remote_endpoint_class", "remote_address_class", "destination_class")),
        (packet, ("remote_endpoint_class", "remote_address_class", "destination_class")),
    ):
        for field in fields:
            value = row.get(field)
            if value not in {None, ""}:
                return _safe_token(value)
    return "unknown"


def _dns_state(dns: dict[str, Any]) -> str:
    if not dns:
        return "uncorrelated"
    state = _safe_token(dns.get("dns_correlation_state") or dns.get("correlation_state") or dns.get("state") or "")
    if state in METADATA_CORRELATION_STATES:
        return state
    if dns.get("conflict_reason") or dns.get("conflicting"):
        return "conflicting"
    if dns.get("domain_summary") or dns.get("domain_hash") or dns.get("destination_summary") or dns.get("resolver_class"):
        return "correlated"
    return "partially_correlated"


def _topology_state(topology: dict[str, Any]) -> str:
    if not topology:
        return "uncorrelated"
    state = _safe_token(topology.get("topology_correlation_state") or topology.get("correlation_state") or topology.get("state") or "")
    if state in METADATA_CORRELATION_STATES:
        return state
    if topology.get("conflict_reason") or topology.get("conflicting"):
        return "conflicting"
    if topology.get("relationship_id") or topology.get("edge_id") or topology.get("topology_edge_id"):
        return "correlated"
    return "partially_correlated"


def _conflict_reason(
    *,
    packet: dict[str, Any],
    session: dict[str, Any],
    flow: dict[str, Any],
    dns: dict[str, Any],
    protocol_hint: str,
    topology: dict[str, Any],
) -> str:
    dns_state = _dns_state(dns)
    topology_state = _topology_state(topology)
    if dns_state == "conflicting":
        return "dns_destination_conflict"
    if topology_state == "conflicting":
        return "topology_relationship_conflict"
    packet_protocol = _safe_token(packet.get("protocol") or packet.get("transport") or packet.get("transport_protocol") or "")
    session_protocol = _safe_token(session.get("protocol") or flow.get("protocol") or "")
    if packet_protocol not in {"", "unknown"} and session_protocol not in {"", "unknown"} and packet_protocol != session_protocol:
        return "packet_session_protocol_conflict"
    protocol_family = _safe_token(flow.get("protocol") or session.get("protocol") or "")
    if protocol_hint not in {"", "unknown"} and protocol_family not in {"", "unknown"} and protocol_hint in {"tcp", "udp", "icmp"} and protocol_hint != protocol_family:
        return "protocol_hint_conflict"
    return ""


def _advisory_notes(*, state: str, conflict_reason: str, payload_keys: list[str]) -> list[str]:
    notes = [
        f"metadata correlation state is {state}",
        "metadata-only correlation record; packet payloads and PCAP files are not stored",
    ]
    if conflict_reason:
        notes.append(f"operator review recommended: {conflict_reason}")
    if payload_keys:
        notes.append("payload-like input fields were ignored during export-safe normalization")
    return notes


def _record_ref(record: dict[str, Any], prefix: str) -> str:
    for field in (
        f"{prefix}_reference",
        f"{prefix}_ref",
        f"{prefix}_id",
        "record_id",
        "observation_id",
        "packet_id",
        "socket_id",
        "domain_ref",
        "relationship_id",
        "edge_id",
    ):
        value = record.get(field)
        if value not in {None, ""}:
            return str(value)[:96]
    return ""


def _session_ref(session: dict[str, Any], flow: dict[str, Any]) -> str:
    return str(session.get("session_id") or flow.get("session_ref") or flow.get("session_reference") or "")


def _flow_ref(flow: dict[str, Any]) -> str:
    return str(flow.get("flow_pair_id") or flow.get("flow_id") or flow.get("flow_ref") or "")


def _payload_keys(*records: dict[str, Any]) -> list[str]:
    keys = set()
    for record in records:
        for key in record:
            if str(key).lower() in PAYLOAD_FIELD_NAMES:
                keys.add(str(key))
    return sorted(keys)


def _safe_token(value: Any) -> str:
    text = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return "unknown"
    return text[:80]


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("correlation_state") == state)


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return utc_now_iso()
