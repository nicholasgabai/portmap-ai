from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.flows import SERVICE_PORTS
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


FLOW_OBSERVATION_RECORD_VERSION = 1
DEFAULT_LOCAL_CIDRS = ("203.0.113.0/24", "2001:db8:100::/48")

FLOW_OBSERVATION_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "metadata_only": True,
    "raw_payload_rendered": False,
    "payload_bytes_stored": 0,
    "automatic_blocking": False,
    "traffic_injection": False,
}


def build_enriched_flow_observation(
    flow: dict[str, Any],
    *,
    previous_observation: dict[str, Any] | None = None,
    local_cidrs: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a metadata-only enrichment record for one reconstructed flow."""
    timestamp = generated_at or _now()
    row = dict(flow or {})
    initiator = _endpoint(row.get("initiator"))
    responder = _endpoint(row.get("responder"))
    endpoint_classification = classify_flow_endpoints(initiator=initiator, responder=responder, local_cidrs=local_cidrs)
    direction = infer_flow_direction(endpoint_classification)
    service_hint = correlate_service_port_hint(row)
    quality_flags = build_flow_quality_flags(flow=row, direction=direction, service_hint=service_hint)
    confidence = score_flow_observation_confidence(flow=row, quality_flags=quality_flags, service_hint=service_hint)
    counters = build_flow_counter_summary(row)
    transition = build_flow_state_transition(
        previous_observation=previous_observation,
        current_flow=row,
        current_direction=direction,
        current_service_hint=service_hint,
        counters=counters,
        generated_at=timestamp,
    )
    observation = {
        "record_type": "enriched_flow_observation",
        "record_version": FLOW_OBSERVATION_RECORD_VERSION,
        "generated_at": timestamp,
        "flow_ref": str(row.get("flow_id") or ""),
        "flow_digest": str(row.get("flow_digest") or ""),
        "flow_key": str(row.get("flow_key") or ""),
        "transport_protocol": str(row.get("transport_protocol") or "unknown"),
        "classification": str(row.get("classification") or "unknown"),
        "ephemeral_or_persistent": str(row.get("ephemeral_or_persistent") or "unknown"),
        "first_seen": str(row.get("first_seen") or ""),
        "last_seen": str(row.get("last_seen") or ""),
        "duration_seconds": int(row.get("duration_seconds") or 0),
        "initiator": initiator,
        "responder": responder,
        "endpoint_classification": endpoint_classification,
        "direction": direction,
        "service_port_hint": service_hint,
        "counters": counters,
        "state_transition": transition,
        "confidence": confidence,
        "telemetry_quality_flags": quality_flags,
        "interface_names": sorted(str(item) for item in row.get("interface_names") or []),
        "source_node_ids": sorted(str(item) for item in row.get("source_node_ids") or []),
        "source_refs": sorted(str(item) for item in row.get("source_refs") or []),
        "topology_edge_ref": str((row.get("topology_edge") or {}).get("edge_id") if isinstance(row.get("topology_edge"), dict) else ""),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }
    observation["observation_id"] = "flow-observation-" + _digest(
        {
            "flow_ref": observation["flow_ref"],
            "flow_digest": observation["flow_digest"],
            "first_seen": observation["first_seen"],
            "last_seen": observation["last_seen"],
            "generated_at": observation["generated_at"],
        }
    )[:16]
    return observation


def classify_flow_endpoints(
    *,
    initiator: dict[str, Any],
    responder: dict[str, Any],
    local_cidrs: Iterable[str] | None = None,
) -> dict[str, Any]:
    networks = _parse_networks(local_cidrs or DEFAULT_LOCAL_CIDRS)
    return {
        "record_type": "flow_endpoint_classification",
        "initiator": classify_endpoint_scope(initiator, networks=networks),
        "responder": classify_endpoint_scope(responder, networks=networks),
        "local_cidr_count": len(networks),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def classify_endpoint_scope(endpoint: dict[str, Any], *, networks: Iterable[ipaddress._BaseNetwork]) -> dict[str, Any]:
    ip_value = str((endpoint or {}).get("ip") or "")
    port = _safe_port((endpoint or {}).get("port"))
    scope = "unknown"
    family = "unknown"
    if ip_value:
        try:
            address = ipaddress.ip_address(ip_value)
            family = "ipv6" if address.version == 6 else "ipv4"
            scope = "local" if any(address in network for network in networks) else "remote"
        except ValueError:
            scope = "malformed"
    return {
        "ip": ip_value,
        "port": port,
        "address_family": family,
        "endpoint_scope": scope,
        "service_port_known": port in SERVICE_PORTS if port is not None else False,
    }


def infer_flow_direction(endpoint_classification: dict[str, Any]) -> dict[str, Any]:
    initiator_scope = str((endpoint_classification.get("initiator") or {}).get("endpoint_scope") or "unknown")
    responder_scope = str((endpoint_classification.get("responder") or {}).get("endpoint_scope") or "unknown")
    direction = "unknown"
    if initiator_scope == "local" and responder_scope == "remote":
        direction = "outbound"
    elif initiator_scope == "remote" and responder_scope == "local":
        direction = "inbound"
    elif initiator_scope == "local" and responder_scope == "local":
        direction = "internal"
    elif initiator_scope == "remote" and responder_scope == "remote":
        direction = "external"
    return {
        "record_type": "flow_direction_inference",
        "direction": direction,
        "initiator_scope": initiator_scope,
        "responder_scope": responder_scope,
        "confidence": 0.9 if direction != "unknown" else 0.2,
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def correlate_service_port_hint(flow: dict[str, Any]) -> dict[str, Any]:
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    service_port = _safe_port(service.get("service_port"))
    if service_port is None:
        service_port = _known_endpoint_port(flow)
    service_name = str(service.get("service_name") or SERVICE_PORTS.get(service_port, "unknown"))
    return {
        "record_type": "service_port_hint",
        "service_port": service_port,
        "service_name": service_name,
        "service_endpoint": str(service.get("service_endpoint") or "unknown"),
        "known_service_port": service_port in SERVICE_PORTS if service_port is not None else False,
        "source": "flow_service_association" if service else "endpoint_port_heuristic" if service_port is not None else "none",
        "confidence": round(float(service.get("confidence") or (0.65 if service_port in SERVICE_PORTS else 0.3 if service_port is not None else 0.0)), 3),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def build_flow_counter_summary(flow: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_type": "flow_counter_summary",
        "packet_count": int(flow.get("packet_count") or 0),
        "byte_count": int(flow.get("byte_count") or 0),
        "forward_packet_count": int(flow.get("forward_packet_count") or 0),
        "reverse_packet_count": int(flow.get("reverse_packet_count") or 0),
        "duration_seconds": int(flow.get("duration_seconds") or 0),
        "packet_digest_count": len(flow.get("packet_digests") or []),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def build_flow_state_transition(
    *,
    previous_observation: dict[str, Any] | None,
    current_flow: dict[str, Any],
    current_direction: dict[str, Any],
    current_service_hint: dict[str, Any],
    counters: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not previous_observation:
        return _transition(
            state="new",
            reasons=["new_flow_observation"],
            previous_counters={},
            current_counters=counters,
            generated_at=timestamp,
        )
    previous_counters = dict(previous_observation.get("counters") or {})
    reasons: list[str] = []
    if int(counters.get("packet_count") or 0) > int(previous_counters.get("packet_count") or 0):
        reasons.append("packet_count_increased")
    if int(counters.get("byte_count") or 0) > int(previous_counters.get("byte_count") or 0):
        reasons.append("byte_count_increased")
    if str(current_flow.get("classification") or "") != str(previous_observation.get("classification") or ""):
        reasons.append("classification_changed")
    previous_direction = (previous_observation.get("direction") or {}).get("direction") if isinstance(previous_observation.get("direction"), dict) else previous_observation.get("direction")
    if str(current_direction.get("direction") or "") != str(previous_direction or ""):
        reasons.append("direction_changed")
    previous_service = previous_observation.get("service_port_hint") if isinstance(previous_observation.get("service_port_hint"), dict) else {}
    if str(current_service_hint.get("service_name") or "") != str(previous_service.get("service_name") or ""):
        reasons.append("service_hint_changed")
    return _transition(
        state="changed" if reasons else "unchanged",
        reasons=reasons or ["no_counter_or_state_change"],
        previous_counters=previous_counters,
        current_counters=counters,
        generated_at=timestamp,
    )


def build_flow_quality_flags(*, flow: dict[str, Any], direction: dict[str, Any], service_hint: dict[str, Any]) -> dict[str, Any]:
    initiator = flow.get("initiator") if isinstance(flow.get("initiator"), dict) else {}
    responder = flow.get("responder") if isinstance(flow.get("responder"), dict) else {}
    classification = str(flow.get("classification") or "unknown")
    flags = {
        "record_type": "flow_telemetry_quality_flags",
        "complete_flow": classification == "complete",
        "partial_flow": classification == "partial",
        "malformed_flow": classification == "malformed",
        "missing_endpoint": not initiator.get("ip") or not responder.get("ip"),
        "direction_known": str(direction.get("direction") or "unknown") != "unknown",
        "service_known": str(service_hint.get("service_name") or "unknown") != "unknown",
        "counter_data_present": int(flow.get("packet_count") or 0) > 0 and int(flow.get("byte_count") or 0) > 0,
        "metadata_only": True,
        "raw_payload_stored": False,
        "payload_bytes_stored": 0,
    }
    flags["quality_level"] = _quality_level(flags)
    return {**flags, **FLOW_OBSERVATION_SAFETY_FLAGS}


def score_flow_observation_confidence(
    *,
    flow: dict[str, Any],
    quality_flags: dict[str, Any],
    service_hint: dict[str, Any],
) -> float:
    score = 0.25
    if quality_flags.get("complete_flow"):
        score += 0.25
    elif quality_flags.get("partial_flow"):
        score += 0.1
    if quality_flags.get("direction_known"):
        score += 0.15
    if quality_flags.get("service_known"):
        score += min(0.2, float(service_hint.get("confidence") or 0.0) * 0.2)
    if quality_flags.get("counter_data_present"):
        score += 0.1
    if flow.get("source_refs") or flow.get("packet_digests"):
        score += 0.05
    if quality_flags.get("malformed_flow") or quality_flags.get("missing_endpoint"):
        score -= 0.3
    return round(max(0.0, min(1.0, score)), 3)


def deterministic_flow_observation_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _transition(
    *,
    state: str,
    reasons: list[str],
    previous_counters: dict[str, Any],
    current_counters: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    return {
        "record_type": "flow_state_transition_summary",
        "generated_at": generated_at,
        "state": state,
        "reasons": sorted(reasons),
        "previous_counters": previous_counters,
        "current_counters": current_counters,
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def _quality_level(flags: dict[str, Any]) -> str:
    if flags.get("malformed_flow") or flags.get("missing_endpoint"):
        return "poor"
    if flags.get("complete_flow") and flags.get("direction_known") and flags.get("service_known"):
        return "high"
    if flags.get("partial_flow") or not flags.get("service_known"):
        return "medium"
    return "low"


def _endpoint(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"ip": str(value.get("ip") or ""), "port": _safe_port(value.get("port"))}
    return {"ip": "", "port": None}


def _known_endpoint_port(flow: dict[str, Any]) -> int | None:
    ports = []
    for endpoint_name in ("responder", "initiator"):
        endpoint = flow.get(endpoint_name) if isinstance(flow.get(endpoint_name), dict) else {}
        port = _safe_port(endpoint.get("port"))
        if port is not None:
            ports.append(port)
    known = [port for port in ports if port in SERVICE_PORTS]
    return known[0] if known else min(ports) if ports else None


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


def _parse_networks(values: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    return networks


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
