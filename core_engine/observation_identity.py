"""Canonical identity for metadata observations; no collection or runtime state."""

from __future__ import annotations

import ipaddress
import json
from hashlib import sha256
from typing import Any

from core_engine.time_utils import normalize_timestamp


IDENTITY_VERSION = 2


def _first(row: dict[str, Any], *keys: str) -> Any:
    return next((row[key] for key in keys if row.get(key) not in (None, "", "-")), None)


def split_endpoint(value: Any) -> tuple[str, int | None]:
    text = str(value or "").strip()
    if text in {"", "-"}:
        return "", None
    if text.startswith("[") and "]" in text:
        host, _, suffix = text[1:].partition("]")
        return normalize_address(host), _port(suffix.removeprefix(":"))
    # Unbracketed IPv6 addresses are addresses, never guessed host:port pairs.
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        host, separator, port = text.rpartition(":")
        if separator and text.count(":") == 1 and _port(port) is not None:
            return normalize_address(host), _port(port)
        return normalize_address(text), None


def normalize_address(value: Any) -> str:
    text = str(value or "").strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return "" if text == "-" else text


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def identity_basis(row: dict[str, Any], *, node_id: str = "") -> dict[str, Any]:
    local, local_port = split_endpoint(row.get("local"))
    remote, remote_port = split_endpoint(row.get("remote"))
    local = normalize_address(_first(row, "local_address", "local_ip", "src_ip", "source_ip") or local)
    remote = normalize_address(_first(row, "remote_address", "remote_ip", "dst_ip", "destination_ip") or remote)
    explicit_local_port = _first(row, "local_port", "src_port", "source_port", "port")
    explicit_remote_port = _first(row, "remote_port", "dst_port", "destination_port")
    local_port = _port(explicit_local_port if explicit_local_port is not None else local_port)
    remote_port = _port(explicit_remote_port if explicit_remote_port is not None else remote_port)
    protocol = str(_first(row, "transport_protocol", "transport", "protocol") or "unknown").lower()
    state = str(_first(row, "transport_state", "socket_state", "status", "state") or "unknown").lower()
    if protocol not in {"tcp", "udp", "icmp", "icmpv6"}:
        protocol = "tcp" if state in {"listen", "listening", "established"} else "unknown"
    listener = state in {"listen", "listening"} or row.get("identity_scope") == "listener"
    scope = "listener" if listener else "flow" if local and remote and local_port is not None and remote_port is not None else "socket"
    if listener:
        remote, remote_port = "", None
    families = set()
    for address in (local, remote):
        try:
            families.add(ipaddress.ip_address(address).version)
        except ValueError:
            pass
    family = f"ipv{next(iter(families))}" if len(families) == 1 else "unknown"
    direction = str(_first(row, "flow_direction", "direction") or "unknown_direction").lower()
    if direction not in {"inbound", "outbound", "local_loopback"}:
        direction = "unknown_direction"
        if scope != "listener":
            loopback_classes = row.get("local_endpoint_class") == row.get("remote_endpoint_class") == "loopback"
            if (local in {"127.0.0.1", "::1"} and remote in {"127.0.0.1", "::1"}) or (not local and not remote and loopback_classes):
                direction = "local_loopback"
            elif local_port is not None and remote_port is not None and local_port < 49152 <= remote_port:
                direction = "inbound"
            elif local_port is not None and remote_port is not None and remote_port < 49152 <= local_port:
                direction = "outbound"
    return {
        "node_id": str(node_id or _first(row, "node_id", "node") or ""),
        "local_address": local, "remote_address": remote,
        "local_port": local_port, "remote_port": remote_port,
        "protocol": protocol, "address_family": family,
        "identity_scope": scope,
        "flow_direction": direction,
        "source_mode": str(_first(row, "source_mode") or "unknown").lower(),
        "telemetry_source": str(_first(row, "telemetry_source") or "socket_inventory"),
    }


def identity_key(row: dict[str, Any], *, node_id: str = "") -> str:
    return json.dumps(identity_basis(row, node_id=node_id), sort_keys=True, separators=(",", ":"))


def _id(prefix: str, value: Any) -> str:
    return prefix + sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]


def observation_identity(row: dict[str, Any], *, node_id: str = "", event_timestamp: Any = None) -> dict[str, Any]:
    basis = identity_basis(row, node_id=node_id)
    instant = row.get("event_timestamp") if "event_timestamp" in row else _first(row, "timestamp", "observed_at") or event_timestamp
    instant = normalize_timestamp(instant, preserve_ambiguous=True)
    observation_id = _first(row, "observation_id", "event_id", "packet_id", "record_id")
    # A stable reference needs an observed time or an existing upstream ID.
    if not observation_id and instant:
        observation_id = _id("socket-observation-", {
            **basis, "event_timestamp": instant,
            "state": str(_first(row, "transport_state", "socket_state", "status", "state") or "unknown").lower(),
        })
    session = _first(row, "session_id", "session_ref", "session_reference")
    if basis["identity_scope"] == "listener":
        session = ""
    elif not session and basis["identity_scope"] == "flow":
        session = _id("flow-session-", basis)
    flow = ""
    if basis["identity_scope"] == "flow":
        flow = _first(row, "flow_key", "flow_id") or _id("flow-key-", basis)
    result = {
        **basis, "identity_version": IDENTITY_VERSION,
        "observation_id": observation_id or "", "session_id": session or "", "flow_key": flow,
        "observation_type": "listener" if basis["identity_scope"] == "listener" else "established_conversation" if str(_first(row, "transport_state", "socket_state", "status", "state") or "").lower() == "established" else "socket_conversation",
        "evidence_origin": _first(row, "evidence_origin") or ("listener_socket_observation" if basis["identity_scope"] == "listener" else "reconstructed_socket_flow"),
    }
    if basis["identity_scope"] == "listener":
        # Old aliases must not reintroduce conversation IDs downstream.
        result.update({key: "" for key in ("session_ref", "session_reference", "flow_id") if key in row})
    return result
