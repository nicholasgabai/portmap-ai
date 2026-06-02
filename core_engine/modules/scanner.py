from __future__ import annotations

import socket
from hashlib import sha256
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List

from core_engine import platform_utils
from core_engine.risky_ports import service_name_for_port

SOURCE_MODES = frozenset({"live", "simulated", "fixture", "replay", "unknown"})
DEFAULT_MAX_SCAN_OBSERVATIONS = 128
DEFAULT_TRANSIENT_STATUSES = frozenset({"TIME_WAIT"})


def _normalize_source_mode(value: Any) -> str:
    mode = str(value or "live").strip().lower()
    return mode if mode in SOURCE_MODES else "unknown"


def _format_address(addr: Any) -> str:
    if not addr:
        return "-"
    host = getattr(addr, "ip", None)
    port = getattr(addr, "port", None)
    if host is None and isinstance(addr, tuple):
        if not addr:
            return "-"
        host = addr[0]
        port = addr[1] if len(addr) > 1 else None
    if host is None:
        return "-"
    return f"{host}:{port}" if port is not None else str(host)


def _split_host_port(value: Any) -> tuple[str, int | None]:
    text = str(value or "").strip()
    if text in {"", "-"}:
        return "", None
    if text.startswith("[") and "]" in text:
        host, _, tail = text[1:].partition("]")
        port_text = tail[1:] if tail.startswith(":") else ""
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
    else:
        host, port_text = text, ""
    try:
        port = int(port_text) if port_text else None
    except ValueError:
        port = None
    return host, port


def _address_class(value: Any) -> str:
    host, _ = _split_host_port(value)
    if not host:
        return "none"
    try:
        address = ip_address(host)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_unspecified:
        return "unspecified"
    if address.is_multicast:
        return "multicast"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private_or_documentation"
    if address.is_global:
        return "global"
    return "other"


def _get_process_name(pid: int | None) -> str:
    return platform_utils.process_name(pid)


def _infer_direction(status: str, remote: str) -> str:
    if status == "LISTEN":
        return "incoming"
    if remote != "-":
        return "outgoing"
    return "unknown"


def _infer_flags(status: str) -> str:
    if status == "LISTEN":
        return "L"
    if status == "ESTABLISHED":
        return "E"
    if status == "CLOSE_WAIT":
        return "CW"
    if status == "TIME_WAIT":
        return "TW"
    return ""


def _normalize_protocol(sock_type: Any) -> str:
    if sock_type == socket.SOCK_STREAM:
        return "TCP"
    if sock_type == socket.SOCK_DGRAM:
        return "UDP"
    return "Unknown"


def _dedupe(connections: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique: List[Dict[str, Any]] = []
    for conn in connections:
        key = (
            conn.get("pid"),
            conn.get("program"),
            conn.get("local"),
            conn.get("remote"),
            conn.get("status"),
            conn.get("protocol"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(conn)
    return unique


def scan_snapshot_key(connection: Dict[str, Any], *, node_id: str = "") -> tuple:
    local = connection.get("local")
    remote = connection.get("remote")
    _, remote_port = _split_host_port(remote)
    return (
        str(node_id or connection.get("node_id") or ""),
        _address_class(local),
        int(connection.get("port") or 0),
        _address_class(remote),
        remote_port or 0,
        str(connection.get("protocol") or "Unknown").upper(),
        str(connection.get("status") or connection.get("state") or "UNKNOWN").upper(),
        str(connection.get("program") or connection.get("service_name") or "Unattributed").lower(),
        _normalize_source_mode(connection.get("source_mode") or connection.get("data_source") or "live"),
    )


def normalize_scan_snapshot(
    connections: Iterable[Dict[str, Any]],
    *,
    node_id: str = "",
    max_observations: int = DEFAULT_MAX_SCAN_OBSERVATIONS,
    prune_transient: bool = True,
    transient_statuses: Iterable[str] = DEFAULT_TRANSIENT_STATUSES,
) -> List[Dict[str, Any]]:
    """Return a bounded, deduplicated current scan snapshot."""
    transient = {str(status).upper() for status in transient_statuses}
    unique: dict[tuple, Dict[str, Any]] = {}
    for raw in connections or []:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        mode = _normalize_source_mode(row.get("source_mode") or row.get("data_source") or "live")
        status = str(row.get("status") or row.get("state") or "UNKNOWN").upper()
        if prune_transient and mode == "live" and status in transient:
            continue
        if str(row.get("program") or "").strip() in {"dummy_app", "dummy_db"} and mode not in {"simulated", "fixture"}:
            row["program"] = "Unattributed"
            row["attribution_status"] = "unattributed"
        row["source_mode"] = mode
        row.setdefault("data_source", "local_socket_inventory" if mode == "live" else mode)
        row.setdefault("attribution_status", "matched" if row.get("pid") else "unattributed")
        key = scan_snapshot_key(row, node_id=node_id)
        row["scan_snapshot_key"] = "|".join(str(part) for part in key)
        row["current_snapshot"] = True
        unique.setdefault(key, row)
    rows = sorted(
        unique.values(),
        key=lambda item: (
            int(item.get("port") or 0),
            str(item.get("program") or ""),
            str(item.get("protocol") or ""),
            str(item.get("status") or ""),
            str(item.get("local") or ""),
            str(item.get("remote") or ""),
        ),
    )
    limit = max(0, int(max_observations))
    return rows[:limit] if limit else []


def scan_snapshot_id(rows: Iterable[Dict[str, Any]], *, node_id: str = "") -> str:
    material = json_safe_snapshot(rows, node_id=node_id)
    return "scan-snapshot-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def json_safe_snapshot(rows: Iterable[Dict[str, Any]], *, node_id: str = "") -> str:
    parts = sorted(str(scan_snapshot_key(row, node_id=node_id)) for row in rows or [] if isinstance(row, dict))
    return "\n".join(parts)


def _fallback_connections(*, source_mode: str = "simulated") -> List[Dict[str, Any]]:
    mode = _normalize_source_mode(source_mode)
    return [
        {
            "program": "dummy_app",
            "pid": 1234,
            "port": 8080,
            "service_name": "HTTP-alt",
            "payload": "GET /",
            "flags": "S",
            "protocol": "HTTP",
            "status": "LISTEN",
            "direction": "incoming",
            "local": "127.0.0.1:8080",
            "remote": "-",
            "source_mode": mode,
            "data_source": mode,
            "attribution_status": "simulated",
        },
        {
            "program": "dummy_db",
            "pid": 5678,
            "port": 3306,
            "service_name": "MySQL",
            "payload": "SELECT * FROM users;",
            "flags": "",
            "protocol": "MySQL",
            "status": "LISTEN",
            "direction": "incoming",
            "local": "127.0.0.1:3306",
            "remote": "-",
            "source_mode": mode,
            "data_source": mode,
            "attribution_status": "simulated",
        },
    ]


def basic_scan(kind: str = "inet", *, source_mode: str = "live", allow_simulated_fallback: bool = False) -> List[Dict[str, Any]]:
    """Return local host network connections in the legacy worker payload shape.

    Deterministic dummy connections are only emitted for explicit fixture or
    simulation mode. Live/default mode returns no rows when the runtime cannot
    enumerate sockets, avoiding misleading dummy labels in operator views.
    """
    mode = _normalize_source_mode(source_mode)
    try:
        raw_connections = platform_utils.net_connections(kind=kind)
    except Exception:
        return _fallback_connections(source_mode=mode if mode in {"fixture", "simulated"} else "simulated") if allow_simulated_fallback or mode in {"fixture", "simulated"} else []
    if not raw_connections:
        return _fallback_connections(source_mode=mode if mode in {"fixture", "simulated"} else "simulated") if allow_simulated_fallback or mode in {"fixture", "simulated"} else []

    normalized: List[Dict[str, Any]] = []
    for conn in raw_connections:
        if not conn.laddr:
            continue

        local = _format_address(conn.laddr)
        remote = _format_address(conn.raddr)
        port = getattr(conn.laddr, "port", None)
        status = conn.status or "UNKNOWN"
        protocol = _normalize_protocol(getattr(conn, "type", None))
        if protocol == "Unknown":
            protocol = "TCP" if status else "Unknown"

        normalized.append(
            {
                "program": _get_process_name(conn.pid),
                "pid": conn.pid or 0,
                "port": int(port or 0),
                "service_name": service_name_for_port(port) or "",
                "payload": "",
                "flags": _infer_flags(status),
                "protocol": protocol,
                "status": status,
                "direction": _infer_direction(status, remote),
                "local": local,
                "remote": remote,
                "source_mode": mode,
                "data_source": "local_socket_inventory" if mode == "live" else mode,
                "attribution_status": "matched" if conn.pid else "unattributed",
            }
        )

    normalized = normalize_scan_snapshot(_dedupe(normalized), prune_transient=True)
    if normalized:
        return normalized
    return _fallback_connections(source_mode=mode if mode in {"fixture", "simulated"} else "simulated") if allow_simulated_fallback or mode in {"fixture", "simulated"} else []
