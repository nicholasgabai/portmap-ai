from __future__ import annotations

import socket
from typing import Any, Dict, Iterable, List

from core_engine import platform_utils
from core_engine.risky_ports import service_name_for_port

SOURCE_MODES = frozenset({"live", "simulated", "fixture", "replay", "unknown"})


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

    normalized = _dedupe(normalized)
    normalized.sort(
        key=lambda item: (
            item.get("port", 0),
            item.get("program", ""),
            item.get("pid", 0),
            item.get("local", ""),
            item.get("remote", ""),
        )
    )
    if normalized:
        return normalized
    return _fallback_connections(source_mode=mode if mode in {"fixture", "simulated"} else "simulated") if allow_simulated_fallback or mode in {"fixture", "simulated"} else []
