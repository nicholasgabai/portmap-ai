from __future__ import annotations

import socket
from typing import Any, Dict, Iterable, List

from core_engine import platform_utils
from core_engine.risky_ports import service_name_for_port


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


def _fallback_connections() -> List[Dict[str, Any]]:
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
        },
    ]


def basic_scan(kind: str = "inet") -> List[Dict[str, Any]]:
    """Return local host network connections in the legacy worker payload shape.

    Falls back to deterministic demo connections when psutil is unavailable or
    the runtime cannot enumerate sockets.
    """
    try:
        raw_connections = platform_utils.net_connections(kind=kind)
    except Exception:
        return _fallback_connections()
    if not raw_connections:
        return _fallback_connections()

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
    return normalized or _fallback_connections()
