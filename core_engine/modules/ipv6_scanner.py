from __future__ import annotations

import errno
import json
import logging
import socket
import time
from typing import Any, Callable, Iterable, Protocol

from core_engine.modules.ip_utils import TargetAddress, expand_targets, format_host_port
from core_engine.risky_ports import service_name_for_port


TCP_STATES = {"open", "closed", "filtered", "unknown"}
DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_TARGETS = 64
DEFAULT_MAX_PORTS = 128
DEFAULT_RATE_DELAY = 0.01
AGGRESSIVE_MAX_TARGETS = 4096
AGGRESSIVE_MAX_PORTS = 4096


class TCPSocket(Protocol):
    def settimeout(self, timeout: float) -> None: ...
    def connect_ex(self, address: tuple[Any, ...]) -> int: ...
    def close(self) -> None: ...


SocketFactory = Callable[[socket.AddressFamily, socket.SocketKind, int], TCPSocket]


def _socket_factory(family: socket.AddressFamily, sock_type: socket.SocketKind, proto: int) -> TCPSocket:
    return socket.socket(family, sock_type, proto)


def normalize_tcp_ports(ports: Iterable[int]) -> list[int]:
    normalized: list[int] = []
    seen: set[int] = set()
    for raw_port in ports:
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError(f"TCP port must be between 1 and 65535: {raw_port}")
        if port in seen:
            continue
        seen.add(port)
        normalized.append(port)
    return normalized


def _family_for_target(target: TargetAddress) -> socket.AddressFamily:
    return socket.AF_INET6 if target.version == 6 else socket.AF_INET


def _sockaddr(target: TargetAddress, port: int) -> tuple[Any, ...]:
    if target.version == 6:
        return (target.host, port, 0, 0)
    return (target.host, port)


def _state_from_connect_ex(code: int) -> tuple[str, str]:
    if code == 0:
        return "open", "connect_success"
    if code in {errno.ECONNREFUSED, errno.ECONNRESET}:
        return "closed", "connection_refused"
    if code in {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}:
        return "filtered", errno.errorcode.get(code, str(code)).lower()
    if code in {errno.EACCES, errno.EPERM}:
        return "unknown", "permission_denied"
    return "unknown", errno.errorcode.get(code, str(code)).lower()


def _result(target: TargetAddress, port: int, state: str, reason: str) -> dict[str, Any]:
    return {
        "program": "-",
        "pid": 0,
        "port": port,
        "service_name": service_name_for_port(port) or "",
        "payload": "",
        "flags": "",
        "protocol": "TCP",
        "status": state.upper(),
        "tcp_state": state,
        "direction": "outgoing",
        "local": "-",
        "remote": format_host_port(target.host, port),
        "target": target.host,
        "ip_version": target.version,
        "target_source": target.source,
        "reason": reason,
    }


def scan_tcp_port(
    target: TargetAddress,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    socket_factory: SocketFactory = _socket_factory,
) -> dict[str, Any]:
    """Probe one IPv4 or IPv6 TCP port using connect_ex."""
    if timeout <= 0:
        raise ValueError("TCP timeout must be greater than 0")
    port = normalize_tcp_ports([port])[0]
    sock = socket_factory(_family_for_target(target), socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        sock.settimeout(timeout)
        code = sock.connect_ex(_sockaddr(target, port))
        state, reason = _state_from_connect_ex(int(code or 0))
        return _result(target, port, state, reason)
    finally:
        sock.close()


def scan_dual_stack_targets(
    targets: str | Iterable[str],
    ports: Iterable[int],
    *,
    ip_version: str | int | None = "auto",
    timeout: float = DEFAULT_TIMEOUT,
    max_targets: int = DEFAULT_MAX_TARGETS,
    max_ports: int = DEFAULT_MAX_PORTS,
    rate_delay: float = DEFAULT_RATE_DELAY,
    aggressive: bool = False,
    socket_factory: SocketFactory = _socket_factory,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    """Scan IPv4 and/or IPv6 targets with conservative limits."""
    target_limit = max(max_targets, AGGRESSIVE_MAX_TARGETS) if aggressive else max_targets
    port_limit = max(max_ports, AGGRESSIVE_MAX_PORTS) if aggressive else max_ports
    selected_targets = expand_targets(targets, ip_version=ip_version, max_targets=target_limit)
    selected_ports = normalize_tcp_ports(ports)
    if not aggressive and len(selected_targets) > max_targets:
        raise ValueError(f"target scan limited to {max_targets} targets by default; enable aggressive mode to override")
    if not aggressive and len(selected_ports) > max_ports:
        raise ValueError(f"target scan limited to {max_ports} ports by default; enable aggressive mode to override")
    if aggressive and len(selected_targets) > target_limit:
        raise ValueError(f"target scan exceeds aggressive target limit of {target_limit}")
    if aggressive and len(selected_ports) > port_limit:
        raise ValueError(f"target scan exceeds aggressive port limit of {port_limit}")
    if rate_delay < 0:
        raise ValueError("TCP rate_delay must be 0 or greater")

    rows: list[dict[str, Any]] = []
    total = len(selected_targets) * len(selected_ports)
    completed = 0
    for target in selected_targets:
        for port in selected_ports:
            row = scan_tcp_port(target, port, timeout=timeout, socket_factory=socket_factory)
            rows.append(row)
            completed += 1
            if logger:
                logger.info("dual_stack_scan_result %s", json.dumps(row, sort_keys=True))
            if rate_delay and completed < total:
                time.sleep(rate_delay)
    return rows
