from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import logging
import socket
import time
from typing import Any, Callable, Iterable, Protocol

from core_engine.risky_ports import service_name_for_port


UDP_STATES = {"open", "closed", "filtered", "unknown"}
DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1
DEFAULT_MAX_PORTS = 64
DEFAULT_RATE_DELAY = 0.02


class UDPSocket(Protocol):
    def settimeout(self, timeout: float) -> None: ...
    def connect(self, address: tuple[str, int]) -> None: ...
    def send(self, payload: bytes) -> int: ...
    def recv(self, size: int) -> bytes: ...
    def close(self) -> None: ...


SocketFactory = Callable[[socket.AddressFamily, socket.SocketKind, int], UDPSocket]


@dataclass(frozen=True)
class UDPProbe:
    port: int
    name: str
    payload: bytes
    expects_response: bool = True


COMMON_UDP_PROBES: dict[int, UDPProbe] = {
    53: UDPProbe(
        port=53,
        name="DNS",
        payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    ),
    67: UDPProbe(port=67, name="DHCP-server", payload=b"\x01\x01\x06\x00" + (b"\x00" * 236)),
    68: UDPProbe(port=68, name="DHCP-client", payload=b"\x01\x01\x06\x00" + (b"\x00" * 236)),
    123: UDPProbe(port=123, name="NTP", payload=b"\x1b" + (b"\x00" * 47)),
    137: UDPProbe(port=137, name="NetBIOS-NS", payload=b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"),
    138: UDPProbe(port=138, name="NetBIOS-DGM", payload=b"\x10\x02" + (b"\x00" * 12)),
    161: UDPProbe(port=161, name="SNMP", payload=b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x6d\x61\x70\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    5353: UDPProbe(port=5353, name="mDNS", payload=b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_local\x00\x00\x0c\x00\x01"),
}


def _socket_factory(family: socket.AddressFamily, sock_type: socket.SocketKind, proto: int) -> UDPSocket:
    return socket.socket(family, sock_type, proto)


def normalize_udp_ports(ports: Iterable[int]) -> list[int]:
    normalized: list[int] = []
    seen: set[int] = set()
    for raw_port in ports:
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError(f"UDP port must be between 1 and 65535: {raw_port}")
        if port in seen:
            continue
        seen.add(port)
        normalized.append(port)
    return normalized


def default_udp_ports() -> list[int]:
    return sorted(COMMON_UDP_PROBES)


def _resolve_target(target: str, port: int) -> tuple[socket.AddressFamily, tuple[str, int]]:
    try:
        candidates = socket.getaddrinfo(target, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ValueError(f"Invalid UDP target '{target}': {exc}") from exc
    if not candidates:
        raise ValueError(f"Invalid UDP target '{target}': no address candidates")
    family, _, _, _, sockaddr = candidates[0]
    return family, (str(sockaddr[0]), int(sockaddr[1]))


def _format_remote(address: tuple[str, int]) -> str:
    return f"[{address[0]}]:{address[1]}" if ":" in address[0] else f"{address[0]}:{address[1]}"


def _classify_socket_error(exc: OSError) -> tuple[str, str]:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "filtered", "timeout"
    if isinstance(exc, ConnectionRefusedError) or exc.errno in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH}:
        return "closed", "icmp_unreachable"
    if isinstance(exc, PermissionError) or exc.errno in {errno.EACCES, errno.EPERM}:
        return "unknown", "permission_denied"
    return "unknown", exc.__class__.__name__


def _result(
    *,
    target: str,
    address: tuple[str, int] | None,
    port: int,
    state: str,
    reason: str,
    probe: UDPProbe,
    attempts: int,
    response: bytes = b"",
) -> dict[str, Any]:
    service_name = service_name_for_port(port) or probe.name
    remote = _format_remote(address) if address else f"{target}:{port}"
    return {
        "program": "-",
        "pid": 0,
        "port": port,
        "service_name": service_name,
        "payload": "",
        "flags": "",
        "protocol": "UDP",
        "status": state.upper(),
        "udp_state": state,
        "direction": "outgoing",
        "local": "-",
        "remote": remote,
        "target": target,
        "probe": probe.name,
        "attempts": attempts,
        "reason": reason,
        "response_bytes": len(response),
    }


def scan_udp_port(
    target: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    socket_factory: SocketFactory = _socket_factory,
) -> dict[str, Any]:
    """Probe one UDP port and return a JSON-serializable scan row.

    UDP is intentionally conservative: a response means open, an ICMP-style
    connection refused error means closed, and repeated timeout means filtered.
    """
    if timeout <= 0:
        raise ValueError("UDP timeout must be greater than 0")
    if retries < 0:
        raise ValueError("UDP retries must be 0 or greater")
    port = normalize_udp_ports([port])[0]
    probe = COMMON_UDP_PROBES.get(port, UDPProbe(port=port, name=service_name_for_port(port) or "UDP", payload=b""))
    family, address = _resolve_target(target, port)
    sock = socket_factory(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    attempts = 0
    last_state = "unknown"
    last_reason = "not_started"
    try:
        sock.settimeout(timeout)
        sock.connect(address)
        for attempt in range(retries + 1):
            attempts = attempt + 1
            try:
                sock.send(probe.payload)
                response = sock.recv(4096)
                return _result(
                    target=target,
                    address=address,
                    port=port,
                    state="open",
                    reason="udp_response",
                    probe=probe,
                    attempts=attempts,
                    response=response,
                )
            except OSError as exc:
                last_state, last_reason = _classify_socket_error(exc)
                if last_state in {"closed", "unknown"}:
                    break
        return _result(
            target=target,
            address=address,
            port=port,
            state=last_state,
            reason=last_reason,
            probe=probe,
            attempts=attempts,
        )
    finally:
        sock.close()


def scan_udp_target(
    target: str,
    ports: Iterable[int] | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    max_ports: int = DEFAULT_MAX_PORTS,
    rate_delay: float = DEFAULT_RATE_DELAY,
    aggressive: bool = False,
    socket_factory: SocketFactory = _socket_factory,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    """Scan multiple UDP ports with safe defaults and optional structured logging."""
    selected_ports = normalize_udp_ports(ports if ports is not None else default_udp_ports())
    if not aggressive and len(selected_ports) > max_ports:
        raise ValueError(f"UDP scan limited to {max_ports} ports by default; enable aggressive mode to override")
    if rate_delay < 0:
        raise ValueError("UDP rate_delay must be 0 or greater")

    rows: list[dict[str, Any]] = []
    for index, port in enumerate(selected_ports):
        row = scan_udp_port(target, port, timeout=timeout, retries=retries, socket_factory=socket_factory)
        rows.append(row)
        if logger:
            logger.info("udp_scan_result %s", json.dumps(row, sort_keys=True))
        if rate_delay and index < len(selected_ports) - 1:
            time.sleep(rate_delay)
    return rows
