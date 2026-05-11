from __future__ import annotations

import errno
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from core_engine.modules.ip_utils import TargetAddress, expand_targets, format_host_port


DEFAULT_TIMEOUT = 2.0
DEFAULT_MAX_TARGETS = 64
DEFAULT_MAX_PORTS = 128
DEFAULT_RATE_DELAY = 0.01
AGGRESSIVE_MAX_TARGETS = 1024
AGGRESSIVE_MAX_PORTS = 4096
COMMON_ENUMERATION_PORTS = (
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    5985,
    6379,
    8080,
    8443,
    9200,
    27017,
)
PACKAGE_FINGERPRINTS = Path(__file__).resolve().parents[1] / "service_fingerprints.json"
REPO_FINGERPRINTS = Path(__file__).resolve().parents[2] / "data" / "service_fingerprints.json"


class ServiceSocket(Protocol):
    def settimeout(self, timeout: float) -> None: ...
    def connect_ex(self, address: tuple[Any, ...]) -> int: ...
    def sendall(self, data: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...
    def close(self) -> None: ...


SocketFactory = Callable[[socket.AddressFamily, socket.SocketKind, int], ServiceSocket]
TLSWrapper = Callable[[ServiceSocket, str], ServiceSocket]


@dataclass(frozen=True)
class ServiceFingerprint:
    name: str
    default_ports: tuple[int, ...] = ()
    banner_patterns: tuple[str, ...] = ()
    probes: tuple[str, ...] = ()


@dataclass
class ServiceDetectionResult:
    target: str
    port: int
    ip_version: int
    state: str
    service: str = "unknown"
    version: str = ""
    confidence: float = 0.0
    banner: str = ""
    probe: str = ""
    evidence: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "remote": format_host_port(self.target, self.port),
            "ip_version": self.ip_version,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "confidence": self.confidence,
            "banner": self.banner,
            "probe": self.probe,
            "evidence": list(self.evidence),
            "reason": self.reason,
        }


def _socket_factory(family: socket.AddressFamily, sock_type: socket.SocketKind, proto: int) -> ServiceSocket:
    return socket.socket(family, sock_type, proto)


def _tls_wrapper(sock: ServiceSocket, server_hostname: str) -> ServiceSocket:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=server_hostname)  # type: ignore[arg-type]


def load_fingerprints(path: str | Path | None = None) -> list[ServiceFingerprint]:
    selected_path = Path(path) if path else REPO_FINGERPRINTS if REPO_FINGERPRINTS.exists() else PACKAGE_FINGERPRINTS
    with open(selected_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    fingerprints: list[ServiceFingerprint] = []
    for raw in payload.get("services", []):
        fingerprints.append(
            ServiceFingerprint(
                name=str(raw.get("name") or "unknown"),
                default_ports=tuple(int(port) for port in raw.get("default_ports", [])),
                banner_patterns=tuple(str(pattern) for pattern in raw.get("banner_patterns", [])),
                probes=tuple(str(probe) for probe in raw.get("probes", [])),
            )
        )
    return fingerprints


def normalize_service_ports(ports: Iterable[int] | None = None) -> list[int]:
    selected = COMMON_ENUMERATION_PORTS if ports is None else ports
    normalized: list[int] = []
    seen: set[int] = set()
    for raw_port in selected:
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError(f"service port must be between 1 and 65535: {raw_port}")
        if port in seen:
            continue
        seen.add(port)
        normalized.append(port)
    return normalized


def fingerprint_for_port(port: int, fingerprints: Iterable[ServiceFingerprint] | None = None) -> ServiceFingerprint | None:
    for fingerprint in fingerprints or load_fingerprints():
        if port in fingerprint.default_ports:
            return fingerprint
    return None


def _family_for_target(target: TargetAddress) -> socket.AddressFamily:
    return socket.AF_INET6 if target.version == 6 else socket.AF_INET


def _sockaddr(target: TargetAddress, port: int) -> tuple[Any, ...]:
    return (target.host, port, 0, 0) if target.version == 6 else (target.host, port)


def _state_from_connect_ex(code: int) -> tuple[str, str]:
    if code == 0:
        return "open", "connect_success"
    if code in {errno.ECONNREFUSED, errno.ECONNRESET}:
        return "closed", "connection_refused"
    if code in {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}:
        return "filtered", errno.errorcode.get(code, str(code)).lower()
    return "unknown", errno.errorcode.get(code, str(code)).lower()


def _read_banner(sock: ServiceSocket, timeout: float) -> str:
    sock.settimeout(timeout)
    try:
        data = sock.recv(2048)
    except socket.timeout:
        return ""
    except Exception:
        return ""
    return data.decode("utf-8", errors="replace").strip()


def _send_probe(sock: ServiceSocket, probe: str, target: TargetAddress, timeout: float) -> str:
    payloads = {
        "http_head": f"HEAD / HTTP/1.1\r\nHost: {target.host}\r\nConnection: close\r\n\r\n".encode("ascii"),
        "smtp_ehlo": b"EHLO portmap-ai.local\r\n",
    }
    payload = payloads.get(probe)
    if not payload:
        return ""
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        data = sock.recv(4096)
    except Exception:
        return ""
    return data.decode("utf-8", errors="replace").strip()


def _extract_version(service: str, banner: str) -> str:
    if not banner:
        return ""
    if service == "SSH":
        match = re.search(r"SSH-\d+(?:\.\d+)?-([^\s]+)", banner)
        return match.group(1) if match else ""
    if service in {"HTTP", "HTTPS"}:
        match = re.search(r"(?im)^Server:\s*([^\r\n]+)", banner)
        return match.group(1).strip() if match else ""
    if service in {"FTP", "SMTP"}:
        first_line = banner.splitlines()[0] if banner.splitlines() else banner
        return first_line[:120]
    if service == "MySQL":
        match = re.search(r"\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\x00\s]*)", banner)
        return match.group(1) if match else ""
    if service == "Redis":
        match = re.search(r"redis_version:([^\r\n]+)", banner, flags=re.IGNORECASE)
        return match.group(1).strip() if match else ""
    if service in {"Elasticsearch", "MongoDB", "PostgreSQL", "MSSQL", "Oracle", "VNC", "WinRM", "POP3", "IMAP"}:
        first_line = banner.splitlines()[0] if banner.splitlines() else banner
        return first_line[:120]
    return ""


def _match_banner(
    banner: str,
    port: int,
    fingerprints: Iterable[ServiceFingerprint],
) -> tuple[str, float, list[str]]:
    evidence: list[str] = []
    for fingerprint in fingerprints:
        for pattern in fingerprint.banner_patterns:
            if re.search(pattern, banner, flags=re.IGNORECASE | re.MULTILINE):
                evidence.append(f"banner:{pattern}")
                confidence = 0.92 if port in fingerprint.default_ports else 0.82
                return fingerprint.name, confidence, evidence
    hint = fingerprint_for_port(port, fingerprints)
    if hint:
        evidence.append(f"port_hint:{port}")
        return hint.name, 0.55, evidence
    return "unknown", 0.0, evidence


def detect_service(
    target: TargetAddress,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    fingerprints: Iterable[ServiceFingerprint] | None = None,
    socket_factory: SocketFactory = _socket_factory,
    tls_wrapper: TLSWrapper = _tls_wrapper,
) -> dict[str, Any]:
    """Probe one TCP service using safe banner and protocol checks."""
    if timeout <= 0:
        raise ValueError("service detection timeout must be greater than 0")
    port = normalize_service_ports([port])[0]
    loaded_fingerprints = list(fingerprints or load_fingerprints())
    sock = socket_factory(_family_for_target(target), socket.SOCK_STREAM, socket.IPPROTO_TCP)
    active_sock: ServiceSocket = sock
    probe_name = "banner"
    try:
        sock.settimeout(timeout)
        code = sock.connect_ex(_sockaddr(target, port))
        state, reason = _state_from_connect_ex(int(code or 0))
        if state != "open":
            hint = fingerprint_for_port(port, loaded_fingerprints)
            return ServiceDetectionResult(
                target=target.host,
                port=port,
                ip_version=target.version,
                state=state,
                service=hint.name if hint else "unknown",
                confidence=0.25 if hint else 0.0,
                evidence=[f"port_hint:{port}"] if hint else [],
                reason=reason,
            ).to_dict()

        hint = fingerprint_for_port(port, loaded_fingerprints)
        if hint and "https_head" in hint.probes:
            try:
                active_sock = tls_wrapper(sock, target.host)
                probe_name = "https_head"
                banner = _send_probe(active_sock, "http_head", target, timeout)
            except Exception:
                banner = ""
        elif hint and "http_head" in hint.probes:
            probe_name = "http_head"
            banner = _send_probe(active_sock, "http_head", target, timeout)
        else:
            banner = _read_banner(active_sock, timeout)
            if not banner and hint and "smtp_ehlo" in hint.probes:
                probe_name = "smtp_ehlo"
                banner = _send_probe(active_sock, "smtp_ehlo", target, timeout)

        service, confidence, evidence = _match_banner(banner, port, loaded_fingerprints)
        version = _extract_version(service, banner)
        if not evidence and hint:
            evidence = [f"port_hint:{port}"]
            service = hint.name
            confidence = 0.55
        return ServiceDetectionResult(
            target=target.host,
            port=port,
            ip_version=target.version,
            state="open",
            service=service,
            version=version,
            confidence=confidence,
            banner=banner,
            probe=probe_name,
            evidence=evidence,
            reason="probe_completed",
        ).to_dict()
    finally:
        try:
            active_sock.close()
        finally:
            if active_sock is not sock:
                sock.close()


def enumerate_services(
    targets: str | Iterable[str],
    ports: Iterable[int] | None = None,
    *,
    ip_version: str | int | None = "auto",
    timeout: float = DEFAULT_TIMEOUT,
    max_targets: int = DEFAULT_MAX_TARGETS,
    max_ports: int = DEFAULT_MAX_PORTS,
    rate_delay: float = DEFAULT_RATE_DELAY,
    aggressive: bool = False,
    fingerprints_path: str | Path | None = None,
    socket_factory: SocketFactory = _socket_factory,
    tls_wrapper: TLSWrapper = _tls_wrapper,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    """Enumerate probable services and versions on authorized targets."""
    target_limit = max(max_targets, AGGRESSIVE_MAX_TARGETS) if aggressive else max_targets
    port_limit = max(max_ports, AGGRESSIVE_MAX_PORTS) if aggressive else max_ports
    selected_targets = expand_targets(targets, ip_version=ip_version, max_targets=target_limit)
    selected_ports = normalize_service_ports(ports)
    if not aggressive and len(selected_targets) > max_targets:
        raise ValueError(f"service enumeration limited to {max_targets} targets by default; enable aggressive mode to override")
    if not aggressive and len(selected_ports) > max_ports:
        raise ValueError(f"service enumeration limited to {max_ports} ports by default; enable aggressive mode to override")
    if rate_delay < 0:
        raise ValueError("service enumeration rate_delay must be 0 or greater")
    fingerprints = load_fingerprints(fingerprints_path)

    rows: list[dict[str, Any]] = []
    total = len(selected_targets) * len(selected_ports)
    completed = 0
    for target in selected_targets:
        for port in selected_ports:
            row = detect_service(
                target,
                port,
                timeout=timeout,
                fingerprints=fingerprints,
                socket_factory=socket_factory,
                tls_wrapper=tls_wrapper,
            )
            rows.append(row)
            completed += 1
            if logger:
                logger.info("service_detection_result %s", json.dumps(row, sort_keys=True))
            if rate_delay and completed < total:
                time.sleep(rate_delay)
    return rows


__all__ = [
    "COMMON_ENUMERATION_PORTS",
    "ServiceDetectionResult",
    "ServiceFingerprint",
    "detect_service",
    "enumerate_services",
    "fingerprint_for_port",
    "load_fingerprints",
    "normalize_service_ports",
]
