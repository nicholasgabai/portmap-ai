from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from typing import Iterable


VALID_IP_VERSIONS = {"auto", "4", "6"}
DEFAULT_MAX_TARGETS = 256


@dataclass(frozen=True)
class TargetAddress:
    host: str
    version: int
    source: str
    private: bool
    loopback: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "version": self.version,
            "source": self.source,
            "private": self.private,
            "loopback": self.loopback,
        }


def normalize_ip_version(ip_version: str | int | None) -> str:
    value = str(ip_version or "auto").lower()
    if value in {"ipv4", "v4"}:
        value = "4"
    elif value in {"ipv6", "v6"}:
        value = "6"
    if value not in VALID_IP_VERSIONS:
        raise ValueError("ip_version must be auto, 4, or 6")
    return value


def detect_ip_version(value: str) -> int:
    try:
        return ipaddress.ip_address(value).version
    except ValueError as exc:
        raise ValueError(f"Invalid IP address '{value}'") from exc


def is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def parse_target(value: str) -> TargetAddress:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target must be a non-empty string")
    raw = value.strip()
    bracketless = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        address = ipaddress.ip_address(bracketless)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address target '{value}'") from exc
    return TargetAddress(
        host=str(address),
        version=address.version,
        source="literal",
        private=address.is_private,
        loopback=address.is_loopback,
    )


def expand_cidr(value: str, *, max_targets: int = DEFAULT_MAX_TARGETS) -> list[TargetAddress]:
    if max_targets <= 0:
        raise ValueError("max_targets must be greater than 0")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR target '{value}'") from exc
    hosts = list(network.hosts())
    if not hosts and network.num_addresses == 1:
        hosts = [network.network_address]
    if len(hosts) > max_targets:
        raise ValueError(f"CIDR target expands to {len(hosts)} hosts; limit is {max_targets}")
    return [
        TargetAddress(
            host=str(address),
            version=address.version,
            source="cidr",
            private=address.is_private,
            loopback=address.is_loopback,
        )
        for address in hosts
    ]


def resolve_hostname(hostname: str, *, ip_version: str | int | None = "auto") -> list[TargetAddress]:
    version = normalize_ip_version(ip_version)
    family = socket.AF_UNSPEC if version == "auto" else socket.AF_INET if version == "4" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target '{hostname}': {exc}") from exc
    targets: list[TargetAddress] = []
    seen: set[str] = set()
    for family, _, _, _, sockaddr in infos:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        host = str(sockaddr[0])
        if host in seen:
            continue
        seen.add(host)
        address = ipaddress.ip_address(host)
        targets.append(
            TargetAddress(
                host=str(address),
                version=address.version,
                source="dns",
                private=address.is_private,
                loopback=address.is_loopback,
            )
        )
    if not targets:
        raise ValueError(f"Unable to resolve target '{hostname}' to IPv4 or IPv6")
    return targets


def expand_targets(
    targets: str | Iterable[str],
    *,
    ip_version: str | int | None = "auto",
    max_targets: int = DEFAULT_MAX_TARGETS,
    resolve_names: bool = True,
) -> list[TargetAddress]:
    version = normalize_ip_version(ip_version)
    raw_targets = [targets] if isinstance(targets, str) else list(targets)
    expanded: list[TargetAddress] = []
    for raw in raw_targets:
        value = str(raw).strip()
        if not value:
            continue
        if "/" in value:
            candidates = expand_cidr(value, max_targets=max_targets)
        else:
            try:
                candidates = [parse_target(value)]
            except ValueError:
                if not resolve_names:
                    raise
                candidates = resolve_hostname(value, ip_version=version)
        for candidate in candidates:
            if version != "auto" and candidate.version != int(version):
                continue
            expanded.append(candidate)
        if len(expanded) > max_targets:
            raise ValueError(f"targets expand beyond safe limit of {max_targets}")
    if not expanded:
        raise ValueError("no valid targets after IP version filtering")
    return expanded


def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
