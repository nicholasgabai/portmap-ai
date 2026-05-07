"""Known risky ports and service hints used by scanner/scoring."""

from __future__ import annotations

from typing import Any


KNOWN_RISKY_PORTS: dict[int, dict[str, Any]] = {
    21: {"service": "FTP", "severity": "medium", "reason": "unencrypted file transfer service"},
    22: {"service": "SSH", "severity": "medium", "reason": "remote shell administration service"},
    23: {"service": "Telnet", "severity": "high", "reason": "unencrypted remote shell service"},
    25: {"service": "SMTP", "severity": "medium", "reason": "mail relay exposure"},
    53: {"service": "DNS", "severity": "medium", "reason": "DNS service exposure"},
    135: {"service": "MSRPC", "severity": "high", "reason": "Windows RPC service exposure"},
    139: {"service": "NetBIOS", "severity": "high", "reason": "legacy Windows file-sharing service"},
    445: {"service": "SMB", "severity": "high", "reason": "Windows file-sharing service"},
    1433: {"service": "MSSQL", "severity": "high", "reason": "database service exposure"},
    1521: {"service": "Oracle", "severity": "high", "reason": "database service exposure"},
    2049: {"service": "NFS", "severity": "high", "reason": "network filesystem exposure"},
    3306: {"service": "MySQL", "severity": "high", "reason": "database service exposure"},
    3389: {"service": "RDP", "severity": "critical", "reason": "remote desktop service exposure"},
    5432: {"service": "PostgreSQL", "severity": "high", "reason": "database service exposure"},
    5900: {"service": "VNC", "severity": "critical", "reason": "remote desktop service exposure"},
    5985: {"service": "WinRM", "severity": "high", "reason": "remote management service exposure"},
    6379: {"service": "Redis", "severity": "high", "reason": "in-memory database service exposure"},
    9200: {"service": "Elasticsearch", "severity": "high", "reason": "search database API exposure"},
    11211: {"service": "Memcached", "severity": "high", "reason": "cache database service exposure"},
    27017: {"service": "MongoDB", "severity": "high", "reason": "database service exposure"},
}

COMMON_SERVICE_PORTS: dict[int, str] = {
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS",
    5353: "mDNS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

SEVERITY_WEIGHTS = {
    "low": 0.08,
    "medium": 0.15,
    "high": 0.25,
    "critical": 0.35,
}


def port_metadata(port: int | str | None) -> dict[str, Any] | None:
    try:
        port_int = int(port or 0)
    except (TypeError, ValueError):
        return None
    if port_int in KNOWN_RISKY_PORTS:
        return {"port": port_int, **KNOWN_RISKY_PORTS[port_int]}
    service = COMMON_SERVICE_PORTS.get(port_int)
    if service:
        return {"port": port_int, "service": service, "severity": "low", "reason": "common service port"}
    return None


def service_name_for_port(port: int | str | None) -> str | None:
    metadata = port_metadata(port)
    return str(metadata["service"]) if metadata else None


__all__ = ["COMMON_SERVICE_PORTS", "KNOWN_RISKY_PORTS", "SEVERITY_WEIGHTS", "port_metadata", "service_name_for_port"]
