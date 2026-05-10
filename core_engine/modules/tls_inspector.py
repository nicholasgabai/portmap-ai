from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import ipaddress
import re
import socket
import ssl
from typing import Any, Callable, Iterable

from core_engine.modules.ip_utils import TargetAddress, expand_targets, format_host_port


DEFAULT_TLS_PORTS = [443]
DEFAULT_TIMEOUT = 3.0
DEFAULT_MAX_TARGETS = 32
DEFAULT_MAX_PORTS = 32
EXPIRY_SOON_DAYS = 30

DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
MODERN_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}
WEAK_CIPHER_PATTERNS = [
    ("null_cipher", re.compile(r"(^|[_-])NULL($|[_-])", re.IGNORECASE), "high"),
    ("export_cipher", re.compile(r"(^|[_-])EXPORT($|[_-])", re.IGNORECASE), "high"),
    ("anonymous_cipher", re.compile(r"(^|[_-])(?:ADH|AECDH|ANON)($|[_-])", re.IGNORECASE), "high"),
    ("rc4_cipher", re.compile(r"(^|[_-])RC4($|[_-])", re.IGNORECASE), "high"),
    ("des_cipher", re.compile(r"(^|[_-])(?:3DES|DES-CBC|DES)($|[_-])", re.IGNORECASE), "medium"),
    ("md5_cipher", re.compile(r"(^|[_-])MD5($|[_-])", re.IGNORECASE), "medium"),
    ("cbc_cipher", re.compile(r"(^|[_-])CBC($|[_-])", re.IGNORECASE), "low"),
]
SEVERITY_SCORES = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75}


def normalize_tls_ports(ports: Iterable[int] | None = None, *, max_ports: int = DEFAULT_MAX_PORTS) -> list[int]:
    raw_ports = list(ports or DEFAULT_TLS_PORTS)
    normalized: list[int] = []
    for raw in raw_ports:
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid TLS port '{raw}'") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"TLS port {port} is outside 1-65535")
        if port not in normalized:
            normalized.append(port)
    if not normalized:
        raise ValueError("at least one TLS port is required")
    if len(normalized) > max_ports:
        raise ValueError(f"TLS port count {len(normalized)} exceeds safe limit of {max_ports}")
    return normalized


def parse_certificate_time(value: Any) -> datetime | None:
    if value in {None, ""}:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _to_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    value = _to_utc(value)
    return value.isoformat() if value else None


def _warning(kind: str, severity: str, detail: str) -> dict[str, str]:
    return {"type": kind, "severity": severity, "detail": detail}


def _flatten_name_tuple(value: Any) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not isinstance(value, (list, tuple)):
        return fields
    for rdn in value:
        if not isinstance(rdn, (list, tuple)):
            continue
        for pair in rdn:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                key, item_value = pair
                fields[str(key)] = str(item_value)
    return fields


def _normalize_string_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        return [values]
    if not isinstance(values, Iterable):
        return [str(values)]
    return [str(item) for item in values if item not in {None, ""}]


def normalize_certificate(certificate: dict[str, Any] | None, der_bytes: bytes | None = None) -> dict[str, Any]:
    certificate = certificate or {}
    subject = certificate.get("subject")
    issuer = certificate.get("issuer")
    subject_fields = _flatten_name_tuple(subject) if isinstance(subject, (list, tuple)) else dict(subject or {})
    issuer_fields = _flatten_name_tuple(issuer) if isinstance(issuer, (list, tuple)) else dict(issuer or {})

    san_dns: list[str] = []
    san_ip: list[str] = []
    alt_names = certificate.get("subjectAltName") or certificate.get("subject_alt_names")
    if isinstance(alt_names, (list, tuple)):
        for entry in alt_names:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                kind, value = str(entry[0]).lower(), str(entry[1])
                if kind == "dns":
                    san_dns.append(value)
                elif kind in {"ip address", "ip"}:
                    san_ip.append(value)
    san_dns.extend(_normalize_string_list(certificate.get("san_dns")))
    san_ip.extend(_normalize_string_list(certificate.get("san_ip")))

    not_before = parse_certificate_time(certificate.get("notBefore") or certificate.get("not_before"))
    not_after = parse_certificate_time(certificate.get("notAfter") or certificate.get("not_after"))
    normalized: dict[str, Any] = {
        "subject": subject_fields,
        "issuer": issuer_fields,
        "common_name": certificate.get("common_name") or subject_fields.get("commonName") or subject_fields.get("CN"),
        "issuer_common_name": certificate.get("issuer_common_name") or issuer_fields.get("commonName") or issuer_fields.get("CN"),
        "san_dns": sorted(set(san_dns)),
        "san_ip": sorted(set(san_ip)),
        "serial_number": certificate.get("serialNumber") or certificate.get("serial_number"),
        "not_before": _iso(not_before),
        "not_after": _iso(not_after),
        "sha256": certificate.get("sha256") or (hashlib.sha256(der_bytes).hexdigest() if der_bytes else None),
    }
    return normalized


def _matches_dns_pattern(hostname: str, pattern: str) -> bool:
    hostname = hostname.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()
    if not hostname or not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return hostname == pattern


def certificate_matches_hostname(certificate: dict[str, Any], server_name: str | None) -> bool | None:
    if not server_name:
        return None
    normalized = normalize_certificate(certificate)
    try:
        ipaddress.ip_address(server_name.strip("[]"))
        return server_name.strip("[]") in normalized["san_ip"]
    except ValueError:
        names = normalized["san_dns"] or ([normalized["common_name"]] if normalized.get("common_name") else [])
        return any(_matches_dns_pattern(server_name, name) for name in names)


def analyze_certificate(
    certificate: dict[str, Any] | None,
    *,
    server_name: str | None = None,
    now: datetime | None = None,
    der_bytes: bytes | None = None,
) -> dict[str, Any]:
    current_time = _to_utc(now) or datetime.now(UTC)
    normalized = normalize_certificate(certificate, der_bytes=der_bytes)
    not_after = parse_certificate_time(normalized.get("not_after"))
    not_before = parse_certificate_time(normalized.get("not_before"))
    warnings: list[dict[str, str]] = []

    days_until_expiry: int | None = None
    expired = False
    expires_soon = False
    if not_after:
        days_until_expiry = int((not_after - current_time).total_seconds() // 86400)
        expired = not_after < current_time
        expires_soon = not expired and days_until_expiry <= EXPIRY_SOON_DAYS
        if expired:
            warnings.append(_warning("certificate_expired", "high", "certificate is expired"))
        elif expires_soon:
            warnings.append(_warning("certificate_expires_soon", "medium", "certificate expires soon"))
    else:
        warnings.append(_warning("certificate_expiry_unknown", "low", "certificate expiry was not available"))

    subject_cn = normalized.get("common_name")
    issuer_cn = normalized.get("issuer_common_name")
    self_signed = bool(subject_cn and issuer_cn and subject_cn == issuer_cn)
    if self_signed:
        warnings.append(_warning("self_signed_certificate", "medium", "certificate appears self-signed"))

    hostname_match = certificate_matches_hostname(normalized, server_name)
    if hostname_match is False:
        warnings.append(_warning("hostname_mismatch", "high", "certificate names do not match the requested server name"))

    return {
        **normalized,
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "expires_soon": expires_soon,
        "self_signed": self_signed,
        "hostname_match": hostname_match,
        "validity_started": bool(not_before and not_before <= current_time),
        "warnings": warnings,
    }


def analyze_tls_version(version: str | None) -> dict[str, Any]:
    if not version:
        return {
            "version": None,
            "status": "unknown",
            "warnings": [_warning("tls_version_unknown", "low", "TLS version was not available")],
        }
    if version in DEPRECATED_TLS_VERSIONS:
        return {
            "version": version,
            "status": "deprecated",
            "warnings": [_warning("deprecated_tls_version", "high", f"{version} is deprecated")],
        }
    if version in MODERN_TLS_VERSIONS:
        return {"version": version, "status": "modern", "warnings": []}
    return {
        "version": version,
        "status": "unknown",
        "warnings": [_warning("unknown_tls_version", "low", f"{version} is not recognized by the local policy")],
    }


def analyze_cipher(cipher: Any) -> dict[str, Any]:
    if isinstance(cipher, dict):
        name = cipher.get("name")
        protocol = cipher.get("protocol")
        bits = cipher.get("bits")
    elif isinstance(cipher, (list, tuple)):
        name = cipher[0] if len(cipher) > 0 else None
        protocol = cipher[1] if len(cipher) > 1 else None
        bits = cipher[2] if len(cipher) > 2 else None
    else:
        name, protocol, bits = None, None, None

    warnings: list[dict[str, str]] = []
    if not name:
        warnings.append(_warning("cipher_unknown", "low", "cipher suite was not available"))
    else:
        for kind, pattern, severity in WEAK_CIPHER_PATTERNS:
            if pattern.search(str(name)):
                warnings.append(_warning(kind, severity, f"cipher suite contains {kind.replace('_', ' ')} marker"))
    try:
        bit_count = int(bits) if bits is not None else None
    except (TypeError, ValueError):
        bit_count = None
    if bit_count is not None and bit_count < 128:
        warnings.append(_warning("small_cipher_key", "high", "cipher key size is below 128 bits"))

    return {
        "name": str(name) if name else None,
        "protocol": str(protocol) if protocol else None,
        "bits": bit_count,
        "weak": any(item["severity"] in {"medium", "high"} for item in warnings),
        "warnings": warnings,
    }


def _risk_score(warnings: list[dict[str, str]]) -> float:
    score = 0.0
    for warning in warnings:
        score = max(score, SEVERITY_SCORES.get(warning.get("severity", "info"), 0.0))
    return round(score, 2)


def analyze_tls_observation(observation: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise ValueError("TLS observation must be an object")
    certificate = analyze_certificate(
        observation.get("certificate") or observation.get("peer_certificate") or {},
        server_name=observation.get("server_name") or observation.get("hostname") or observation.get("target"),
        now=now,
    )
    version = analyze_tls_version(observation.get("tls_version") or observation.get("version"))
    cipher = analyze_cipher(observation.get("cipher"))
    warnings = [*version["warnings"], *cipher["warnings"], *certificate["warnings"]]
    return {
        "target": observation.get("target") or observation.get("host") or observation.get("server_name"),
        "port": int(observation.get("port") or 443),
        "remote": observation.get("remote"),
        "server_name": observation.get("server_name") or observation.get("hostname"),
        "ok": True,
        "source": "observation",
        "tls_version": version,
        "cipher": cipher,
        "certificate": certificate,
        "warnings": warnings,
        "risk_score": _risk_score(warnings),
    }


def inspect_tls_target(
    target: TargetAddress | str,
    *,
    port: int = 443,
    server_name: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    context_factory: Callable[[], ssl.SSLContext] | None = None,
    connection_factory: Callable[..., socket.socket] | None = None,
) -> dict[str, Any]:
    host = target.host if isinstance(target, TargetAddress) else str(target)
    remote = format_host_port(host, port)
    requested_name = server_name or (host if not _is_ip_literal(host) else None)
    started = datetime.now(UTC)

    try:
        context = context_factory() if context_factory else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        create_connection = connection_factory or socket.create_connection
        with create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=requested_name) as tls_socket:
                tls_version = tls_socket.version()
                cipher = tls_socket.cipher()
                peer_cert = tls_socket.getpeercert() or {}
                der_cert = tls_socket.getpeercert(binary_form=True)
    except ssl.SSLError as exc:
        return _tls_error(host, port, requested_name, "tls_handshake_failed", str(exc), started)
    except PermissionError as exc:
        return _tls_error(host, port, requested_name, "permission_denied", str(exc), started)
    except OSError as exc:
        return _tls_error(host, port, requested_name, "connection_failed", str(exc), started)

    observation = analyze_tls_observation(
        {
            "target": host,
            "port": port,
            "remote": remote,
            "server_name": requested_name,
            "tls_version": tls_version,
            "cipher": cipher,
            "certificate": normalize_certificate(peer_cert, der_bytes=der_cert),
        }
    )
    observation["source"] = "live_tls_handshake"
    observation["duration_ms"] = round((datetime.now(UTC) - started).total_seconds() * 1000, 3)
    return observation


def inspect_tls_targets(
    targets: str | Iterable[str],
    *,
    ports: Iterable[int] | None = None,
    server_name: str | None = None,
    ip_version: str = "auto",
    timeout: float = DEFAULT_TIMEOUT,
    max_targets: int = DEFAULT_MAX_TARGETS,
    max_ports: int = DEFAULT_MAX_PORTS,
    aggressive: bool = False,
    inspector: Callable[..., dict[str, Any]] = inspect_tls_target,
) -> list[dict[str, Any]]:
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")
    target_limit = max_targets if aggressive else min(max_targets, DEFAULT_MAX_TARGETS)
    port_limit = max_ports if aggressive else min(max_ports, DEFAULT_MAX_PORTS)
    expanded = expand_targets(targets, ip_version=ip_version, max_targets=target_limit)
    normalized_ports = normalize_tls_ports(ports, max_ports=port_limit)

    rows: list[dict[str, Any]] = []
    for target in expanded:
        for port in normalized_ports:
            rows.append(inspector(target, port=port, server_name=server_name, timeout=timeout))
    return rows


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _tls_error(
    host: str,
    port: int,
    server_name: str | None,
    reason: str,
    error: str,
    started: datetime,
) -> dict[str, Any]:
    return {
        "target": host,
        "port": port,
        "remote": format_host_port(host, port),
        "server_name": server_name,
        "ok": False,
        "source": "live_tls_handshake",
        "reason": reason,
        "error": error,
        "warnings": [_warning(reason, "low", error)],
        "risk_score": 0.0,
        "duration_ms": round((datetime.now(UTC) - started).total_seconds() * 1000, 3),
    }
