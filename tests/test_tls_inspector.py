from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core_engine.modules.ip_utils import TargetAddress
from core_engine.modules.tls_inspector import (
    analyze_certificate,
    analyze_cipher,
    analyze_tls_observation,
    certificate_matches_hostname,
    inspect_tls_targets,
    normalize_tls_ports,
    parse_certificate_time,
)


NOW = datetime(2026, 5, 9, tzinfo=UTC)


def _clock(*parts):
    return ":".join(parts)


def _iso(date, *parts):
    return f"{date}T{_clock(*parts)}+00:00"


def test_parse_certificate_time_accepts_ssl_and_iso_formats():
    expected = _iso("2026-05-10", "12", "00", "00")
    assert parse_certificate_time(f"May 10 {_clock('12', '00', '00')} 2026 GMT").isoformat() == expected
    assert parse_certificate_time(expected).isoformat() == expected
    assert parse_certificate_time("not a date") is None


def test_normalize_tls_ports_validates_range_and_limit():
    assert normalize_tls_ports([443, "8443", 443]) == [443, 8443]
    with pytest.raises(ValueError, match="outside 1-65535"):
        normalize_tls_ports([0])
    with pytest.raises(ValueError, match="safe limit"):
        normalize_tls_ports([443, 8443], max_ports=1)


def test_certificate_analysis_flags_expired_self_signed_and_hostname_mismatch():
    certificate = {
        "subject": {"commonName": "admin.local"},
        "issuer": {"commonName": "admin.local"},
        "san_dns": ["admin.local"],
        "not_after": _iso("2026-05-01", "00", "00", "00"),
    }

    result = analyze_certificate(certificate, server_name="portal.local", now=NOW)

    assert result["expired"] is True
    assert result["self_signed"] is True
    assert result["hostname_match"] is False
    assert {warning["type"] for warning in result["warnings"]} == {
        "certificate_expired",
        "self_signed_certificate",
        "hostname_mismatch",
    }


def test_certificate_analysis_accepts_ssl_peer_certificate_shape():
    certificate = {
        "subject": ((("commonName", "api.example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "subjectAltName": (("DNS", "api.example.com"), ("IP Address", "127.0.0.1")),
        "notBefore": f"May  1 {_clock('00', '00', '00')} 2026 GMT",
        "notAfter": f"Jun  1 {_clock('00', '00', '00')} 2026 GMT",
    }

    result = analyze_certificate(certificate, server_name="api.example.com", now=NOW)

    assert result["common_name"] == "api.example.com"
    assert result["issuer_common_name"] == "Example CA"
    assert result["hostname_match"] is True
    assert result["expired"] is False


def test_certificate_expiry_soon_warning():
    certificate = {
        "subject": {"commonName": "api.example.com"},
        "issuer": {"commonName": "Example CA"},
        "san_dns": ["api.example.com"],
        "not_after": _iso("2026-05-20", "00", "00", "00"),
    }

    result = analyze_certificate(certificate, server_name="api.example.com", now=NOW)

    assert result["expires_soon"] is True
    assert any(warning["type"] == "certificate_expires_soon" for warning in result["warnings"])


def test_wildcard_hostname_matching_uses_single_label_wildcards():
    certificate = {"san_dns": ["*.example.com"]}

    assert certificate_matches_hostname(certificate, "api.example.com") is True
    assert certificate_matches_hostname(certificate, "deep.api.example.com") is False


def test_cipher_analysis_flags_weak_cipher_markers():
    result = analyze_cipher(("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.0", 112))

    assert result["weak"] is True
    assert {warning["type"] for warning in result["warnings"]} >= {"des_cipher", "cbc_cipher", "small_cipher_key"}


def test_tls_observation_combines_version_cipher_and_certificate_warnings():
    observation = {
        "target": "legacy.example.com",
        "server_name": "legacy.example.com",
        "port": 443,
        "tls_version": "TLSv1.0",
        "cipher": {"name": "RC4-MD5", "bits": 64},
        "certificate": {
            "subject": {"commonName": "legacy.example.com"},
            "issuer": {"commonName": "Legacy CA"},
            "san_dns": ["legacy.example.com"],
            "not_after": _iso("2026-04-01", "00", "00", "00"),
        },
    }

    result = analyze_tls_observation(observation, now=NOW)

    warning_types = {warning["type"] for warning in result["warnings"]}
    assert "deprecated_tls_version" in warning_types
    assert "rc4_cipher" in warning_types
    assert "small_cipher_key" in warning_types
    assert "certificate_expired" in warning_types
    assert result["risk_score"] == 0.75


def test_inspect_tls_targets_accepts_injected_inspector_without_network():
    calls = []

    def fake_inspector(target, *, port=443, server_name=None, timeout=3.0):
        calls.append((target, port, server_name, timeout))
        return {"target": target.host, "port": port, "ok": True}

    rows = inspect_tls_targets(
        "127.0.0.1",
        ports=[443, 8443],
        server_name="localhost",
        timeout=0.5,
        inspector=fake_inspector,
    )

    assert rows == [
        {"target": "127.0.0.1", "port": 443, "ok": True},
        {"target": "127.0.0.1", "port": 8443, "ok": True},
    ]
    assert all(isinstance(call[0], TargetAddress) for call in calls)
    assert calls[0][2:] == ("localhost", 0.5)
