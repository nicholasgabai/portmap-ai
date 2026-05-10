from __future__ import annotations

from core_engine.protocols.common import failed, ok, unknown


CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
HANDSHAKE_TYPES = {1: "client_hello", 2: "server_hello", 11: "certificate", 14: "server_hello_done", 16: "client_key_exchange"}
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        if len(payload) < 5:
            return unknown("TLS", reason="tls_record_too_short", payload=payload)
        content_type = payload[0]
        if content_type not in CONTENT_TYPES:
            return unknown("TLS", reason="unknown_tls_content_type", payload=payload)
        version_raw = _u16(payload, 1)
        record_length = _u16(payload, 3)
        fields = {
            "content_type": CONTENT_TYPES[content_type],
            "record_version": TLS_VERSIONS.get(version_raw, f"0x{version_raw:04x}"),
            "record_length": record_length,
        }
        evidence = ["tls_record_header"]
        if content_type == 22 and len(payload) >= 6:
            handshake_type = payload[5]
            fields["handshake_type"] = HANDSHAKE_TYPES.get(handshake_type, str(handshake_type))
            evidence.append("tls_handshake_header")
        return ok("TLS", confidence=0.92, summary=f"TLS {fields['content_type']}", fields=fields, evidence=evidence, payload=payload)
    except Exception as exc:
        return failed("TLS", error=str(exc), payload=payload)
