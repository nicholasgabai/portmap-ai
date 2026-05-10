from __future__ import annotations

from core_engine.protocols.common import failed, ok, unknown


ICMP_TYPES = {0: "echo_reply", 3: "destination_unreachable", 5: "redirect", 8: "echo_request", 11: "time_exceeded"}
ICMPV6_TYPES = {1: "destination_unreachable", 2: "packet_too_big", 3: "time_exceeded", 128: "echo_request", 129: "echo_reply"}


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        protocol = str((metadata or {}).get("protocol") or "ICMP")
        if len(payload) < 2:
            return unknown(protocol, reason="icmp_header_too_short", payload=payload)
        type_value = payload[0]
        code = payload[1]
        names = ICMPV6_TYPES if protocol == "ICMPv6" else ICMP_TYPES
        type_name = names.get(type_value, "unknown")
        fields = {"type": type_value, "code": code, "type_name": type_name}
        return ok(protocol, confidence=0.9, summary=f"{protocol} {type_name}", fields=fields, evidence=["icmp_header"], payload=payload)
    except Exception as exc:
        return failed("ICMP", error=str(exc), payload=payload)
