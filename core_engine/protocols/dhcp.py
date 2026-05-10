from __future__ import annotations

from core_engine.protocols.common import failed, ok, unknown


MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}


def _mac(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _parse_options(data: bytes, offset: int) -> dict[str, object]:
    options: dict[str, object] = {}
    cursor = offset
    while cursor < len(data):
        option = data[cursor]
        cursor += 1
        if option == 255:
            break
        if option == 0:
            continue
        if cursor >= len(data):
            break
        length = data[cursor]
        cursor += 1
        value = data[cursor : cursor + length]
        cursor += length
        if option == 53 and value:
            options["message_type"] = MESSAGE_TYPES.get(value[0], str(value[0]))
        elif option == 12:
            options["hostname"] = value.decode("ascii", errors="replace")[:120]
        elif option == 55:
            options["parameter_request_count"] = len(value)
    return options


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        if len(payload) < 240:
            return unknown("DHCP", reason="dhcp_packet_too_short", payload=payload)
        op = payload[0]
        xid = int.from_bytes(payload[4:8], "big")
        chaddr = _mac(payload[28:34])
        magic = payload[236:240]
        if magic != b"\x63\x82\x53\x63":
            return unknown("DHCP", reason="missing_dhcp_magic_cookie", payload=payload)
        fields = {"op": op, "xid": xid, "client_mac": chaddr}
        fields.update(_parse_options(payload, 240))
        summary = f"DHCP {fields.get('message_type', 'message')}"
        return ok("DHCP", confidence=0.94, summary=summary, fields=fields, evidence=["dhcp_magic_cookie"], payload=payload)
    except Exception as exc:
        return failed("DHCP", error=str(exc), payload=payload)
