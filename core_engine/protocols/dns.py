from __future__ import annotations

from core_engine.protocols.common import failed, ok, unknown


QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    seen = 0
    while cursor < len(data) and seen < 64:
        length = data[cursor]
        if length == 0:
            return ".".join(labels), cursor + 1
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                return ".".join(labels), cursor + 1
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            pointed, _ = _parse_name(data, pointer)
            if pointed:
                labels.append(pointed)
            return ".".join(labels), cursor + 2
        cursor += 1
        if cursor + length > len(data):
            return ".".join(labels), cursor
        labels.append(data[cursor : cursor + length].decode("ascii", errors="replace"))
        cursor += length
        seen += 1
    return ".".join(labels), cursor


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        if len(payload) < 12:
            return unknown("DNS", reason="dns_header_too_short", payload=payload)
        transaction_id = _u16(payload, 0)
        flags = _u16(payload, 2)
        qdcount = _u16(payload, 4)
        ancount = _u16(payload, 6)
        fields = {
            "transaction_id": transaction_id,
            "query": not bool(flags & 0x8000),
            "opcode": (flags >> 11) & 0x0F,
            "rcode": flags & 0x0F,
            "question_count": qdcount,
            "answer_count": ancount,
        }
        evidence = ["dns_header"]
        if qdcount:
            qname, cursor = _parse_name(payload, 12)
            fields["query_name"] = qname
            if cursor + 4 <= len(payload):
                qtype = _u16(payload, cursor)
                fields["query_type"] = QTYPE_NAMES.get(qtype, str(qtype))
                evidence.append("dns_question")
        summary = f"DNS {'query' if fields['query'] else 'response'}"
        if fields.get("query_name"):
            summary = f"{summary} {fields['query_name']}"
        return ok("DNS", confidence=0.95, summary=summary, fields=fields, evidence=evidence, payload=payload)
    except Exception as exc:
        return failed("DNS", error=str(exc), payload=payload)
