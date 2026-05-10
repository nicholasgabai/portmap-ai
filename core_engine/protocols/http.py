from __future__ import annotations

from core_engine.protocols.common import decode_text, failed, ok, strip_query, unknown


METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT"}


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        text = decode_text(payload, limit=4096)
        if not text:
            return unknown("HTTP", reason="empty_payload", payload=payload)
        lines = text.splitlines()
        first = lines[0].strip() if lines else ""
        fields: dict[str, object] = {}
        evidence: list[str] = []
        if first.startswith("HTTP/"):
            parts = first.split(maxsplit=2)
            fields["version"] = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                fields["status_code"] = int(parts[1])
            if len(parts) > 2:
                fields["reason"] = parts[2][:80]
            evidence.append("http_status_line")
            summary = f"HTTP response {fields.get('status_code', '')}".strip()
        else:
            parts = first.split()
            if len(parts) < 2 or parts[0].upper() not in METHODS:
                return unknown("HTTP", reason="no_http_start_line", payload=payload)
            fields["method"] = parts[0].upper()
            fields["path"] = strip_query(parts[1])
            if len(parts) > 2:
                fields["version"] = parts[2]
            evidence.append("http_request_line")
            summary = f"HTTP {fields['method']} {fields['path']}"

        for line in lines[1:]:
            if not line.strip():
                break
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key_lower = key.strip().lower()
            if key_lower in {"host", "server", "user-agent", "content-type"}:
                fields[key_lower.replace("-", "_")] = value.strip()[:160]
                evidence.append(f"header:{key_lower}")
        return ok("HTTP", confidence=0.95, summary=summary, fields=fields, evidence=evidence, payload=payload)
    except Exception as exc:
        return failed("HTTP", error=str(exc), payload=payload)
