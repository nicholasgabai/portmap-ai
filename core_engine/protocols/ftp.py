from __future__ import annotations

from core_engine.protocols.common import failed, first_line, ok, redact_token, unknown


SENSITIVE_COMMANDS = {"PASS", "USER", "ACCT"}


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        line = first_line(payload)
        if not line:
            return unknown("FTP", reason="empty_payload", payload=payload)
        fields: dict[str, object] = {}
        evidence: list[str] = []
        if len(line) >= 3 and line[:3].isdigit():
            fields["response_code"] = int(line[:3])
            fields["message"] = line[4:160] if len(line) > 4 else ""
            evidence.append("ftp_response_code")
            summary = f"FTP response {fields['response_code']}"
        else:
            parts = line.split(maxsplit=1)
            command = parts[0].upper()
            fields["command"] = command
            if len(parts) > 1:
                fields["argument"] = redact_token(parts[1]) if command in SENSITIVE_COMMANDS else parts[1][:120]
            evidence.append("ftp_command")
            summary = f"FTP {command}"
        return ok("FTP", confidence=0.86, summary=summary, fields=fields, evidence=evidence, payload=payload)
    except Exception as exc:
        return failed("FTP", error=str(exc), payload=payload)
