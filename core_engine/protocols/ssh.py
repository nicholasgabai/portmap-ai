from __future__ import annotations

from core_engine.protocols.common import failed, first_line, ok, unknown


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        banner = first_line(payload)
        if not banner.startswith("SSH-"):
            return unknown("SSH", reason="missing_ssh_banner", payload=payload)
        parts = banner.split("-", 2)
        fields = {"banner": banner[:160]}
        if len(parts) >= 2:
            fields["protocol_version"] = parts[1]
        if len(parts) >= 3:
            fields["software"] = parts[2][:120]
        return ok("SSH", confidence=0.96, summary=f"SSH {fields.get('software', '')}".strip(), fields=fields, evidence=["ssh_banner"], payload=payload)
    except Exception as exc:
        return failed("SSH", error=str(exc), payload=payload)
