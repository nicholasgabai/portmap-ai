from __future__ import annotations

from core_engine.protocols.common import failed, ok, unknown


SMB1_COMMANDS = {0x72: "negotiate", 0x73: "session_setup", 0x75: "tree_connect", 0xA2: "nt_create"}
SMB2_COMMANDS = {0: "negotiate", 1: "session_setup", 3: "tree_connect", 5: "create", 8: "read", 9: "write"}


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _strip_netbios(data: bytes) -> bytes:
    if len(data) >= 8 and data[0] == 0 and data[1] == 0 and data[2] == 0:
        return data[4:]
    return data


def dissect(payload: bytes, metadata: dict | None = None) -> dict:
    try:
        body = _strip_netbios(payload)
        if body.startswith(b"\xffSMB") and len(body) >= 5:
            command = body[4]
            fields = {"version": "SMB1", "command": SMB1_COMMANDS.get(command, f"0x{command:02x}")}
            return ok("SMB", confidence=0.95, summary=f"SMB1 {fields['command']}", fields=fields, evidence=["smb1_magic"], payload=payload)
        if body.startswith(b"\xfeSMB") and len(body) >= 14:
            command = _u16(body, 12)
            fields = {"version": "SMB2/3", "command": SMB2_COMMANDS.get(command, str(command))}
            return ok("SMB", confidence=0.95, summary=f"SMB2/3 {fields['command']}", fields=fields, evidence=["smb2_magic"], payload=payload)
        return unknown("SMB", reason="missing_smb_magic", payload=payload)
    except Exception as exc:
        return failed("SMB", error=str(exc), payload=payload)
