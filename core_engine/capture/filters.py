"""Safe metadata-only capture filter descriptions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


FILTER_PRESETS: Dict[str, Dict[str, Any]] = {
    "all": {"expression": "all", "protocols": [], "ports": [], "description": "all packet metadata"},
    "tcp": {"expression": "tcp", "protocols": ["TCP"], "ports": [], "description": "TCP packet metadata"},
    "udp": {"expression": "udp", "protocols": ["UDP"], "ports": [], "description": "UDP packet metadata"},
    "dns": {"expression": "udp port 53 or tcp port 53", "protocols": ["UDP", "TCP"], "ports": [53], "description": "DNS metadata"},
    "http": {"expression": "tcp port 80", "protocols": ["TCP"], "ports": [80], "description": "HTTP metadata"},
    "https": {"expression": "tcp port 443", "protocols": ["TCP"], "ports": [443], "description": "HTTPS metadata"},
    "ssh": {"expression": "tcp port 22", "protocols": ["TCP"], "ports": [22], "description": "SSH metadata"},
    "smb": {"expression": "tcp port 445", "protocols": ["TCP"], "ports": [445], "description": "SMB metadata"},
    "broadcast": {"expression": "broadcast", "protocols": [], "ports": [], "description": "broadcast metadata"},
    "multicast": {"expression": "multicast", "protocols": [], "ports": [], "description": "multicast metadata"},
}


@dataclass(frozen=True)
class CaptureFilter:
    name: str
    expression: str
    mode: str = "preset"
    protocols: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    description: str = "-"
    valid: bool = True
    reason: str = "ok"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "expression": self.expression,
            "mode": self.mode,
            "protocols": list(self.protocols),
            "ports": list(self.ports),
            "description": self.description,
            "valid": self.valid,
            "reason": self.reason,
        }


def build_capture_filter(value: str | None = None, *, mode: str = "preset") -> CaptureFilter:
    name = (value or "all").strip().lower()
    if mode == "preset":
        preset = FILTER_PRESETS.get(name)
        if preset is None:
            return CaptureFilter(
                name=name or "unknown",
                expression=name or "-",
                mode=mode,
                valid=False,
                reason="unsupported_filter_preset",
            )
        return CaptureFilter(
            name=name,
            expression=preset["expression"],
            mode=mode,
            protocols=tuple(preset["protocols"]),
            ports=tuple(preset["ports"]),
            description=preset["description"],
        )
    expression = " ".join((value or "").replace("\n", " ").replace("\r", " ").split())
    if not expression:
        return CaptureFilter(name="empty", expression="-", mode=mode, valid=False, reason="empty_filter")
    blocked_tokens = {";", "&&", "||", "`", "$(", "|", ">", "<"}
    if any(token in expression for token in blocked_tokens):
        return CaptureFilter(
            name="custom",
            expression=expression,
            mode=mode,
            valid=False,
            reason="unsafe_filter_expression",
        )
    return CaptureFilter(
        name="custom",
        expression=expression,
        mode=mode,
        description="custom metadata filter expression",
    )


def validate_capture_filter(value: str | None = None, *, mode: str = "preset") -> Dict[str, Any]:
    return build_capture_filter(value, mode=mode).to_dict()
