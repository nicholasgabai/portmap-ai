from __future__ import annotations

import json
import re
from typing import Any, Mapping

from core_engine.security import scrub_secrets


PRIVATE_IDENTIFIER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_ipv4", re.compile(r"\b(?:192\.168|10|172\.(?:1[6-9]|2[0-9]|3[0-1]))(?:\.[0-9]{1,3}){2}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("unix_home_path", re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+(?:/[^\s\"'<>]*)?")),
)

REDACTION_REPLACEMENTS = {
    "private_ipv4": "<redacted-ip>",
    "mac_address": "<redacted-mac>",
    "unix_home_path": "<redacted-path>",
}


def redact_operational_record(value: Any) -> Any:
    """Redact secret-like keys and private local identifiers from export data."""
    return _redact_strings(scrub_secrets(value))


def contains_private_identifiers(value: Any) -> bool:
    text = _to_text(value)
    return any(pattern.search(text) for _, pattern in PRIVATE_IDENTIFIER_PATTERNS)


def validate_placeholder_safe(value: Any) -> dict[str, Any]:
    text = _to_text(value)
    matches = sorted(
        {
            name
            for name, pattern in PRIVATE_IDENTIFIER_PATTERNS
            if pattern.search(text)
        }
    )
    return {
        "ok": not matches,
        "private_identifier_types": matches,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def _redact_strings(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _redact_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_strings(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_strings(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(text: str) -> str:
    redacted = text
    for name, pattern in PRIVATE_IDENTIFIER_PATTERNS:
        redacted = pattern.sub(REDACTION_REPLACEMENTS[name], redacted)
    return redacted


def _to_text(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
