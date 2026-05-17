from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable


SUPPORTED_PATTERN_TYPES = {"string", "hex"}
SAFETY_FLAGS = {
    "local_only": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


def normalize_patterns(
    patterns: Iterable[dict[str, Any]] | None,
    *,
    max_patterns: int = 32,
    max_pattern_bytes: int = 128,
) -> dict[str, Any]:
    rows = list(patterns or [])
    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, pattern in enumerate(rows[:max_patterns]):
        if not isinstance(pattern, dict):
            errors.append(f"pattern {index} must be an object")
            continue
        pattern_type = str(pattern.get("type") or "string")
        name = str(pattern.get("name") or f"pattern-{index}")
        value = pattern.get("value")
        if pattern_type not in SUPPORTED_PATTERN_TYPES:
            errors.append(f"{name} has unsupported pattern type {pattern_type}")
            continue
        try:
            encoded = _pattern_bytes(pattern_type, value)
        except ValueError as exc:
            errors.append(f"{name}: {exc}")
            continue
        if not encoded:
            errors.append(f"{name} pattern cannot be empty")
            continue
        if len(encoded) > max_pattern_bytes:
            errors.append(f"{name} exceeds max pattern length {max_pattern_bytes}")
            continue
        normalized.append(
            {
                "pattern_id": _pattern_id(name, pattern_type, encoded),
                "name": name,
                "type": pattern_type,
                "value_summary": encoded[:16].hex(),
                "length": len(encoded),
                "case_sensitive": bool(pattern.get("case_sensitive", False)),
                "_bytes": encoded,
            }
        )
    if len(rows) > max_patterns:
        errors.append(f"pattern count exceeds max_patterns {max_patterns}")
    public_patterns = [{key: value for key, value in item.items() if key != "_bytes"} for item in normalized]
    return {
        "ok": not errors,
        "status": "ok" if not errors else "invalid",
        "patterns": public_patterns,
        "_patterns": normalized,
        "errors": errors,
        **SAFETY_FLAGS,
    }


def detect_patterns(data: bytes | bytearray, patterns: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized = normalize_patterns(patterns)
    if not normalized["ok"]:
        return []
    raw = bytes(data)
    results: list[dict[str, Any]] = []
    for pattern in normalized["_patterns"]:
        needle = bytes(pattern["_bytes"])
        haystack = raw
        if pattern["type"] == "string" and not pattern["case_sensitive"]:
            needle = needle.lower()
            haystack = raw.lower()
        offsets = _find_offsets(haystack, needle)
        if offsets:
            results.append(
                {
                    "pattern_id": pattern["pattern_id"],
                    "name": pattern["name"],
                    "type": pattern["type"],
                    "match_count": len(offsets),
                    "offsets": offsets[:8],
                }
            )
    return results


def _pattern_bytes(pattern_type: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("pattern value must be a string")
    if pattern_type == "hex":
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("hex pattern value is invalid") from exc
    return value.encode("utf-8")


def _pattern_id(name: str, pattern_type: str, encoded: bytes) -> str:
    digest = sha256(name.encode("utf-8") + b":" + pattern_type.encode("utf-8") + b":" + encoded).hexdigest()[:12]
    return f"pattern-{digest}"


def _find_offsets(haystack: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        offset = haystack.find(needle, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + max(len(needle), 1)
    return offsets
