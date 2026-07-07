from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


UTC_SUFFIX = "Z"


class AmbiguousTimestampError(ValueError):
    """Raised when a canonical timestamp would require guessing a timezone."""


def utc_now_iso() -> str:
    return utc_isoformat(datetime.now(UTC))


def utc_isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        raise AmbiguousTimestampError("naive datetime cannot be canonicalized as UTC")
    return value.astimezone(UTC).isoformat().replace("+00:00", UTC_SUFFIX)


def normalize_timestamp(value: Any, *, preserve_ambiguous: bool = True) -> str:
    if value in {None, ""}:
        return ""
    if isinstance(value, datetime):
        return utc_isoformat(value)
    if isinstance(value, (int, float)):
        if float(value) <= 0:
            return ""
        return utc_isoformat(_datetime_from_epoch(float(value)))
    text = str(value).strip()
    if text in {"", "-"}:
        return text
    try:
        epoch = float(text)
        if epoch <= 0:
            return ""
        return utc_isoformat(_datetime_from_epoch(epoch))
    except ValueError:
        pass
    parsed = parse_utc_instant(text)
    if parsed is not None:
        return utc_isoformat(parsed)
    if preserve_ambiguous:
        return text
    raise AmbiguousTimestampError(f"timestamp has no timezone: {text}")


def parse_utc_instant(value: Any) -> datetime | None:
    if value in {None, ""}:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value.astimezone(UTC)
    if isinstance(value, (int, float)):
        if float(value) <= 0:
            return None
        return _datetime_from_epoch(float(value))
    text = str(value).strip()
    if text in {"", "-", "0"}:
        return None
    try:
        return _datetime_from_epoch(float(text))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    try:
        if parsed.timestamp() <= 0:
            return None
    except Exception:
        return None
    return parsed.astimezone(UTC)


def format_utc_label(value: Any) -> str:
    parsed = parse_utc_instant(value)
    if parsed is None:
        text = str(value or "").strip()
        if text and text != "-":
            return f"{text} (timezone ambiguous)"
        return "-"
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def epoch_seconds(value: Any) -> float:
    parsed = parse_utc_instant(value)
    return parsed.timestamp() if parsed is not None else 0.0


def _datetime_from_epoch(value: float) -> datetime:
    if value <= 0:
        raise ValueError("epoch timestamp must be positive")
    if value > 10_000_000_000:
        value = value / 1000.0
    return datetime.fromtimestamp(value, UTC)
