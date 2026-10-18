from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Any


UTC_SUFFIX = "Z"


class AmbiguousTimestampError(ValueError):
    """Raised when a canonical timestamp would require guessing a timezone."""


def utc_now_iso() -> str:
    return utc_isoformat(datetime.now(UTC))


def utc_isoformat(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
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
        if value.tzinfo is None or value.utcoffset() is None:
            return None
        return value.astimezone(UTC)
    if isinstance(value, (int, float)):
        if float(value) <= 0:
            return None
        try:
            return _datetime_from_epoch(float(value))
        except (ValueError, OverflowError, OSError):
            return None
    text = str(value).strip()
    if text in {"", "-", "0"}:
        return None
    try:
        return _datetime_from_epoch(float(text))
    except (ValueError, OverflowError, OSError):
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
    if not math.isfinite(value) or value <= 0:
        raise ValueError("epoch timestamp must be positive")
    if value > 10_000_000_000:
        value = value / 1000.0
    return datetime.fromtimestamp(value, UTC)


def timestamp_sort_key(value: Any) -> tuple[bool, float, str]:
    """Known instants sort chronologically; ambiguous values remain deterministic."""
    parsed = parse_utc_instant(value)
    return (parsed is not None, parsed.timestamp() if parsed else 0.0, str(value or ""))


def observation_timestamps(
    record: dict[str, Any], *, event_timestamp: Any = None,
    ingested_at: Any = None, strict: bool = False,
) -> dict[str, Any]:
    """Separate event time from receiver time without guessing legacy timezones."""
    raw = record.get("event_timestamp") if "event_timestamp" in record else record.get("timestamp") or record.get("observed_at") or event_timestamp
    event = normalize_timestamp(raw, preserve_ambiguous=not strict) if raw not in (None, "", "-") else None
    parsed = parse_utc_instant(event)
    if strict and parsed is None:
        raise AmbiguousTimestampError("canonical observation requires an aware event timestamp")
    result = {
        "event_timestamp": event,
        "timestamp": event,
        "timestamp_status": "canonical_utc" if parsed else "ambiguous_legacy" if event else "unavailable",
    }
    received = ingested_at if ingested_at is not None else record.get("ingested_at")
    if received not in (None, "", "-"):
        result["ingested_at"] = normalize_timestamp(received, preserve_ambiguous=False)
    return result
