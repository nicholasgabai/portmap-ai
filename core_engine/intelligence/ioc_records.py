from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit


IOC_RECORD_VERSION = 1
IOC_TYPES = {
    "ipv4",
    "ipv6",
    "domain",
    "fqdn",
    "url",
    "sha256",
    "md5",
    "process_name",
    "tls_sni",
    "certificate_fingerprint",
    "dns_pattern",
    "unknown",
}
IOC_SOURCE_CATEGORIES = {
    "dns",
    "flow",
    "socket",
    "process",
    "tls",
    "packet",
    "topology",
    "manual",
    "unknown",
}
SOURCE_MODES = {"live", "simulated", "fixture", "replay", "unknown"}
IOC_SAFETY_FLAGS = {
    "metadata_only": True,
    "external_lookup_performed": False,
    "remote_feed_loaded": False,
    "raw_payload_stored": False,
    "raw_dns_history_stored": False,
    "private_identifier_exported": False,
    "enforcement_action_created": False,
    "preview_only": True,
    "destructive_action": False,
    "export_safe": True,
    "bounded": True,
}


class IOCRecordError(ValueError):
    """Raised when IOC input cannot be normalized safely."""


@dataclass(frozen=True)
class IOCRecord:
    ioc_id: str
    ioc_type: str
    value_hash: str
    value_preview: str
    source_category: str
    source_mode: str
    confidence_score: float
    first_seen: str
    last_seen: str
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    normalized_value: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "ioc_record",
            "record_version": IOC_RECORD_VERSION,
            "ioc_id": sanitize_reference(self.ioc_id),
            "ioc_type": normalize_ioc_type(self.ioc_type),
            "value_hash": str(self.value_hash or ""),
            "value_preview": sanitize_text(self.value_preview),
            "source_category": normalize_ioc_source_category(self.source_category),
            "source_mode": normalize_source_mode(self.source_mode),
            "confidence_score": clamp_score(self.confidence_score),
            "first_seen": str(self.first_seen or ""),
            "last_seen": str(self.last_seen or ""),
            "tags": sorted({sanitize_token(tag) for tag in self.tags if sanitize_token(tag)}),
            "metadata": sanitize_metadata(self.metadata),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_ioc_record(
    value: Any,
    *,
    ioc_type: str = "unknown",
    source_category: str = "unknown",
    source_mode: str = "unknown",
    confidence_score: float = 0.5,
    first_seen: str | None = None,
    last_seen: str | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    advisory_notes: list[str] | None = None,
) -> IOCRecord:
    normalized_type = normalize_ioc_type(ioc_type)
    normalized_value = normalize_ioc_value(value, normalized_type)
    if not normalized_value:
        raise IOCRecordError("ioc value is required")
    value_hash = hash_ioc_value(normalized_value, normalized_type)
    timestamp = now_timestamp()
    first = str(first_seen or timestamp)
    last = str(last_seen or first)
    record_id = "ioc-" + digest({"type": normalized_type, "value_hash": value_hash})[:16]
    notes = list(advisory_notes or [])
    notes.append("metadata-only IOC record; no verdict or enforcement")
    return IOCRecord(
        ioc_id=record_id,
        ioc_type=normalized_type,
        value_hash=value_hash,
        value_preview=redacted_value_preview(normalized_value, normalized_type),
        source_category=normalize_ioc_source_category(source_category),
        source_mode=normalize_source_mode(source_mode),
        confidence_score=clamp_score(confidence_score),
        first_seen=first,
        last_seen=last,
        tags=[sanitize_token(tag) for tag in tags or [] if sanitize_token(tag)],
        metadata=sanitize_metadata(metadata or {}),
        advisory_notes=notes,
        normalized_value=normalized_value,
    )


def normalize_ioc_type(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in IOC_TYPES else "unknown"


def normalize_ioc_source_category(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in IOC_SOURCE_CATEGORIES else "unknown"


def normalize_source_mode(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in SOURCE_MODES else "unknown"


def normalize_ioc_value(value: Any, ioc_type: str = "unknown") -> str:
    if value is None:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""
    normalized_type = normalize_ioc_type(ioc_type)
    if normalized_type == "ipv4":
        try:
            return str(ipaddress.IPv4Address(raw))
        except Exception as exc:
            raise IOCRecordError("invalid ipv4 IOC") from exc
    if normalized_type == "ipv6":
        try:
            return str(ipaddress.IPv6Address(raw)).lower()
        except Exception as exc:
            raise IOCRecordError("invalid ipv6 IOC") from exc
    if normalized_type in {"domain", "fqdn", "tls_sni"}:
        return raw.lower().rstrip(".")
    if normalized_type == "dns_pattern":
        return raw.lower().rstrip(".")
    if normalized_type == "url":
        parts = urlsplit(raw)
        if not parts.scheme or not parts.netloc:
            raise IOCRecordError("invalid url IOC")
        return urlunsplit(
            (
                parts.scheme.lower(),
                parts.netloc.lower(),
                parts.path or "",
                parts.query or "",
                "",
            )
        )
    if normalized_type in {"sha256", "md5", "certificate_fingerprint"}:
        return re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if normalized_type == "process_name":
        return raw.strip().lower()
    return raw.lower()


def hash_ioc_value(normalized_value: str, ioc_type: str = "unknown") -> str:
    return hashlib.sha256(f"{normalize_ioc_type(ioc_type)}:{normalized_value}".encode("utf-8")).hexdigest()


def redacted_value_preview(normalized_value: str, ioc_type: str = "unknown") -> str:
    return f"{normalize_ioc_type(ioc_type)}:{hash_ioc_value(normalized_value, ioc_type)[:12]}"


def sanitize_reference(value: Any) -> str:
    token = sanitize_token(value)
    if not token:
        return ""
    if _looks_private(token):
        return "ref-" + digest(token)[:12]
    return token[:96]


def sanitize_token(value: Any) -> str:
    if value is None:
        return ""
    token = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(value).strip())
    token = re.sub(r"-{2,}", "-", token).strip("-")
    return token[:128]


def sanitize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if _looks_private(text):
        return "redacted-" + digest(text)[:12]
    text = re.sub(r"[\r\n\t]+", " ", text)
    return text[:180]


def sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        safe_key = sanitize_token(key)
        if not safe_key:
            continue
        if isinstance(value, dict):
            safe[safe_key] = sanitize_metadata(value)
        elif isinstance(value, (list, tuple, set)):
            safe[safe_key] = [sanitize_text(item) for item in value][:16]
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[safe_key] = value
        else:
            safe[safe_key] = sanitize_text(value)
    return safe


def clamp_score(value: Any) -> float:
    try:
        return round(max(0.0, min(1.0, float(value))), 4)
    except Exception:
        return 0.0


def now_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")).hexdigest()


def deterministic_ioc_json(record: IOCRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, IOCRecord) else dict(record)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _looks_private(value: str) -> bool:
    return bool(
        re.search(r"\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b", value)
        or re.search(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value)
        or "/" in value
        or "\\" in value
        or "@" in value
        or re.search(r"\bhost(?:name)?\b", value, flags=re.IGNORECASE)
        or re.search(r"\buser(?:name)?\b", value, flags=re.IGNORECASE)
    )
