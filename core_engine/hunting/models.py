"""Immutable metadata-only packet hunting models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple


FORBIDDEN_HUNT_FIELDS = {
    "payload",
    "payload_body",
    "payload_bytes",
    "raw_packet",
    "raw_bytes",
    "packet_bytes",
    "body",
    "content",
}


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_id(prefix: str, value: Any, *, length: int = 16) -> str:
    return f"{prefix}-{hashlib.sha256(stable_json(value).encode('utf-8')).hexdigest()[:length]}"


def safe_text(value: Any, default: str = "-") -> str:
    text = " ".join(str(value or "").replace("\n", " ").replace("\r", " ").split())
    return text or default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(parsed, 0)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default
    return max(0.0, min(1.0, parsed))


def safe_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: Dict[str, Any] = {}
    for key in sorted(value):
        normalized_key = safe_text(key).lower()
        if normalized_key in FORBIDDEN_HUNT_FIELDS:
            continue
        item = value[key]
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[str(key)] = item
        elif isinstance(item, (list, tuple)):
            safe_items = []
            for entry in item:
                if isinstance(entry, (str, int, float, bool)) or entry is None:
                    safe_items.append(entry)
                elif isinstance(entry, dict):
                    safe_items.append(safe_metadata(entry))
                else:
                    safe_items.append(str(entry))
            result[str(key)] = safe_items
        elif isinstance(item, dict):
            result[str(key)] = safe_metadata(item)
        else:
            result[str(key)] = str(item)
    return result


def safe_tags(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        source = [value]
    else:
        source = list(value or [])
    return tuple(sorted({safe_text(item).lower() for item in source if safe_text(item) != "-"}))


@dataclass(frozen=True)
class HuntQuery:
    query_id: str = ""
    created_at: str = "-"
    time_start: str = "-"
    time_end: str = "-"
    src_ip: str = "-"
    dst_ip: str = "-"
    host: str = "-"
    mac: str = "-"
    protocol: str = "-"
    application_protocol: str = "-"
    transport_protocol: str = "-"
    port: int = 0
    src_port: int = 0
    dst_port: int = 0
    flow_key: str = "-"
    conversation_id: str = "-"
    session_id: str = "-"
    interface: str = "-"
    importance: str = "-"
    confidence: float = 0.0
    tags: Tuple[str, ...] = field(default_factory=tuple)
    limit: int = 0
    offset: int = 0
    sort_by: str = "time"
    sort_direction: str = "asc"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = {
            "created_at": safe_text(self.created_at),
            "time_start": safe_text(self.time_start),
            "time_end": safe_text(self.time_end),
            "src_ip": safe_text(self.src_ip),
            "dst_ip": safe_text(self.dst_ip),
            "host": safe_text(self.host),
            "mac": safe_text(self.mac),
            "protocol": safe_text(self.protocol).lower(),
            "application_protocol": safe_text(self.application_protocol).lower(),
            "transport_protocol": safe_text(self.transport_protocol).lower(),
            "port": safe_int(self.port),
            "src_port": safe_int(self.src_port),
            "dst_port": safe_int(self.dst_port),
            "flow_key": safe_text(self.flow_key),
            "conversation_id": safe_text(self.conversation_id),
            "session_id": safe_text(self.session_id),
            "interface": safe_text(self.interface),
            "importance": safe_text(self.importance).lower(),
            "confidence": safe_float(self.confidence),
            "tags": safe_tags(self.tags),
            "limit": safe_int(self.limit),
            "offset": safe_int(self.offset),
            "sort_by": safe_text(self.sort_by, "time").lower(),
            "sort_direction": "desc" if safe_text(self.sort_direction).lower() == "desc" else "asc",
            "metadata": safe_metadata(self.metadata),
        }
        for key, value in normalized.items():
            object.__setattr__(self, key, value)
        if not safe_text(self.query_id, ""):
            object.__setattr__(self, "query_id", stable_id("hunt-query", normalized))
        else:
            object.__setattr__(self, "query_id", safe_text(self.query_id))

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | "HuntQuery") -> "HuntQuery":
        if isinstance(data, HuntQuery):
            return data
        source = safe_metadata(data or {})
        if "tags" in source:
            source["tags"] = safe_tags(source["tags"])
        return cls(**source)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "created_at": self.created_at,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "host": self.host,
            "mac": self.mac,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "transport_protocol": self.transport_protocol,
            "port": self.port,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flow_key": self.flow_key,
            "conversation_id": self.conversation_id,
            "session_id": self.session_id,
            "interface": self.interface,
            "importance": self.importance,
            "confidence": round(float(self.confidence), 3),
            "tags": list(self.tags),
            "limit": self.limit,
            "offset": self.offset,
            "sort_by": self.sort_by,
            "sort_direction": self.sort_direction,
            "metadata": safe_metadata(self.metadata),
        }


@dataclass(frozen=True)
class SavedQuery:
    name: str
    description: str
    query: HuntQuery
    tags: Tuple[str, ...] = field(default_factory=tuple)
    created_at: str = "-"
    updated_at: str = "-"
    version: str = "1"
    saved_query_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", safe_text(self.name))
        object.__setattr__(self, "description", safe_text(self.description))
        object.__setattr__(self, "query", HuntQuery.from_dict(self.query))
        object.__setattr__(self, "tags", safe_tags(self.tags))
        object.__setattr__(self, "created_at", safe_text(self.created_at))
        object.__setattr__(self, "updated_at", safe_text(self.updated_at))
        object.__setattr__(self, "version", safe_text(self.version, "1"))
        if not safe_text(self.saved_query_id, ""):
            object.__setattr__(
                self,
                "saved_query_id",
                stable_id(
                    "saved-hunt-query",
                    {
                        "name": self.name,
                        "query": self.query.to_dict(),
                        "version": self.version,
                    },
                ),
            )
        else:
            object.__setattr__(self, "saved_query_id", safe_text(self.saved_query_id))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "saved_query_id": self.saved_query_id,
            "name": self.name,
            "description": self.description,
            "query": self.query.to_dict(),
            "tags": list(self.tags),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }
