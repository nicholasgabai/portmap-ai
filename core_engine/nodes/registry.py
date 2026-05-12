from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.nodes.capabilities import NodeCapabilities
from core_engine.nodes.identity import NodeIdentity


NODE_STATES = frozenset({"registered", "online", "stale", "offline", "removed"})


class NodeRegistryError(ValueError):
    """Raised when node registry data is malformed."""


@dataclass(slots=True)
class HeartbeatMetadata:
    last_seen_at: str
    heartbeat_count: int = 0
    status_message: str = ""
    health_status: str = "unknown"
    scheduler_status: str | None = None
    event_queue_depth: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.last_seen_at, str) or not self.last_seen_at.strip():
            raise NodeRegistryError("last_seen_at must be a non-empty string")
        if not isinstance(self.heartbeat_count, int) or self.heartbeat_count < 0:
            raise NodeRegistryError("heartbeat_count must be a non-negative integer")
        for field_name in ("status_message", "health_status"):
            if not isinstance(getattr(self, field_name), str):
                raise NodeRegistryError(f"{field_name} must be a string")
        if self.scheduler_status is not None and not isinstance(self.scheduler_status, str):
            raise NodeRegistryError("scheduler_status must be a string when provided")
        if self.event_queue_depth is not None and (
            not isinstance(self.event_queue_depth, int) or self.event_queue_depth < 0
        ):
            raise NodeRegistryError("event_queue_depth must be a non-negative integer when provided")

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_seen_at": self.last_seen_at,
            "heartbeat_count": self.heartbeat_count,
            "status_message": self.status_message,
            "health_status": self.health_status,
            "scheduler_status": self.scheduler_status,
            "event_queue_depth": self.event_queue_depth,
        }


@dataclass(slots=True)
class NodeRegistryEntry:
    identity: NodeIdentity
    capabilities: NodeCapabilities
    lifecycle_state: str = "registered"
    registered_at: str = field(default_factory=lambda: _now())
    updated_at: str = field(default_factory=lambda: _now())
    heartbeat: HeartbeatMetadata | None = None
    removed_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.lifecycle_state not in NODE_STATES:
            raise NodeRegistryError(f"unsupported node lifecycle state: {self.lifecycle_state}")
        if self.identity.node_id != self.capabilities.node_id:
            raise NodeRegistryError("identity and capability node IDs must match")
        if self.identity.role != self.capabilities.role:
            raise NodeRegistryError("identity and capability roles must match")
        if not isinstance(self.metadata, dict):
            raise NodeRegistryError("metadata must be an object")

    @property
    def node_id(self) -> str:
        return self.identity.node_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "role": self.identity.role,
            "lifecycle_state": self.lifecycle_state,
            "registered_at": self.registered_at,
            "updated_at": self.updated_at,
            "removed_at": self.removed_at,
            "identity": self.identity.to_dict(),
            "capabilities": self.capabilities.to_dict(),
            "heartbeat": self.heartbeat.to_dict() if self.heartbeat else None,
            "metadata": dict(self.metadata),
            "local_only": True,
            "automatic_changes": False,
        }

    def summary(self) -> dict[str, Any]:
        heartbeat = self.heartbeat.to_dict() if self.heartbeat else {}
        return {
            "node_id": self.node_id,
            "role": self.identity.role,
            "state": self.lifecycle_state,
            "platform": self.capabilities.platform,
            "architecture": self.capabilities.architecture,
            "supported_features": list(self.capabilities.supported_features),
            "heartbeat_count": heartbeat.get("heartbeat_count", 0),
            "last_seen_at": heartbeat.get("last_seen_at"),
            "health_status": heartbeat.get("health_status", "unknown"),
            "scheduler_status": heartbeat.get("scheduler_status"),
            "event_queue_depth": heartbeat.get("event_queue_depth"),
        }


class NodeRegistry:
    """In-memory local node registry for coordination primitives."""

    def __init__(self) -> None:
        self._nodes: dict[str, NodeRegistryEntry] = {}

    @property
    def local_only(self) -> bool:
        return True

    def register_node(
        self,
        identity: NodeIdentity,
        capabilities: NodeCapabilities,
        *,
        metadata: dict[str, Any] | None = None,
        now: str | None = None,
    ) -> NodeRegistryEntry:
        timestamp = now or _now()
        entry = NodeRegistryEntry(
            identity=identity,
            capabilities=capabilities,
            lifecycle_state="registered",
            registered_at=timestamp,
            updated_at=timestamp,
            metadata=metadata or {},
        )
        self._nodes[entry.node_id] = entry
        return entry

    def update_heartbeat(
        self,
        node_id: str,
        *,
        now: str | None = None,
        status_message: str = "",
        health_status: str = "ok",
        scheduler_status: str | None = None,
        event_queue_depth: int | None = None,
    ) -> NodeRegistryEntry:
        entry = self._require_node(node_id)
        timestamp = now or _now()
        previous_count = entry.heartbeat.heartbeat_count if entry.heartbeat else 0
        entry.heartbeat = HeartbeatMetadata(
            last_seen_at=timestamp,
            heartbeat_count=previous_count + 1,
            status_message=status_message,
            health_status=health_status,
            scheduler_status=scheduler_status,
            event_queue_depth=event_queue_depth,
        )
        entry.lifecycle_state = "online"
        entry.updated_at = timestamp
        return entry

    def mark_stale_nodes(
        self,
        *,
        now: str | None = None,
        stale_after_seconds: float,
        offline_after_seconds: float | None = None,
    ) -> list[NodeRegistryEntry]:
        if stale_after_seconds < 0:
            raise NodeRegistryError("stale_after_seconds must be non-negative")
        if offline_after_seconds is not None and offline_after_seconds < stale_after_seconds:
            raise NodeRegistryError("offline_after_seconds must be greater than or equal to stale_after_seconds")
        current = _parse_time(now or _now())
        changed: list[NodeRegistryEntry] = []
        for entry in self._nodes.values():
            if entry.lifecycle_state in {"removed", "offline"} or entry.heartbeat is None:
                continue
            age = (current - _parse_time(entry.heartbeat.last_seen_at)).total_seconds()
            next_state = entry.lifecycle_state
            if offline_after_seconds is not None and age >= offline_after_seconds:
                next_state = "offline"
            elif age >= stale_after_seconds:
                next_state = "stale"
            if next_state != entry.lifecycle_state:
                entry.lifecycle_state = next_state
                entry.updated_at = now or _now()
                changed.append(entry)
        return changed

    def list_nodes(self, *, include_removed: bool = False) -> list[NodeRegistryEntry]:
        nodes = self._nodes.values() if include_removed else (
            node for node in self._nodes.values() if node.lifecycle_state != "removed"
        )
        return sorted(nodes, key=lambda item: item.node_id)

    def get_node(self, node_id: str) -> NodeRegistryEntry | None:
        return self._nodes.get(node_id)

    def remove_node(self, node_id: str, *, now: str | None = None) -> bool:
        entry = self._nodes.get(node_id)
        if entry is None:
            return False
        timestamp = now or _now()
        entry.lifecycle_state = "removed"
        entry.removed_at = timestamp
        entry.updated_at = timestamp
        return True

    def summarize_nodes(self, *, include_removed: bool = False) -> dict[str, Any]:
        nodes = self.list_nodes(include_removed=include_removed)
        by_state = {state: 0 for state in sorted(NODE_STATES)}
        for node in nodes:
            by_state[node.lifecycle_state] += 1
        return {
            "node_count": len(nodes),
            "by_state": by_state,
            "nodes": [node.summary() for node in nodes],
            "local_only": True,
            "automatic_changes": False,
        }

    def _require_node(self, node_id: str) -> NodeRegistryEntry:
        entry = self._nodes.get(node_id)
        if entry is None or entry.lifecycle_state == "removed":
            raise NodeRegistryError(f"node is not registered: {node_id}")
        return entry


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise NodeRegistryError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed
