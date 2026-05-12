from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class NodeCapabilitiesError(ValueError):
    """Raised when node capability metadata is malformed."""


@dataclass(slots=True)
class NodeCapabilities:
    node_id: str
    role: str
    platform: str
    architecture: str
    supported_features: list[str] = field(default_factory=list)
    runtime_version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("node_id", "role", "platform", "architecture"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise NodeCapabilitiesError(f"{field_name} must be a non-empty string")
        if not isinstance(self.supported_features, list) or not all(isinstance(item, str) for item in self.supported_features):
            raise NodeCapabilitiesError("supported_features must be a list of strings")
        if self.runtime_version is not None and not isinstance(self.runtime_version, str):
            raise NodeCapabilitiesError("runtime_version must be a string when provided")
        if not isinstance(self.metadata, dict):
            raise NodeCapabilitiesError("metadata must be an object")

    @property
    def local_only(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "role": self.role,
            "platform": self.platform,
            "architecture": self.architecture,
            "supported_features": list(self.supported_features),
            "runtime_version": self.runtime_version,
            "metadata": dict(self.metadata),
            "local_only": self.local_only,
        }


def create_node_capabilities(
    *,
    node_id: str,
    role: str,
    platform: str,
    architecture: str,
    supported_features: list[str] | None = None,
    runtime_version: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> NodeCapabilities:
    return NodeCapabilities(
        node_id=node_id,
        role=role,
        platform=platform,
        architecture=architecture,
        supported_features=supported_features or [],
        runtime_version=runtime_version,
        metadata=metadata or {},
    )
