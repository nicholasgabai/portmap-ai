"""Local node identity and coordination primitives."""

from core_engine.nodes.capabilities import NodeCapabilities, create_node_capabilities
from core_engine.nodes.identity import (
    NodeIdentity,
    NodeIdentityError,
    create_node_identity,
    generate_node_id,
    load_node_identity,
    node_identity_fingerprint,
    save_node_identity,
)
from core_engine.nodes.registry import (
    NODE_STATES,
    HeartbeatMetadata,
    NodeRegistry,
    NodeRegistryEntry,
)

__all__ = [
    "HeartbeatMetadata",
    "NODE_STATES",
    "NodeCapabilities",
    "NodeIdentity",
    "NodeIdentityError",
    "NodeRegistry",
    "NodeRegistryEntry",
    "create_node_capabilities",
    "create_node_identity",
    "generate_node_id",
    "load_node_identity",
    "node_identity_fingerprint",
    "save_node_identity",
]
