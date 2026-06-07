from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


TOPOLOGY_VISUAL_RECORD_VERSION = 1
SOURCE_MODES = {"live", "simulated", "fixture", "replay", "unknown"}
ASSET_CATEGORIES = {
    "WORKSTATION",
    "SERVER",
    "ROUTER",
    "SWITCH",
    "NAS",
    "PRINTER",
    "PHONE",
    "IOT",
    "UNKNOWN",
}
TOPOLOGY_VISUAL_SAFETY_FLAGS = {
    "visualization_model_only": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "packet_payload_inspected": False,
    "raw_packet_stored": False,
    "pcap_generated": False,
    "raw_dns_history_stored": False,
    "private_identifier_exported": False,
    "browser_ui_started": False,
    "enforcement_enabled": False,
    "automatic_changes": False,
}


class TopologyVisualizationError(ValueError):
    """Raised when visualization topology inputs are malformed."""


@dataclass(frozen=True)
class TopologyNode:
    node_id: str
    label: str
    asset_category: str = "UNKNOWN"
    node_class: str = "unknown"
    role_hint: str = "unknown"
    source_mode: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 1
    confidence_score: float = 0.0
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "visual_topology_node",
            "record_version": TOPOLOGY_VISUAL_RECORD_VERSION,
            "node_id": self.node_id,
            "label": self.label,
            "asset_category": normalize_asset_category(self.asset_category),
            "node_class": _safe_token(self.node_class),
            "role_hint": _safe_token(self.role_hint),
            "source_mode": normalize_source_mode(self.source_mode),
            "data_source": normalize_source_mode(self.source_mode),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": max(0, int(self.observation_count or 0)),
            "confidence_score": clamp_score(self.confidence_score),
            "advisory_notes": [str(note) for note in self.advisory_notes],
            **TOPOLOGY_VISUAL_SAFETY_FLAGS,
        }


@dataclass(frozen=True)
class TopologyEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str = "flow_observed"
    flow_reference: str = ""
    protocol: str = "unknown"
    service_hint: str = "unknown"
    source_mode: str = "unknown"
    observation_count: int = 1
    weight: float = 0.0
    confidence_score: float = 0.0
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "visual_topology_edge",
            "record_version": TOPOLOGY_VISUAL_RECORD_VERSION,
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relationship_type": _safe_token(self.relationship_type),
            "flow_reference": _safe_reference(self.flow_reference),
            "protocol": _safe_token(self.protocol),
            "service_hint": _safe_token(self.service_hint),
            "source_mode": normalize_source_mode(self.source_mode),
            "data_source": normalize_source_mode(self.source_mode),
            "observation_count": max(0, int(self.observation_count or 0)),
            "weight": clamp_score(self.weight),
            "confidence_score": clamp_score(self.confidence_score),
            "advisory_notes": [str(note) for note in self.advisory_notes],
            **TOPOLOGY_VISUAL_SAFETY_FLAGS,
        }


@dataclass(frozen=True)
class TopologyGraph:
    graph_id: str
    generated_at: str
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, Any] = field(default_factory=dict)
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        node_rows = [node.to_dict() for node in self.nodes]
        edge_rows = [edge.to_dict() for edge in self.edges]
        return {
            "record_type": "visual_topology_graph",
            "record_version": TOPOLOGY_VISUAL_RECORD_VERSION,
            "graph_id": self.graph_id,
            "generated_at": self.generated_at,
            "nodes": node_rows,
            "edges": edge_rows,
            "summary": dict(self.summary),
            "limits": dict(self.limits),
            "advisory_notes": [str(note) for note in self.advisory_notes],
            **TOPOLOGY_VISUAL_SAFETY_FLAGS,
        }


def deterministic_topology_json(record: TopologyGraph | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, TopologyGraph) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def normalize_source_mode(value: Any) -> str:
    mode = str(value or "unknown").strip().lower().replace("-", "_")
    return mode if mode in SOURCE_MODES else "unknown"


def normalize_asset_category(value: Any) -> str:
    category = str(value or "UNKNOWN").strip().upper().replace("-", "_")
    return category if category in ASSET_CATEGORIES else "UNKNOWN"


def clamp_score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(1.0, score)), 3)


def now_timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _safe_token(value: Any) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    allowed = [char for char in token if char.isalnum() or char == "_"]
    return "".join(allowed)[:64] or "unknown"


def _safe_reference(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "_", ":"})
    return safe[:96]
