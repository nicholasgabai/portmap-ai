from __future__ import annotations

from copy import deepcopy
from typing import Any


SAMPLE_DASHBOARD_API_DATA: dict[str, dict[str, Any]] = {
    "health": {
        "status": "ok",
        "generated_at": "sample-generated-at",
        "bind_host": "127.0.0.1",
        "port": 9200,
        "local_only": True,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    },
    "assets": {
        "status": "ok",
        "count": 2,
        "items": [
            {"asset_id": "asset-sample-001", "status": "reachable"},
            {"asset_id": "asset-sample-002", "status": "unknown"},
        ],
        "generated_at": "sample-generated-at",
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    },
    "events": {
        "status": "ok",
        "count": 3,
        "items": [
            {"event_id": "event-sample-001", "event_type": "asset_observed", "severity": "info"},
            {"event_id": "event-sample-002", "event_type": "operator_review_created", "severity": "medium"},
            {"event_id": "event-sample-003", "event_type": "policy_review_required", "severity": "high"},
        ],
        "generated_at": "sample-generated-at",
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    },
    "snapshots": {
        "status": "ok",
        "count": 1,
        "items": [{"snapshot_id": "snapshot-sample-001", "label": "sample-baseline"}],
        "generated_at": "sample-generated-at",
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    },
    "nodes": {
        "status": "ok",
        "count": 1,
        "items": [{"node_id": "worker-sample", "state": "online", "health_status": "ok"}],
        "generated_at": "sample-generated-at",
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    },
    "topology": {
        "status": "ok",
        "count": 1,
        "items": [{"edge_id": "edge-sample-001", "src": "asset-sample-001", "dst": "asset-sample-002"}],
        "generated_at": "sample-generated-at",
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    },
}


def sample_dashboard_api_data() -> dict[str, dict[str, Any]]:
    return deepcopy(SAMPLE_DASHBOARD_API_DATA)
