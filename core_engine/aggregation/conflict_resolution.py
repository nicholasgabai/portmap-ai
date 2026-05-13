from __future__ import annotations

from hashlib import sha256
from typing import Any

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def build_conflict_record(
    *,
    conflict_type: str,
    affected_ref: str,
    source_node_ids: list[str],
    summary: str,
    severity: str = "medium",
    recommended_review: bool = True,
) -> dict[str, Any]:
    if severity not in VALID_SEVERITIES:
        severity = "medium"
    material = "|".join([conflict_type, affected_ref, ",".join(sorted(source_node_ids)), summary])
    return {
        "conflict_id": "conflict-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        "conflict_type": conflict_type,
        "affected_ref": affected_ref,
        "source_node_ids": sorted(set(source_node_ids)),
        "summary": summary,
        "recommended_review": recommended_review,
        "severity": severity,
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
    }
