from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from core_engine.telemetry.behavior_summary import (
    BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
    BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
)


def build_behavioral_intelligence_operator_view(
    behavioral_intelligence_summary: dict[str, Any] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not behavioral_intelligence_summary:
        return build_behavioral_intelligence_empty_state(generated_at=timestamp)
    dashboard = behavioral_intelligence_summary.get("dashboard_status") if isinstance(behavioral_intelligence_summary.get("dashboard_status"), dict) else {}
    state_summary = behavioral_intelligence_summary.get("state_summary") if isinstance(behavioral_intelligence_summary.get("state_summary"), dict) else {}
    rollups = behavioral_intelligence_summary.get("component_rollups") if isinstance(behavioral_intelligence_summary.get("component_rollups"), dict) else {}
    return {
        "record_type": "behavioral_intelligence_operator_view",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "panel": "behavioral_intelligence",
        "status": str(dashboard.get("status") or state_summary.get("overall_state") or "unknown"),
        "generated_at": timestamp,
        "metrics": dict(dashboard.get("metrics") or {}),
        "state_summary": dict(state_summary),
        "component_rows": list(dashboard.get("component_rows") or []),
        "recommendations": list(behavioral_intelligence_summary.get("recommendations") or []),
        "explanations": list(behavioral_intelligence_summary.get("explanations") or []),
        "privacy_safety_summary": dict(behavioral_intelligence_summary.get("privacy_safety_summary") or {}),
        "rollup_status": {str(name): str((row or {}).get("state") or "unknown") for name, row in sorted(rollups.items()) if isinstance(row, dict)},
        "recommended_review": bool(dashboard.get("recommended_review")),
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_behavioral_intelligence_status_panel(
    behavioral_intelligence_summary: dict[str, Any] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    operator_view = build_behavioral_intelligence_operator_view(behavioral_intelligence_summary, generated_at=generated_at)
    return {
        "record_type": "behavioral_intelligence_status_panel",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "panel": "behavioral_intelligence_status",
        "status": operator_view["status"],
        "generated_at": operator_view["generated_at"],
        "metrics": dict(operator_view.get("metrics") or {}),
        "recommended_review": bool(operator_view.get("recommended_review")),
        "advisory_only": True,
        "enforcement_allowed": False,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def build_behavioral_intelligence_empty_state(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "behavioral_intelligence_empty_operator_view",
        "record_version": BEHAVIORAL_INTELLIGENCE_RECORD_VERSION,
        "panel": "behavioral_intelligence",
        "status": "empty",
        "generated_at": generated_at or _now(),
        "metrics": {},
        "state_summary": {
            "overall_state": "unavailable",
            "component_states": {},
            "recommended_review_count": 0,
        },
        "component_rows": [],
        "recommendations": [],
        "explanations": [],
        "privacy_safety_summary": {},
        "rollup_status": {},
        "recommended_review": False,
        **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    }


def deterministic_behavior_operator_view_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _now() -> str:
    return datetime.now(UTC).isoformat()
