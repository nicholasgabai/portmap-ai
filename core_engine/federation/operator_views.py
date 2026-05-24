from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.diagnostics import build_federation_diagnostics
from core_engine.federation.exchange import build_exchange_summary
from core_engine.federation.signing import SIGNING_SAFETY_FLAGS, canonical_json
from core_engine.federation.transport import build_transport_session_summary
from core_engine.federation.trust import summarize_trust_profile


FEDERATION_OPERATOR_VIEW_RECORD_VERSION = 1
FEDERATION_PANEL_ORDER = (
    "trusted_peers",
    "transport_sessions",
    "signed_exchanges",
    "synchronization",
    "event_propagation",
    "diagnostics",
    "readiness",
    "counters",
)

FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS = {
    **SIGNING_SAFETY_FLAGS,
    "read_only": True,
    "api_compatible": True,
    "public_exposure_enabled": False,
    "cloud_sync_enabled": False,
    "textual_tui_replaced": False,
}


def build_federation_operator_view(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    distributed_state: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    session_rows = _rows(transport_sessions)
    exchange_rows = _exchange_rows(signed_exchanges)
    diagnostic_record = diagnostics
    if diagnostic_record is None and _has_any_input(
        trust_profile,
        session_rows,
        signed_exchanges,
        sync_result,
        event_batch,
        cluster_health,
        distributed_state,
    ):
        diagnostic_record = build_federation_diagnostics(
            trust_profile=trust_profile,
            transport_sessions=session_rows,
            signed_exchanges=signed_exchanges,
            sync_result=sync_result,
            event_batch=event_batch,
            cluster_health=cluster_health,
            distributed_state=distributed_state,
            generated_at=timestamp,
        )
    panels = {
        "trusted_peers": build_trusted_peer_status_panel(trust_profile, generated_at=timestamp),
        "transport_sessions": build_transport_session_panel(session_rows, generated_at=timestamp),
        "signed_exchanges": build_signed_exchange_panel(signed_exchanges, generated_at=timestamp),
        "synchronization": build_sync_window_panel(sync_result, generated_at=timestamp),
        "event_propagation": build_event_propagation_panel(event_batch, generated_at=timestamp),
        "diagnostics": build_federation_diagnostics_panel(diagnostic_record, generated_at=timestamp),
        "readiness": build_readiness_score_panel(diagnostic_record, generated_at=timestamp),
        "counters": build_federation_counter_panel(
            sync_result=sync_result,
            event_batch=event_batch,
            diagnostics=diagnostic_record,
            generated_at=timestamp,
        ),
    }
    empty_state = build_empty_federation_state_model(generated_at=timestamp) if _panels_empty(panels) else None
    summary = summarize_federation_operator_view(panels, generated_at=timestamp)
    api = build_federation_api_response(panels=panels, summary=summary, empty_state=empty_state, generated_at=timestamp)
    return {
        "record_type": "federation_operator_view",
        "record_version": FEDERATION_OPERATOR_VIEW_RECORD_VERSION,
        "view_id": _stable_id("federation-view", timestamp, summary, [row.get("session_id") for row in session_rows], [row.get("envelope_id") for row in exchange_rows]),
        "generated_at": timestamp,
        "status": summary["status"],
        "panels": panels,
        "empty_state": empty_state,
        "summary": summary,
        "api": api,
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def build_trusted_peer_status_panel(trust_profile: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not trust_profile:
        return _empty_panel("trusted_peers", generated_at=timestamp)
    summary = summarize_trust_profile(trust_profile, generated_at=timestamp)
    expired = int(summary.get("expired_peer_count") or 0)
    approved = int(summary.get("approved_peer_count") or 0)
    status = "review_required" if expired or approved == 0 else "ok"
    return _panel(
        "trusted_peers",
        status=status,
        metrics={
            "approved_peer_count": approved,
            "expired_peer_count": expired,
            "trust_scope_count": len(summary.get("by_trust_scope") or {}),
            "transport_mode_count": len(summary.get("by_transport_mode") or {}),
        },
        detail=summary,
        recommended_review=bool(expired or approved == 0),
        generated_at=timestamp,
    )


def build_transport_session_panel(sessions: Iterable[dict[str, Any]] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = _rows(sessions)
    if not rows:
        return _empty_panel("transport_sessions", generated_at=timestamp)
    summary = build_transport_session_summary(rows, generated_at=timestamp)
    by_status = summary.get("by_status") if isinstance(summary.get("by_status"), dict) else {}
    expired = int(summary.get("expired_session_count") or 0)
    rejected = int(by_status.get("rejected") or 0)
    status = "review_required" if expired or rejected else "ok"
    return _panel(
        "transport_sessions",
        status=status,
        metrics={
            "session_count": int(summary.get("session_count") or 0),
            "expired_session_count": expired,
            "rejected_session_count": rejected,
            "transport_mode_count": len(summary.get("by_transport_mode") or {}),
        },
        detail=summary,
        recommended_review=bool(expired or rejected),
        generated_at=timestamp,
    )


def build_signed_exchange_panel(
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = _exchange_rows(signed_exchanges)
    if not rows:
        return _empty_panel("signed_exchanges", generated_at=timestamp)
    summary = signed_exchanges if isinstance(signed_exchanges, dict) and "by_status" in signed_exchanges else build_exchange_summary(rows, generated_at=timestamp)
    by_status = summary.get("by_status") if isinstance(summary.get("by_status"), dict) else {}
    rejected = sum(int(by_status.get(status) or 0) for status in ("rejected", "stale", "replayed", "malformed", "untrusted"))
    status = "review_required" if rejected else "ok"
    return _panel(
        "signed_exchanges",
        status=status,
        metrics={
            "envelope_count": int(summary.get("envelope_count") or len(rows)),
            "accepted_exchange_count": int(by_status.get("accepted") or by_status.get("exchange-ready") or 0),
            "rejected_exchange_count": rejected,
            "trust_scope_count": len(summary.get("by_trust_scope") or {}),
        },
        detail=dict(summary),
        recommended_review=bool(rejected),
        generated_at=timestamp,
    )


def build_sync_window_panel(sync_result: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = _summary(sync_result)
    if not summary:
        return _empty_panel("synchronization", generated_at=timestamp)
    review = bool(summary.get("administrator_review_required"))
    return _panel(
        "synchronization",
        status=str(summary.get("status") or ("review_required" if review else "ok")),
        metrics={
            "accepted_update_count": int(summary.get("accepted_update_count") or 0),
            "rejected_update_count": int(summary.get("rejected_update_count") or 0),
            "stale_update_count": int(summary.get("stale_update_count") or 0),
            "replayed_update_count": int(summary.get("replayed_update_count") or 0),
            "conflict_count": int(summary.get("conflict_count") or 0),
            "drift_count": int(summary.get("drift_count") or 0),
        },
        detail=summary,
        recommended_review=review,
        generated_at=timestamp,
    )


def build_event_propagation_panel(event_batch: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = _summary(event_batch)
    if not summary:
        return _empty_panel("event_propagation", generated_at=timestamp)
    review = bool(summary.get("administrator_review_required"))
    return _panel(
        "event_propagation",
        status=str(summary.get("status") or ("review_required" if review else "ok")),
        metrics={
            "event_count": int(summary.get("event_count") or 0),
            "accepted_event_count": int(summary.get("accepted_event_count") or 0),
            "rejected_event_count": int(summary.get("rejected_event_count") or 0),
            "duplicate_event_count": int(summary.get("duplicate_event_count") or 0),
            "stale_event_count": int(summary.get("stale_event_count") or 0),
            "malformed_event_count": int(summary.get("malformed_event_count") or 0),
        },
        detail=summary,
        recommended_review=review,
        generated_at=timestamp,
    )


def build_federation_diagnostics_panel(diagnostics: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not diagnostics:
        return _empty_panel("diagnostics", generated_at=timestamp)
    dashboard = diagnostics.get("dashboard_status") if isinstance(diagnostics.get("dashboard_status"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return _panel(
        "diagnostics",
        status=str(diagnostics.get("status") or dashboard.get("status") or "unknown"),
        metrics={
            "readiness_score": int(metrics.get("readiness_score") or 0),
            "check_count": int(metrics.get("check_count") or 0),
            "degraded_count": int(metrics.get("degraded_count") or 0),
            "unavailable_count": int(metrics.get("unavailable_count") or 0),
            "recommendation_count": int(metrics.get("recommendation_count") or len(diagnostics.get("recommendations") or [])),
        },
        detail=dashboard or diagnostics,
        recommended_review=bool(diagnostics.get("recommendations")),
        generated_at=timestamp,
    )


def build_readiness_score_panel(diagnostics: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not diagnostics:
        return _empty_panel("readiness", generated_at=timestamp)
    health = diagnostics.get("health") if isinstance(diagnostics.get("health"), dict) else {}
    readiness = health.get("readiness") if isinstance(health.get("readiness"), dict) else {}
    score = int(readiness.get("score") or 0)
    return _panel(
        "readiness",
        status=str(readiness.get("status") or diagnostics.get("status") or "unknown"),
        metrics={
            "readiness_score": score,
            "degraded_below": int(readiness.get("degraded_below") or 0),
            "recommendation_count": len(diagnostics.get("recommendations") or []),
        },
        detail=readiness,
        recommended_review=bool(score and readiness.get("status") == "degraded"),
        generated_at=timestamp,
    )


def build_federation_counter_panel(
    *,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    sync_summary = _summary(sync_result)
    event_summary = _summary(event_batch)
    diagnostic_metrics = {}
    if diagnostics:
        dashboard = diagnostics.get("dashboard_status") if isinstance(diagnostics.get("dashboard_status"), dict) else {}
        diagnostic_metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    metrics = {
        "stale_update_count": int(sync_summary.get("stale_update_count") or diagnostic_metrics.get("stale_update_count") or 0),
        "rejected_update_count": int(sync_summary.get("rejected_update_count") or diagnostic_metrics.get("rejected_update_count") or 0),
        "replayed_update_count": int(sync_summary.get("replayed_update_count") or diagnostic_metrics.get("replayed_update_count") or 0),
        "duplicate_event_count": int(event_summary.get("duplicate_event_count") or diagnostic_metrics.get("duplicate_event_count") or 0),
        "stale_event_count": int(event_summary.get("stale_event_count") or 0),
        "rejected_event_count": int(event_summary.get("rejected_event_count") or diagnostic_metrics.get("rejected_event_count") or 0),
    }
    if not any(metrics.values()) and not (sync_summary or event_summary or diagnostics):
        return _empty_panel("counters", generated_at=timestamp)
    review = any(metrics.values())
    return _panel(
        "counters",
        status="review_required" if review else "ok",
        metrics=metrics,
        detail={"sync_summary": sync_summary, "event_summary": event_summary},
        recommended_review=review,
        generated_at=timestamp,
    )


def build_empty_federation_state_model(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "federation_empty_state",
        "status": "empty",
        "generated_at": generated_at or _now(),
        "message": "No trusted federation records are available for local dashboard or API views.",
        "remote_control_enabled": False,
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def build_federation_api_response(
    *,
    panels: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    empty_state: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    ordered_panels = {name: panels[name] for name in FEDERATION_PANEL_ORDER if name in panels}
    return {
        "record_type": "federation_operator_api",
        "status": summary.get("status", "ok"),
        "generated_at": generated_at or _now(),
        "count": int(summary.get("active_panel_count") or 0),
        "items": list(ordered_panels.values()),
        "panels": ordered_panels,
        "summary": dict(summary),
        "empty_state": empty_state,
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def summarize_federation_operator_view(panels: dict[str, dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    ordered = [panels[name] for name in FEDERATION_PANEL_ORDER if name in panels]
    by_status: dict[str, int] = {}
    for panel in ordered:
        status = str(panel.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    review_count = sum(1 for panel in ordered if panel.get("recommended_review"))
    active_count = sum(1 for panel in ordered if panel.get("status") != "empty")
    status = "empty" if active_count == 0 else "review_required" if review_count else "ok"
    return {
        "record_type": "federation_operator_view_summary",
        "generated_at": generated_at or _now(),
        "status": status,
        "panel_count": len(ordered),
        "active_panel_count": active_count,
        "empty_panel_count": by_status.get("empty", 0),
        "recommended_review_count": review_count,
        "by_status": dict(sorted(by_status.items())),
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def deterministic_federation_operator_view_json(record: dict[str, Any]) -> str:
    return canonical_json(record)


def _panel(
    name: str,
    *,
    status: str,
    metrics: dict[str, int],
    detail: dict[str, Any],
    recommended_review: bool,
    generated_at: str,
) -> dict[str, Any]:
    return {
        "record_type": "federation_dashboard_panel",
        "panel": name,
        "status": status,
        "generated_at": generated_at,
        "metrics": dict(sorted(metrics.items())),
        "detail": detail,
        "recommended_review": bool(recommended_review),
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def _empty_panel(name: str, *, generated_at: str) -> dict[str, Any]:
    return _panel(
        name,
        status="empty",
        metrics={},
        detail={"message": f"No {name.replace('_', ' ')} records were provided."},
        recommended_review=False,
        generated_at=generated_at,
    )


def _summary(value: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    summary = value.get("summary")
    return dict(summary) if isinstance(summary, dict) else {}


def _exchange_rows(value: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if not value:
        return []
    if isinstance(value, dict):
        if isinstance(value.get("envelopes"), list):
            return _rows(value.get("envelopes"))
        if value.get("record_type") == "signed_runtime_summary_envelope":
            return [dict(value)]
        return []
    return _rows(value)


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in value or [] if isinstance(row, dict)]


def _panels_empty(panels: dict[str, dict[str, Any]]) -> bool:
    return all(panel.get("status") == "empty" for panel in panels.values())


def _has_any_input(*items: Any) -> bool:
    for item in items:
        if item:
            return True
    return False


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
