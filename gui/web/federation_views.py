from __future__ import annotations

from typing import Any

from core_engine.federation.operator_views import (
    FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    build_federation_operator_view,
)
from gui.web.render import render_metric_panel


def build_federation_dashboard_view(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: list[dict[str, Any]] | None = None,
    signed_exchanges: list[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    cluster_health: dict[str, Any] | None = None,
    distributed_state: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    model = build_federation_operator_view(
        trust_profile=trust_profile,
        transport_sessions=transport_sessions,
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        diagnostics=diagnostics,
        cluster_health=cluster_health,
        distributed_state=distributed_state,
        generated_at=generated_at,
    )
    model["sections"] = build_federation_dashboard_sections(model)
    return model


def build_federation_dashboard_sections(model: dict[str, Any]) -> list[dict[str, Any]]:
    panels = model.get("panels") if isinstance(model.get("panels"), dict) else {}
    return [
        _section("Trusted Peers", panels.get("trusted_peers")),
        _section("Transport Sessions", panels.get("transport_sessions")),
        _section("Signed Exchanges", panels.get("signed_exchanges")),
        _section("Sync Windows", panels.get("synchronization")),
        _section("Event Propagation", panels.get("event_propagation")),
        _section("Federation Diagnostics", panels.get("diagnostics")),
        _section("Readiness Score", panels.get("readiness")),
        _section("Replay Counters", panels.get("counters")),
    ]


def render_federation_dashboard_sections(model: dict[str, Any]) -> str:
    return "\n".join(
        render_metric_panel(section["title"], section["value"], section["detail"])
        for section in build_federation_dashboard_sections(model)
    )


def federation_dashboard_api_response(model: dict[str, Any]) -> dict[str, Any]:
    api = model.get("api") if isinstance(model.get("api"), dict) else {}
    panels = api.get("panels") if isinstance(api.get("panels"), dict) else model.get("panels", {})
    return {
        "record_type": "federation_dashboard_api_response",
        "status": api.get("status", model.get("status", "ok")),
        "generated_at": model.get("generated_at"),
        "count": api.get("count", 0),
        "items": api.get("items", []),
        "panels": panels,
        "summary": api.get("summary", model.get("summary", {})),
        "empty_state": api.get("empty_state", model.get("empty_state")),
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def build_empty_federation_dashboard_view(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_federation_dashboard_view(generated_at=generated_at)


def _section(title: str, panel: Any) -> dict[str, Any]:
    payload = panel if isinstance(panel, dict) else {}
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    return {
        "title": title,
        "value": _primary_value(title, metrics),
        "detail": str(payload.get("status") or "empty"),
        "panel": str(payload.get("panel") or title.lower().replace(" ", "_")),
        **FEDERATION_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def _primary_value(title: str, metrics: dict[str, Any]) -> int:
    if title == "Readiness Score":
        return int(metrics.get("readiness_score") or 0)
    for key in (
        "approved_peer_count",
        "session_count",
        "envelope_count",
        "accepted_update_count",
        "event_count",
        "check_count",
        "rejected_update_count",
    ):
        if key in metrics:
            return int(metrics.get(key) or 0)
    return sum(int(value or 0) for value in metrics.values() if isinstance(value, int))
