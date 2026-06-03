from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.attribution.confidence_models import (
    ATTRIBUTION_SAFETY_FLAGS,
    ATTRIBUTION_STATES,
    build_confidence_breakdown,
    classify_attribution_state,
    score_application_attribution_confidence,
)
from core_engine.attribution.signature_learning import build_behavioral_signature_records


APPLICATION_ATTRIBUTION_RECORD_VERSION = 1
DEMO_ATTRIBUTION_LABELS = {"dummy_app", "dummy_db"}


class ApplicationAttributionError(ValueError):
    """Raised when dynamic application attribution inputs are malformed."""


def build_probable_application_attributions(
    observation: dict[str, Any],
    *,
    signatures: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_candidates: int = 3,
) -> list[dict[str, Any]]:
    if not isinstance(observation, dict):
        raise ApplicationAttributionError("observation must be an object")
    timestamp = generated_at or _now()
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    hints = _extract_hints(observation, source_mode=mode)
    signature_rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    candidates = _candidate_classes(hints, signature_rows, source_mode=mode)
    if not candidates:
        candidates = [("Unknown", "Unattributed", "unresolved_live_attribution")]
    records = [
        build_probable_application_attribution(
            observation,
            candidate_app_class=app_class,
            candidate_service_class=service_class,
            candidate_reason=reason,
            signatures=signature_rows,
            generated_at=timestamp,
        )
        for app_class, service_class, reason in candidates
    ]
    return sorted(records, key=lambda item: (-float(item.get("confidence_score") or 0.0), str(item.get("attribution_id") or "")))[: int(max_candidates)]


def build_probable_application_attribution(
    observation: dict[str, Any],
    *,
    candidate_app_class: str | None = None,
    candidate_service_class: str | None = None,
    candidate_reason: str = "metadata_hint",
    signatures: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise ApplicationAttributionError("observation must be an object")
    timestamp = generated_at or _now()
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    hints = _extract_hints(observation, source_mode=mode)
    signature_rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    conflict_reason = _conflict_reason(hints=hints, source_mode=mode)
    app_class = _safe_candidate(candidate_app_class or _default_app_class(hints, signature_rows), source_mode=mode, fallback="Unknown")
    service_class = _safe_candidate(candidate_service_class or _default_service_class(hints), source_mode=mode, fallback="Unattributed")
    unresolved = app_class == "Unknown" and service_class in {"Unknown", "Unattributed"}
    recurrence_confidence = _signature_recurrence_confidence(signature_rows)
    conflict_penalty = 0.32 if conflict_reason else _candidate_conflict_penalty(app_class=app_class, service_class=service_class, hints=hints)
    confidence = score_application_attribution_confidence(
        process_confidence=_hint_confidence(hints["process_hint"]),
        service_confidence=_hint_confidence(hints["service_hint"]),
        protocol_confidence=_hint_confidence(hints["protocol_hint"]),
        destination_confidence=_hint_confidence(hints["destination_behavior_hint"]),
        flow_confidence=_hint_confidence(hints["flow_behavior_hint"]),
        recurrence_confidence=recurrence_confidence,
        conflict_penalty=conflict_penalty,
    )
    if candidate_reason == "fixture_or_simulated_hint" and mode in {"fixture", "simulated"}:
        confidence = round(min(1.0, confidence + 0.03), 3)
    state = classify_attribution_state(confidence_score=confidence, unresolved=unresolved, conflicting=bool(conflict_reason))
    confidence_breakdown = build_confidence_breakdown(
        process_confidence=_hint_confidence(hints["process_hint"]),
        service_confidence=_hint_confidence(hints["service_hint"]),
        protocol_confidence=_hint_confidence(hints["protocol_hint"]),
        destination_confidence=_hint_confidence(hints["destination_behavior_hint"]),
        flow_confidence=_hint_confidence(hints["flow_behavior_hint"]),
        recurrence_confidence=recurrence_confidence,
        conflict_penalty=conflict_penalty,
    )
    record = {
        "record_type": "probable_application_attribution",
        "record_version": APPLICATION_ATTRIBUTION_RECORD_VERSION,
        "attribution_id": "app-attr-"
        + _digest(
            {
                "observed_entity_reference": _entity_ref(observation),
                "candidate_app_class": app_class,
                "candidate_service_class": service_class,
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "observed_entity_reference": _entity_ref(observation),
        "candidate_app_class": app_class,
        "candidate_service_class": service_class,
        "process_hint": hints["process_hint"],
        "service_hint": hints["service_hint"],
        "protocol_hint": hints["protocol_hint"],
        "destination_behavior_hint": hints["destination_behavior_hint"],
        "flow_behavior_hint": hints["flow_behavior_hint"],
        "source_mode": mode,
        "data_source": mode,
        "attribution_state": state,
        "confidence_score": confidence,
        "confidence_breakdown": confidence_breakdown,
        "evidence_summary": {
            "candidate_reason": _safe_token(candidate_reason),
            "signature_refs": sorted(str(row.get("signature_id") or "") for row in signature_rows if row.get("signature_id")),
            "signature_count": len(signature_rows),
            "conflict_reason": conflict_reason,
        },
        "advisory_notes": _attribution_notes(state=state, source_mode=mode, conflict_reason=conflict_reason),
        **ATTRIBUTION_SAFETY_FLAGS,
    }
    return record


def build_application_attribution_report(
    observations: Iterable[dict[str, Any]],
    *,
    signature_observations: Iterable[dict[str, Any]] | None = None,
    signatures: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_candidates_per_observation: int = 3,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        observation_rows = [dict(row) for row in observations or [] if isinstance(row, dict)]
    except TypeError as exc:
        raise ApplicationAttributionError("observations must be iterable") from exc
    signature_rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    if signature_observations is not None:
        signature_rows.extend(build_behavioral_signature_records(signature_observations, generated_at=timestamp))
    attributions: list[dict[str, Any]] = []
    for row in observation_rows:
        attributions.extend(
            build_probable_application_attributions(
                row,
                signatures=_signatures_for_observation(row, signature_rows),
                generated_at=timestamp,
                max_candidates=max_candidates_per_observation,
            )
        )
    summary = summarize_application_attributions(attributions, generated_at=timestamp)
    return {
        "record_type": "dynamic_application_attribution_report",
        "record_version": APPLICATION_ATTRIBUTION_RECORD_VERSION,
        "report_id": "dynamic-app-attribution-report-"
        + _digest({"generated_at": timestamp, "attributions": [row["attribution_id"] for row in attributions]})[:16],
        "generated_at": timestamp,
        "attributions": attributions,
        "summary": summary,
        "dashboard_status": build_application_attribution_dashboard(summary=summary, attributions=attributions, generated_at=timestamp),
        "api_status": build_application_attribution_api(summary=summary, attributions=attributions, generated_at=timestamp),
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def summarize_application_attributions(
    attributions: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    return {
        "record_type": "dynamic_application_attribution_summary",
        "record_version": APPLICATION_ATTRIBUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "attribution_count": len(rows),
        "attributed_count": _count_state(rows, "attributed"),
        "probable_count": _count_state(rows, "probable"),
        "possible_count": _count_state(rows, "possible"),
        "unattributed_count": _count_state(rows, "unattributed"),
        "conflicting_count": _count_state(rows, "conflicting"),
        "unknown_count": _count_state(rows, "unknown"),
        "average_confidence_score": _average(rows, "confidence_score"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def build_application_attribution_dashboard(
    *,
    summary: dict[str, Any],
    attributions: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("conflicting_count") or 0) else "degraded" if int(summary.get("unattributed_count") or 0) else "ok"
    return {
        "record_type": "dynamic_application_attribution_dashboard",
        "panel": "dynamic_application_attribution",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "attribution_count": int(summary.get("attribution_count") or 0),
            "probable_count": int(summary.get("probable_count") or 0),
            "possible_count": int(summary.get("possible_count") or 0),
            "unattributed_count": int(summary.get("unattributed_count") or 0),
            "average_confidence_score": float(summary.get("average_confidence_score") or 0.0),
        },
        "rows": [
            {
                "attribution_id": row.get("attribution_id"),
                "observed_entity_reference": row.get("observed_entity_reference"),
                "candidate_app_class": row.get("candidate_app_class"),
                "candidate_service_class": row.get("candidate_service_class"),
                "attribution_state": row.get("attribution_state"),
                "confidence_score": row.get("confidence_score"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def build_application_attribution_api(
    *,
    summary: dict[str, Any],
    attributions: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    return {
        "record_type": "dynamic_application_attribution_api",
        "status": "review_required" if int(summary.get("conflicting_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "attributions": rows,
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def deterministic_application_attribution_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def normalize_source_mode(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in {"live", "simulated", "fixture", "replay", "unknown"} else "unknown"


def _candidate_classes(hints: dict[str, str], signatures: list[dict[str, Any]], *, source_mode: str) -> list[tuple[str, str, str]]:
    if _is_unresolved(hints):
        return []
    candidates: list[tuple[str, str, str]] = []
    service = hints["service_hint"].lower()
    protocol = hints["protocol_hint"].lower()
    process = hints["process_hint"].lower()
    destination = hints["destination_behavior_hint"].lower()
    flow = hints["flow_behavior_hint"].lower()
    if normalize_source_mode(source_mode) in {"fixture", "simulated"} and (process in DEMO_ATTRIBUTION_LABELS or service in DEMO_ATTRIBUTION_LABELS):
        candidates.append((_safe_candidate(hints["process_hint"], source_mode=source_mode, fallback="Unknown"), _safe_candidate(hints["service_hint"], source_mode=source_mode, fallback="Unattributed"), "fixture_or_simulated_hint"))
    if any(token in service or token in protocol for token in ("https", "http", "tls")):
        candidates.append(("browser_or_web_client", "web_service", "web_protocol_metadata"))
    if "ssh" in service or "ssh" in protocol or "terminal" in process:
        candidates.append(("remote_access_client", "secure_shell_service", "remote_access_metadata"))
    if any(token in service or token in process for token in ("db", "database", "sql", "postgres")):
        candidates.append(("database_client_or_service", "database_service", "database_metadata"))
    if "resolver" in destination or "dns" in service or "dns" in protocol:
        candidates.append(("name_resolution_client", "dns_service", "destination_behavior_metadata"))
    if "recurring" in flow and signatures:
        candidates.append(("recurring_application_behavior", _default_service_class(hints), "recurring_signature_metadata"))
    if not candidates and normalize_source_mode(source_mode) in {"fixture", "simulated"}:
        candidates.append((_safe_candidate(hints["process_hint"], source_mode=source_mode, fallback="Unknown"), _safe_candidate(hints["service_hint"], source_mode=source_mode, fallback="Unattributed"), "fixture_or_simulated_hint"))
    return _dedupe_candidates(candidates)


def _default_app_class(hints: dict[str, str], signatures: list[dict[str, Any]]) -> str:
    candidates = _candidate_classes(hints, signatures, source_mode="unknown")
    return candidates[0][0] if candidates else "Unknown"


def _default_service_class(hints: dict[str, str]) -> str:
    service = hints.get("service_hint") or "Unattributed"
    if service in {"Unknown", "Unattributed"}:
        protocol = hints.get("protocol_hint") or "unknown"
        return protocol if protocol != "unknown" else "Unattributed"
    return service


def _extract_hints(observation: dict[str, Any], *, source_mode: str) -> dict[str, str]:
    return {
        "process_hint": _safe_candidate(observation.get("process_hint") or observation.get("process_attribution"), source_mode=source_mode, fallback="Unknown"),
        "service_hint": _safe_candidate(observation.get("service_hint") or observation.get("service_attribution"), source_mode=source_mode, fallback="Unattributed"),
        "protocol_hint": _safe_token(observation.get("protocol_hint") or observation.get("protocol") or observation.get("application_protocol")),
        "destination_behavior_hint": _safe_destination_hint(observation),
        "flow_behavior_hint": _safe_token(observation.get("flow_behavior_hint") or observation.get("relationship_state") or observation.get("session_state")),
    }


def _safe_candidate(value: Any, *, source_mode: str, fallback: str) -> str:
    if isinstance(value, dict):
        value = value.get("display_name") or value.get("service_name") or value.get("process_name") or value.get("name") or value.get("value")
    text = str(value or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    if lowered in {"unknown", "none"}:
        return "Unknown"
    if lowered == "unattributed":
        return fallback
    if lowered in DEMO_ATTRIBUTION_LABELS and normalize_source_mode(source_mode) not in {"fixture", "simulated"}:
        return fallback
    return text[:80]


def _safe_destination_hint(observation: dict[str, Any]) -> str:
    if observation.get("domain_hash"):
        return "hashed_destination"
    if observation.get("domain_summary") or observation.get("destination_behavior_hint"):
        return _safe_token(observation.get("destination_behavior_hint") or "redacted_destination")
    return _safe_token(observation.get("destination_class") or "unknown")


def _hint_confidence(value: str) -> float:
    if value in {"", "unknown", "Unknown", "Unattributed", "unattributed"}:
        return 0.0
    if value in {"redacted_destination", "hashed_destination"}:
        return 0.7
    return 0.82


def _signature_recurrence_confidence(signatures: list[dict[str, Any]]) -> float:
    if not signatures:
        return 0.0
    return round(min(1.0, max(float(row.get("confidence_score") or row.get("recurrence_score") or 0.0) for row in signatures)), 3)


def _candidate_conflict_penalty(*, app_class: str, service_class: str, hints: dict[str, str]) -> float:
    service = service_class.lower()
    protocol = hints.get("protocol_hint", "").lower()
    if service not in {"unknown", "unattributed"} and protocol not in {"", "unknown"}:
        if protocol == "udp" and any(token in service for token in ("ssh", "https", "tls")):
            return 0.22
        if protocol == "icmp" and service not in {"icmp", "diagnostic"}:
            return 0.28
    if app_class == "Unknown":
        return 0.08
    return 0.0


def _conflict_reason(*, hints: dict[str, str], source_mode: str) -> str:
    if normalize_source_mode(source_mode) in {"fixture", "simulated"}:
        return ""
    values = {hints["process_hint"].lower(), hints["service_hint"].lower()}
    if values & DEMO_ATTRIBUTION_LABELS:
        return "demo_label_not_allowed_for_live_source"
    return ""


def _is_unresolved(hints: dict[str, str]) -> bool:
    return (
        hints["process_hint"] in {"Unknown", "Unattributed"}
        and hints["service_hint"] in {"Unknown", "Unattributed"}
        and hints["protocol_hint"] == "unknown"
        and hints["destination_behavior_hint"] == "unknown"
        and hints["flow_behavior_hint"] == "unknown"
    )


def _signatures_for_observation(observation: dict[str, Any], signatures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    matching = [row for row in signatures if normalize_source_mode(row.get("source_mode") or row.get("learned_from_source_mode") or "unknown") in {mode, "unknown"}]
    return matching or signatures


def _entity_ref(observation: dict[str, Any]) -> str:
    for field in ("observed_entity_reference", "session_reference", "session_id", "flow_reference", "flow_pair_id", "relationship_reference", "record_id"):
        value = observation.get(field)
        if value not in {None, ""}:
            return str(value)[:96]
    return "entity-" + _digest(_extract_hints(observation, source_mode=normalize_source_mode(observation.get("source_mode") or "unknown")))[:16]


def _attribution_notes(*, state: str, source_mode: str, conflict_reason: str) -> list[str]:
    notes = [
        f"attribution state is {state}",
        f"source mode is {source_mode}",
        "metadata-only dynamic attribution; unresolved live attribution remains Unknown or Unattributed",
    ]
    if conflict_reason:
        notes.append(f"operator review recommended: {conflict_reason}")
    return notes


def _dedupe_candidates(candidates: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    seen: set[tuple[str, str]] = set()
    deduped = []
    for app_class, service_class, reason in candidates:
        key = (app_class, service_class)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((app_class, service_class, reason))
    return deduped


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("attribution_state") == state)


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _safe_token(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return text[:80] if text else "unknown"


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
