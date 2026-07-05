from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.attribution.confidence_models import ATTRIBUTION_SAFETY_FLAGS


LEARNING_PROFILE_RECORD_VERSION = 1
MAX_CONFIDENCE_HISTORY = 24
MAX_OBSERVATION_RECORDS = 100


class LearningProfileError(ValueError):
    """Raised when learning profile inputs are malformed."""


def build_learning_profile(
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise LearningProfileError("observation must be an object")
    timestamp = _profile_timestamp(observation, generated_at=generated_at)
    classification = _profile_name(observation, classification_model)
    confidence = _profile_confidence(observation, classification_model)
    profile = {
        "record_type": "application_learning_profile",
        "record_version": LEARNING_PROFILE_RECORD_VERSION,
        "profile_id": _profile_id(classification),
        "profile_name": classification,
        "first_seen": _safe_time(observation.get("first_seen")) or timestamp,
        "last_seen": _safe_time(observation.get("last_seen")) or timestamp,
        "observation_count": _observation_count(observation),
        "observed_ports": _observed_ports(observation),
        "observed_protocols": _observed_values(observation, ("protocol", "protocol_hint", "transport")),
        "observed_services": _observed_values(observation, ("service_name", "service", "service_hint")),
        "observed_processes": _observed_values(observation, ("program", "process", "process_hint")),
        "confidence_history": [_confidence_history_row(timestamp, classification, confidence)],
        "stability_score": 0.0,
        "metadata_only": True,
        "read_only": True,
        "training_performed": False,
        "model_mutated": False,
        "online_learning_performed": False,
        "automated_action": False,
        **ATTRIBUTION_SAFETY_FLAGS,
    }
    profile["stability_score"] = _stability_score(profile)
    return profile


def update_learning_profile(
    profile: dict[str, Any] | None,
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if profile is None:
        return build_learning_profile(
            observation,
            classification_model=classification_model,
            generated_at=generated_at,
        )
    if not isinstance(profile, dict):
        raise LearningProfileError("profile must be an object")
    current = _normalize_profile(profile)
    incoming = build_learning_profile(
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    current["first_seen"] = _earliest_time(current.get("first_seen"), incoming.get("first_seen"))
    current["last_seen"] = _latest_time(current.get("last_seen"), incoming.get("last_seen"))
    current["observation_count"] = int(current.get("observation_count") or 0) + int(
        incoming.get("observation_count") or 0
    )
    current["observed_ports"] = _merge_sorted(current.get("observed_ports"), incoming.get("observed_ports"), numeric=True)
    current["observed_protocols"] = _merge_sorted(current.get("observed_protocols"), incoming.get("observed_protocols"))
    current["observed_services"] = _merge_sorted(current.get("observed_services"), incoming.get("observed_services"))
    current["observed_processes"] = _merge_sorted(current.get("observed_processes"), incoming.get("observed_processes"))
    current["confidence_history"] = _confidence_history(
        [*list(current.get("confidence_history") or []), *list(incoming.get("confidence_history") or [])]
    )
    current["stability_score"] = _stability_score(current)
    return current


def update_learning_profiles(
    profiles: Iterable[dict[str, Any]] | None,
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    rows = [_normalize_profile(row) for row in profiles or [] if isinstance(row, dict)]
    incoming = build_learning_profile(
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    for index, row in enumerate(rows):
        if row.get("profile_id") == incoming["profile_id"]:
            rows[index] = update_learning_profile(
                row,
                observation,
                classification_model=classification_model,
                generated_at=generated_at,
            )
            break
    else:
        rows.append(incoming)
    return sorted(rows, key=lambda item: (str(item.get("profile_name") or ""), str(item.get("profile_id") or "")))


def save_learning_profiles(path: str | Path, profiles: Iterable[dict[str, Any]]) -> dict[str, Any]:
    target = Path(path)
    payload = {
        "record_type": "application_learning_profile_store",
        "record_version": LEARNING_PROFILE_RECORD_VERSION,
        "profiles": sorted(
            [_normalize_profile(row) for row in profiles or [] if isinstance(row, dict)],
            key=lambda item: str(item.get("profile_id") or ""),
        ),
        "metadata_only": True,
        "read_only": True,
        "external_system": False,
        "cloud_dependency": False,
        **ATTRIBUTION_SAFETY_FLAGS,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))
    return payload


def load_learning_profiles(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []
    try:
        payload = json.loads(source.read_text())
    except Exception as exc:
        raise LearningProfileError(f"could not load learning profiles: {exc}") from exc
    rows = payload.get("profiles") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise LearningProfileError("learning profile store must contain a profile list")
    return [_normalize_profile(row) for row in rows if isinstance(row, dict)]


def update_learning_profile_store(
    path: str | Path,
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    profiles = update_learning_profiles(
        load_learning_profiles(path),
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    save_learning_profiles(path, profiles)
    return profiles


def build_learning_profile_history(
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    profile = build_learning_profile(
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    observed_at = _profile_timestamp(observation, generated_at=generated_at)
    record = _historical_observation_record(
        observation,
        profile=profile,
        classification_model=classification_model,
        observed_at=observed_at,
    )
    history = {
        "record_type": "application_learning_profile_history",
        "record_version": LEARNING_PROFILE_RECORD_VERSION,
        "profile_id": profile["profile_id"],
        "profile_name": profile["profile_name"],
        "first_observed": _safe_time(observation.get("first_seen")) or observed_at,
        "last_observed": _safe_time(observation.get("last_seen")) or observed_at,
        "observation_count": profile["observation_count"],
        "historical_ports": profile["observed_ports"],
        "historical_protocols": profile["observed_protocols"],
        "historical_services": profile["observed_services"],
        "historical_processes": profile["observed_processes"],
        "observation_timestamps": [observed_at],
        "observation_records": [record],
        "historical_summary": {},
        "metadata_only": True,
        "read_only": True,
        "training_performed": False,
        "model_retrained": False,
        "confidence_evolution_performed": False,
        "adaptive_scoring_performed": False,
        "automated_action": False,
        **ATTRIBUTION_SAFETY_FLAGS,
    }
    history["historical_summary"] = summarize_learning_profile_history(history)
    history["stability_score"] = history["historical_summary"]["stability_score"]
    history["stability_label"] = history["historical_summary"]["stability_label"]
    history["drift_score"] = history["historical_summary"]["drift_score"]
    history["drift_label"] = history["historical_summary"]["drift_label"]
    history["confidence_first"] = history["historical_summary"]["confidence_first"]
    history["confidence_latest"] = history["historical_summary"]["confidence_latest"]
    history["confidence_trend"] = history["historical_summary"]["confidence_trend"]
    history["confidence_delta"] = history["historical_summary"]["confidence_delta"]
    history["confidence_average"] = history["historical_summary"]["confidence_average"]
    history["confidence_min"] = history["historical_summary"]["confidence_min"]
    history["confidence_max"] = history["historical_summary"]["confidence_max"]
    history["recommendation_count"] = history["historical_summary"]["recommendation_count"]
    history["primary_recommendation"] = history["historical_summary"]["primary_recommendation"]
    history["recommendation_list"] = history["historical_summary"]["recommendation_list"]
    return history


def append_learning_profile_history(
    history: dict[str, Any] | None,
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if history is None:
        return build_learning_profile_history(
            observation,
            classification_model=classification_model,
            generated_at=generated_at,
        )
    if not isinstance(history, dict):
        raise LearningProfileError("history must be an object")
    current = _normalize_history(history)
    incoming = build_learning_profile_history(
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    current["first_observed"] = _earliest_time(current.get("first_observed"), incoming.get("first_observed"))
    current["last_observed"] = _latest_time(current.get("last_observed"), incoming.get("last_observed"))
    current["observation_count"] = int(current.get("observation_count") or 0) + int(
        incoming.get("observation_count") or 0
    )
    current["historical_ports"] = _merge_sorted(current.get("historical_ports"), incoming.get("historical_ports"), numeric=True)
    current["historical_protocols"] = _merge_sorted(current.get("historical_protocols"), incoming.get("historical_protocols"))
    current["historical_services"] = _merge_sorted(current.get("historical_services"), incoming.get("historical_services"))
    current["historical_processes"] = _merge_sorted(current.get("historical_processes"), incoming.get("historical_processes"))
    current["observation_timestamps"] = _timestamp_history(
        [*list(current.get("observation_timestamps") or []), *list(incoming.get("observation_timestamps") or [])]
    )
    current["observation_records"] = _observation_records(
        [*list(current.get("observation_records") or []), *list(incoming.get("observation_records") or [])]
    )
    current["historical_summary"] = summarize_learning_profile_history(current)
    current["stability_score"] = current["historical_summary"]["stability_score"]
    current["stability_label"] = current["historical_summary"]["stability_label"]
    current["drift_score"] = current["historical_summary"]["drift_score"]
    current["drift_label"] = current["historical_summary"]["drift_label"]
    current["confidence_first"] = current["historical_summary"]["confidence_first"]
    current["confidence_latest"] = current["historical_summary"]["confidence_latest"]
    current["confidence_trend"] = current["historical_summary"]["confidence_trend"]
    current["confidence_delta"] = current["historical_summary"]["confidence_delta"]
    current["confidence_average"] = current["historical_summary"]["confidence_average"]
    current["confidence_min"] = current["historical_summary"]["confidence_min"]
    current["confidence_max"] = current["historical_summary"]["confidence_max"]
    current["recommendation_count"] = current["historical_summary"]["recommendation_count"]
    current["primary_recommendation"] = current["historical_summary"]["primary_recommendation"]
    current["recommendation_list"] = current["historical_summary"]["recommendation_list"]
    return current


def update_learning_profile_histories(
    histories: Iterable[dict[str, Any]] | None,
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    rows = [_normalize_history(row) for row in histories or [] if isinstance(row, dict)]
    incoming = build_learning_profile_history(
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    for index, row in enumerate(rows):
        if row.get("profile_id") == incoming["profile_id"]:
            rows[index] = append_learning_profile_history(
                row,
                observation,
                classification_model=classification_model,
                generated_at=generated_at,
            )
            break
    else:
        rows.append(incoming)
    return sorted(rows, key=lambda item: (str(item.get("profile_name") or ""), str(item.get("profile_id") or "")))


def save_learning_profile_histories(path: str | Path, histories: Iterable[dict[str, Any]]) -> dict[str, Any]:
    target = Path(path)
    payload = {
        "record_type": "application_learning_profile_history_store",
        "record_version": LEARNING_PROFILE_RECORD_VERSION,
        "histories": sorted(
            [_normalize_history(row) for row in histories or [] if isinstance(row, dict)],
            key=lambda item: (str(item.get("profile_name") or ""), str(item.get("profile_id") or "")),
        ),
        "metadata_only": True,
        "read_only": True,
        "external_system": False,
        "cloud_dependency": False,
        **ATTRIBUTION_SAFETY_FLAGS,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))
    return payload


def load_learning_profile_histories(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []
    try:
        payload = json.loads(source.read_text())
    except Exception as exc:
        raise LearningProfileError(f"could not load learning profile history: {exc}") from exc
    rows = payload.get("histories") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise LearningProfileError("learning profile history store must contain a history list")
    return [_normalize_history(row) for row in rows if isinstance(row, dict)]


def update_learning_profile_history_store(
    path: str | Path,
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    histories = update_learning_profile_histories(
        load_learning_profile_histories(path),
        observation,
        classification_model=classification_model,
        generated_at=generated_at,
    )
    save_learning_profile_histories(path, histories)
    return histories


def summarize_learning_profile_history(history: dict[str, Any] | None) -> dict[str, Any]:
    row = _normalize_history(history) if isinstance(history, dict) and history.get("historical_summary") is None else dict(history or {})
    first_observed = _safe_time(row.get("first_observed"))
    last_observed = _safe_time(row.get("last_observed"))
    stability = _history_stability(row)
    drift = _history_drift(row)
    confidence = _confidence_evolution(row)
    recommendations = _history_recommendations(row, stability=stability, drift=drift, confidence=confidence)
    return {
        "profile_id": _safe_label(row.get("profile_id")),
        "profile_name": _safe_label(row.get("profile_name")) or "unknown_application",
        "historical_observations": str(max(0, _safe_int(row.get("observation_count"), default=0))),
        "profile_age": _profile_age(first_observed, last_observed),
        "first_observed": first_observed or "-",
        "last_observed": last_observed or "-",
        "stability_score": stability["stability_score"],
        "stability_label": stability["stability_label"],
        "drift_score": drift["drift_score"],
        "drift_label": drift["drift_label"],
        "confidence_first": confidence["confidence_first"],
        "confidence_latest": confidence["confidence_latest"],
        "confidence_min": confidence["confidence_min"],
        "confidence_max": confidence["confidence_max"],
        "confidence_average": confidence["confidence_average"],
        "confidence_delta": confidence["confidence_delta"],
        "confidence_trend": confidence["confidence_trend"],
        "recommendation_count": str(len(recommendations)),
        "primary_recommendation": recommendations[0]["recommendation_id"] if recommendations else "-",
        "recommendation_list": recommendations,
        "historical_ports": _merge_sorted(row.get("historical_ports"), [], numeric=True),
        "historical_protocols": _merge_sorted(row.get("historical_protocols"), []),
        "historical_services": _merge_sorted(row.get("historical_services"), []),
        "historical_processes": _merge_sorted(row.get("historical_processes"), []),
        "observation_timestamp_count": str(len(_timestamp_history(row.get("observation_timestamps") or []))),
        "metadata_only": True,
        "read_only": True,
    }


def deterministic_learning_profile_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _normalize_history(history: dict[str, Any]) -> dict[str, Any]:
    row = dict(history)
    name = _safe_label(row.get("profile_name")) or "unknown_application"
    row.setdefault("record_type", "application_learning_profile_history")
    row.setdefault("record_version", LEARNING_PROFILE_RECORD_VERSION)
    row.setdefault("profile_name", name)
    row.setdefault("profile_id", _profile_id(name))
    row["first_observed"] = _safe_time(row.get("first_observed")) or _safe_time(row.get("first_seen"))
    row["last_observed"] = _safe_time(row.get("last_observed")) or _safe_time(row.get("last_seen"))
    row["observation_count"] = max(0, _safe_int(row.get("observation_count"), default=0))
    row["historical_ports"] = _merge_sorted(row.get("historical_ports") or row.get("observed_ports"), [], numeric=True)
    row["historical_protocols"] = _merge_sorted(row.get("historical_protocols") or row.get("observed_protocols"), [])
    row["historical_services"] = _merge_sorted(row.get("historical_services") or row.get("observed_services"), [])
    row["historical_processes"] = _merge_sorted(row.get("historical_processes") or row.get("observed_processes"), [])
    row["observation_timestamps"] = _timestamp_history(row.get("observation_timestamps") or [])
    row["observation_records"] = _observation_records(row.get("observation_records") or [])
    row["historical_summary"] = summarize_learning_profile_history({**row, "historical_summary": {}})
    row["stability_score"] = row["historical_summary"]["stability_score"]
    row["stability_label"] = row["historical_summary"]["stability_label"]
    row["drift_score"] = row["historical_summary"]["drift_score"]
    row["drift_label"] = row["historical_summary"]["drift_label"]
    row["confidence_first"] = row["historical_summary"]["confidence_first"]
    row["confidence_latest"] = row["historical_summary"]["confidence_latest"]
    row["confidence_trend"] = row["historical_summary"]["confidence_trend"]
    row["confidence_delta"] = row["historical_summary"]["confidence_delta"]
    row["confidence_average"] = row["historical_summary"]["confidence_average"]
    row["confidence_min"] = row["historical_summary"]["confidence_min"]
    row["confidence_max"] = row["historical_summary"]["confidence_max"]
    row["recommendation_count"] = row["historical_summary"]["recommendation_count"]
    row["primary_recommendation"] = row["historical_summary"]["primary_recommendation"]
    row["recommendation_list"] = row["historical_summary"]["recommendation_list"]
    row.setdefault("metadata_only", True)
    row.setdefault("read_only", True)
    row.setdefault("training_performed", False)
    row.setdefault("model_retrained", False)
    row.setdefault("confidence_evolution_performed", False)
    row.setdefault("adaptive_scoring_performed", False)
    row.setdefault("automated_action", False)
    for key, value in ATTRIBUTION_SAFETY_FLAGS.items():
        row.setdefault(key, value)
    return row


def _historical_observation_record(
    observation: dict[str, Any],
    *,
    profile: dict[str, Any],
    classification_model: dict[str, Any] | None,
    observed_at: str,
) -> dict[str, Any]:
    return {
        "observed_at": observed_at,
        "profile_id": profile["profile_id"],
        "profile_name": profile["profile_name"],
        "observation_id": _identity_field(observation, classification_model, "observation_id"),
        "flow_key": _identity_field(observation, classification_model, "flow_key"),
        "session_id": _identity_field(observation, classification_model, "session_id"),
        "evidence_origin": _identity_field(observation, classification_model, "evidence_origin"),
        "observation_type": _identity_field(observation, classification_model, "observation_type"),
        "identity_scope": _identity_field(observation, classification_model, "identity_scope"),
        "local_address": _identity_field(observation, classification_model, "local_address"),
        "remote_address": _identity_field(observation, classification_model, "remote_address"),
        "observation_count": profile["observation_count"],
        "ports": list(profile.get("observed_ports") or []),
        "protocols": list(profile.get("observed_protocols") or []),
        "services": list(profile.get("observed_services") or []),
        "processes": list(profile.get("observed_processes") or []),
        "fingerprints": _observed_fingerprints(observation),
        "confidence": _profile_confidence(observation, classification_model),
        "evidence_quality": _safe_label(_classification_field(classification_model, "evidence_quality")),
        "ambiguity_reason": _safe_label(_classification_field(classification_model, "ambiguity_reason")),
        "evidence_count": _safe_int(_classification_field(classification_model, "evidence_count"), default=0),
        "candidate_count": _candidate_count(classification_model),
        "alternative_candidate_count": _alternative_candidate_count(classification_model),
        "metadata_only": True,
        "read_only": True,
    }


def _timestamp_history(values: Iterable[Any]) -> list[str]:
    return sorted({timestamp for value in values if (timestamp := _safe_time(value))})


def _observation_records(values: Iterable[Any]) -> list[dict[str, Any]]:
    rows = []
    for value in values:
        if not isinstance(value, dict):
            continue
        row = {
            "observed_at": _safe_time(value.get("observed_at")),
            "profile_id": _safe_label(value.get("profile_id")),
            "profile_name": _safe_label(value.get("profile_name")) or "unknown_application",
            "observation_id": _safe_label(value.get("observation_id")),
            "flow_key": _safe_label(value.get("flow_key")),
            "session_id": _safe_label(value.get("session_id")),
            "evidence_origin": _safe_label(value.get("evidence_origin")),
            "observation_type": _safe_label(value.get("observation_type")),
            "identity_scope": _safe_label(value.get("identity_scope")),
            "local_address": _safe_label(value.get("local_address")),
            "remote_address": _safe_label(value.get("remote_address")),
            "observation_count": max(1, _safe_int(value.get("observation_count"), default=1)),
            "ports": _merge_sorted(value.get("ports"), [], numeric=True),
            "protocols": _merge_sorted(value.get("protocols"), []),
            "services": _merge_sorted(value.get("services"), []),
            "processes": _merge_sorted(value.get("processes"), []),
            "fingerprints": _merge_sorted(value.get("fingerprints"), []),
            "confidence": _bounded_float(value.get("confidence")),
            "evidence_quality": _safe_label(value.get("evidence_quality")),
            "ambiguity_reason": _safe_label(value.get("ambiguity_reason")),
            "evidence_count": max(0, _safe_int(value.get("evidence_count"), default=0)),
            "candidate_count": max(0, _safe_int(value.get("candidate_count"), default=0)),
            "alternative_candidate_count": max(0, _safe_int(value.get("alternative_candidate_count"), default=0)),
            "metadata_only": True,
            "read_only": True,
        }
        rows.append(row)
    rows.sort(key=lambda item: (str(item.get("observed_at") or ""), str(item.get("profile_id") or "")))
    return rows[-MAX_OBSERVATION_RECORDS:]


def _identity_field(
    observation: dict[str, Any],
    classification_model: dict[str, Any] | None,
    field: str,
) -> str:
    value = observation.get(field)
    if value in {None, ""} and isinstance(classification_model, dict):
        context = classification_model.get("observation_context")
        if isinstance(context, dict):
            value = context.get(field)
    return _safe_label(value)


def _normalize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    row = dict(profile)
    name = _safe_label(row.get("profile_name")) or "unknown_application"
    row.setdefault("record_type", "application_learning_profile")
    row.setdefault("record_version", LEARNING_PROFILE_RECORD_VERSION)
    row.setdefault("profile_name", name)
    row.setdefault("profile_id", _profile_id(name))
    row["observation_count"] = max(0, _safe_int(row.get("observation_count"), default=0))
    row["observed_ports"] = _merge_sorted(row.get("observed_ports"), [], numeric=True)
    row["observed_protocols"] = _merge_sorted(row.get("observed_protocols"), [])
    row["observed_services"] = _merge_sorted(row.get("observed_services"), [])
    row["observed_processes"] = _merge_sorted(row.get("observed_processes"), [])
    row["confidence_history"] = _confidence_history(row.get("confidence_history") or [])
    row["stability_score"] = _stability_score(row)
    row.setdefault("metadata_only", True)
    row.setdefault("read_only", True)
    row.setdefault("training_performed", False)
    row.setdefault("model_mutated", False)
    row.setdefault("online_learning_performed", False)
    row.setdefault("automated_action", False)
    for key, value in ATTRIBUTION_SAFETY_FLAGS.items():
        row.setdefault(key, value)
    return row


def _profile_name(observation: dict[str, Any], classification_model: dict[str, Any] | None) -> str:
    if isinstance(classification_model, dict):
        value = classification_model.get("top_classification") or classification_model.get("profile_name")
        if _safe_label(value):
            return _safe_label(value)
    for key in ("top_classification", "service_name", "service", "program", "process"):
        value = _safe_label(observation.get(key))
        if value:
            return value
    return "unknown_application"


def _profile_confidence(observation: dict[str, Any], classification_model: dict[str, Any] | None) -> float:
    if isinstance(classification_model, dict):
        value = classification_model.get("confidence")
        if value not in {"", "-", None}:
            return _bounded_float(value)
    for key in ("classification_confidence", "confidence", "risk_score", "score"):
        value = observation.get(key)
        if value not in {"", "-", None}:
            return _bounded_float(value)
    return 0.0


def _classification_field(classification_model: dict[str, Any] | None, field: str) -> Any:
    if not isinstance(classification_model, dict):
        return ""
    return classification_model.get(field)


def _candidate_count(classification_model: dict[str, Any] | None) -> int:
    if not isinstance(classification_model, dict):
        return 0
    candidates = classification_model.get("candidates")
    if isinstance(candidates, list):
        return len(candidates)
    return max(0, _safe_int(classification_model.get("candidate_count"), default=0))


def _alternative_candidate_count(classification_model: dict[str, Any] | None) -> int:
    if not isinstance(classification_model, dict):
        return 0
    alternatives = classification_model.get("alternative_candidates")
    if isinstance(alternatives, list):
        return len(alternatives)
    return max(0, _safe_int(classification_model.get("alternative_candidate_count"), default=0))


def _profile_timestamp(observation: dict[str, Any], *, generated_at: str | None) -> str:
    return (
        _safe_time(generated_at)
        or _safe_time(observation.get("last_seen"))
        or _safe_time(observation.get("timestamp"))
        or _safe_time(observation.get("generated_at"))
        or datetime.now(UTC).isoformat()
    )


def _safe_time(value: Any) -> str:
    text = str(value or "").strip()
    return text if text and text != "-" else ""


def _earliest_time(left: Any, right: Any) -> str:
    values = [value for value in (_safe_time(left), _safe_time(right)) if value]
    return min(values) if values else ""


def _latest_time(left: Any, right: Any) -> str:
    values = [value for value in (_safe_time(left), _safe_time(right)) if value]
    return max(values) if values else ""


def _profile_age(first_observed: Any, last_observed: Any) -> str:
    first = _parse_time(first_observed)
    last = _parse_time(last_observed)
    if first is None or last is None:
        return "-"
    seconds = max(0, int((last - first).total_seconds()))
    days = seconds // 86_400
    if days:
        return f"{days}d"
    hours = seconds // 3_600
    if hours:
        return f"{hours}h"
    minutes = seconds // 60
    if minutes:
        return f"{minutes}m"
    return "0m"


def _history_stability(history: dict[str, Any]) -> dict[str, Any]:
    records = [row for row in history.get("observation_records") or [] if isinstance(row, dict)]
    observation_count = max(_safe_int(history.get("observation_count"), default=0), len(records))
    observation_factor = min(1.0, observation_count / 8.0)
    corroboration_factor = min(1.0, observation_count / 3.0)
    classification_consistency = _classification_consistency(records)
    confidence_consistency = _confidence_consistency(records)
    age_factor = _age_factor(history.get("first_observed"), history.get("last_observed"))
    score = round(
        min(
            1.0,
            max(
                0.0,
                (observation_factor * 0.35)
                + (classification_consistency * corroboration_factor * 0.25)
                + (confidence_consistency * corroboration_factor * 0.25)
                + (age_factor * 0.15),
            ),
        ),
        2,
    )
    return {
        "stability_score": score,
        "stability_label": _stability_label(score),
        "stability_factors": {
            "observation_count": observation_count,
            "classification_consistency": round(classification_consistency, 3),
            "confidence_consistency": round(confidence_consistency, 3),
            "profile_age_factor": round(age_factor, 3),
        },
    }


def _history_drift(history: dict[str, Any]) -> dict[str, Any]:
    records = [row for row in history.get("observation_records") or [] if isinstance(row, dict)]
    classification_drift = 1.0 - _classification_consistency(records) if len(records) > 1 else 0.0
    confidence_drift = _confidence_drift(records)
    metadata_drift = _metadata_drift(records)
    score = round(
        min(
            1.0,
            max(
                0.0,
                (classification_drift * 0.40)
                + (confidence_drift * 0.30)
                + (metadata_drift * 0.30),
            ),
        ),
        2,
    )
    return {
        "drift_score": score,
        "drift_label": _drift_label(score),
        "drift_factors": {
            "classification_drift": round(classification_drift, 3),
            "confidence_drift": round(confidence_drift, 3),
            "metadata_drift": round(metadata_drift, 3),
        },
    }


def _confidence_evolution(history: dict[str, Any]) -> dict[str, Any]:
    records = [row for row in history.get("observation_records") or [] if isinstance(row, dict)]
    values = [_bounded_float(record.get("confidence")) for record in records]
    if not values:
        return {
            "confidence_first": 0.0,
            "confidence_latest": 0.0,
            "confidence_min": 0.0,
            "confidence_max": 0.0,
            "confidence_average": 0.0,
            "confidence_delta": 0.0,
            "confidence_trend": "stable",
        }
    first = values[0]
    latest = values[-1]
    minimum = min(values)
    maximum = max(values)
    average = sum(values) / len(values)
    delta = latest - first
    return {
        "confidence_first": round(first, 3),
        "confidence_latest": round(latest, 3),
        "confidence_min": round(minimum, 3),
        "confidence_max": round(maximum, 3),
        "confidence_average": round(average, 3),
        "confidence_delta": round(delta, 3),
        "confidence_trend": _confidence_trend(values),
    }


def _confidence_trend(values: list[float]) -> str:
    if len(values) <= 1:
        return "stable"
    confidence_range = max(values) - min(values)
    delta = values[-1] - values[0]
    monotonic_up = all(right >= left for left, right in zip(values, values[1:]))
    monotonic_down = all(right <= left for left, right in zip(values, values[1:]))
    if monotonic_up and delta >= 0.12:
        return "improving"
    if monotonic_down and delta <= -0.12:
        return "declining"
    if confidence_range <= 0.10 and abs(delta) <= 0.08:
        return "stable"
    if confidence_range >= 0.20:
        return "volatile"
    if delta >= 0.12:
        return "improving"
    if delta <= -0.12:
        return "declining"
    return "stable"


def _history_recommendations(
    history: dict[str, Any],
    *,
    stability: dict[str, Any],
    drift: dict[str, Any],
    confidence: dict[str, Any],
) -> list[dict[str, Any]]:
    records = [row for row in history.get("observation_records") or [] if isinstance(row, dict)]
    observation_count = max(_safe_int(history.get("observation_count"), default=0), len(records))
    stability_score = _bounded_float(stability.get("stability_score"))
    stability_label = _safe_label(stability.get("stability_label")) or _stability_label(stability_score)
    drift_score = _bounded_float(drift.get("drift_score"))
    drift_label = _safe_label(drift.get("drift_label")) or _drift_label(drift_score)
    drift_factors = drift.get("drift_factors") if isinstance(drift.get("drift_factors"), dict) else {}
    confidence_drift = _bounded_float(drift_factors.get("confidence_drift"))
    metadata_drift = _bounded_float(drift_factors.get("metadata_drift"))
    latest_confidence = _latest_confidence(records)
    average_confidence = _average_confidence(records)
    confidence_trend = _safe_label(confidence.get("confidence_trend")) or "stable"
    confidence_delta = _bounded_delta(confidence.get("confidence_delta"))
    evidence_quality = _latest_evidence_quality(records)
    ambiguous = _has_ambiguity(records)
    recommendations: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(recommendation_id: str, reason: str, supporting_factors: list[str]) -> None:
        if recommendation_id in seen:
            return
        seen.add(recommendation_id)
        recommendations.append(
            {
                "recommendation_id": recommendation_id,
                "reason": reason,
                "supporting_factors": [factor for factor in supporting_factors if factor],
                "read_only": True,
                "automated_action": False,
            }
        )

    if drift_label in {"moderate", "high"} or drift_score >= 0.35:
        add(
            "review_profile_drift",
            "Profile history shows classification or metadata drift that should be reviewed.",
            [f"drift_label:{drift_label}", f"drift_score:{drift_score:.2f}"],
        )
    if confidence_drift >= 0.35 or confidence_trend in {"declining", "volatile"}:
        add(
            "investigate_confidence_change",
            "Attribution confidence has changed enough to warrant operator review.",
            [
                f"confidence_trend:{confidence_trend}",
                f"confidence_delta:{confidence_delta:.2f}",
                f"confidence_drift:{confidence_drift:.2f}",
                f"latest_confidence:{latest_confidence:.2f}",
            ],
        )
    if metadata_drift >= 0.20 and drift_label != "none":
        add(
            "monitor_behavior_change",
            "Observed ports, protocols, services, or fingerprints changed across profile history.",
            [f"metadata_drift:{metadata_drift:.2f}", f"drift_label:{drift_label}"],
        )
    if stability_label in {"stable", "highly_stable"} and drift_label in {"none", "low"} and latest_confidence >= 0.50:
        add(
            "classification_stable",
            "Repeated observations support the current classification.",
            [f"stability_label:{stability_label}", f"stability_score:{stability_score:.2f}", f"drift_label:{drift_label}"],
        )
    if latest_confidence < 0.50 or average_confidence < 0.50:
        add(
            "verify_service_identity",
            "Attribution confidence is low, so the service identity should be verified.",
            [f"latest_confidence:{latest_confidence:.2f}", f"average_confidence:{average_confidence:.2f}"],
        )
    if ambiguous:
        add(
            "verify_service_identity",
            "Alternative classifications remain plausible for this profile.",
            [f"candidate_count:{_max_candidate_count(records)}", f"evidence_quality:{evidence_quality or 'unknown'}"],
        )
    if observation_count < 3 or stability_label in {"unstable", "developing"} or evidence_quality in {"insufficient", "weak", "generic"}:
        add(
            "gather_more_metadata",
            "More metadata would improve profile confidence and stability.",
            [f"observation_count:{observation_count}", f"stability_label:{stability_label}", f"evidence_quality:{evidence_quality or 'unknown'}"],
        )
    if not recommendations or stability_label in {"stable", "highly_stable"}:
        add(
            "continue_observation",
            "Continue read-only observation to maintain profile history.",
            [
                f"observation_count:{observation_count}",
                f"profile_age:{_profile_age(history.get('first_observed'), history.get('last_observed'))}",
                f"confidence_trend:{confidence_trend}",
            ],
        )
    return recommendations


def _classification_consistency(records: list[dict[str, Any]]) -> float:
    if not records:
        return 0.0
    counts: dict[str, int] = {}
    for record in records:
        label = _safe_label(record.get("profile_name")) or "unknown_application"
        counts[label] = counts.get(label, 0) + max(1, _safe_int(record.get("observation_count"), default=1))
    total = sum(counts.values())
    return max(counts.values()) / total if total else 0.0


def _confidence_consistency(records: list[dict[str, Any]]) -> float:
    values = [_bounded_float(record.get("confidence")) for record in records]
    if not values:
        return 0.0
    if len(values) == 1:
        return 1.0
    return max(0.0, 1.0 - (max(values) - min(values)))


def _confidence_drift(records: list[dict[str, Any]]) -> float:
    values = [_bounded_float(record.get("confidence")) for record in records]
    if len(values) <= 1:
        return 0.0
    return max(0.0, min(1.0, max(values) - min(values)))


def _latest_confidence(records: list[dict[str, Any]]) -> float:
    if not records:
        return 0.0
    return _bounded_float(records[-1].get("confidence"))


def _average_confidence(records: list[dict[str, Any]]) -> float:
    values = [_bounded_float(record.get("confidence")) for record in records]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 3)


def _latest_evidence_quality(records: list[dict[str, Any]]) -> str:
    for record in reversed(records):
        value = _safe_label(record.get("evidence_quality"))
        if value:
            return value
    return ""


def _has_ambiguity(records: list[dict[str, Any]]) -> bool:
    return any(
        _safe_int(record.get("candidate_count"), default=0) > 1
        or _safe_int(record.get("alternative_candidate_count"), default=0) > 0
        or bool(_safe_label(record.get("ambiguity_reason")))
        for record in records
    )


def _max_candidate_count(records: list[dict[str, Any]]) -> int:
    return max((_safe_int(record.get("candidate_count"), default=0) for record in records), default=0)


def _metadata_drift(records: list[dict[str, Any]]) -> float:
    if len(records) <= 1:
        return 0.0
    denominator = max(len(records) - 1, 1)
    dimensions = (
        ("ports", 0.25),
        ("protocols", 0.20),
        ("services", 0.30),
        ("fingerprints", 0.25),
    )
    score = 0.0
    for key, weight in dimensions:
        values: set[str] = set()
        for record in records:
            raw = record.get(key)
            if isinstance(raw, list):
                values.update(str(item) for item in raw if str(item or "").strip())
        dimension_drift = min(1.0, max(0, len(values) - 1) / denominator)
        score += dimension_drift * weight
    return min(1.0, score)


def _age_factor(first_observed: Any, last_observed: Any) -> float:
    first = _parse_time(first_observed)
    last = _parse_time(last_observed)
    if first is None or last is None:
        return 0.0
    seconds = max(0, int((last - first).total_seconds()))
    if seconds >= 30 * 86_400:
        return 1.0
    if seconds >= 7 * 86_400:
        return 0.85
    if seconds >= 86_400:
        return 0.65
    if seconds >= 3_600:
        return 0.45
    if seconds >= 600:
        return 0.25
    if seconds > 0:
        return 0.15
    return 0.0


def _stability_label(score: float) -> str:
    if score >= 0.80:
        return "highly_stable"
    if score >= 0.60:
        return "stable"
    if score >= 0.35:
        return "developing"
    return "unstable"


def _drift_label(score: float) -> str:
    if score >= 0.65:
        return "high"
    if score >= 0.35:
        return "moderate"
    if score >= 0.10:
        return "low"
    return "none"


def _parse_time(value: Any) -> datetime | None:
    text = _safe_time(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _observation_count(observation: dict[str, Any]) -> int:
    for key in ("observation_count", "occurrence_count", "event_count", "seen_count", "count"):
        value = observation.get(key)
        if value not in {"", "-", None}:
            return max(1, _safe_int(value, default=1))
    return 1


def _observed_ports(observation: dict[str, Any]) -> list[int]:
    ports: list[int] = []
    for key in ("port", "service_port", "dst_port", "destination_port", "local_port"):
        value = observation.get(key)
        if value in {"", "-", None}:
            continue
        ports.append(_safe_int(value, default=-1))
    return sorted({port for port in ports if port >= 0})


def _observed_values(observation: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = observation.get(key)
        if isinstance(value, (list, tuple, set)):
            values.extend(_safe_label(item) for item in value)
        else:
            values.append(_safe_label(value))
    return sorted({value for value in values if value})


def _observed_fingerprints(observation: dict[str, Any]) -> list[str]:
    return _observed_values(
        observation,
        (
            "fingerprint",
            "service_fingerprint",
            "visibility_fingerprint",
            "application_fingerprint",
        ),
    )


def _confidence_history_row(timestamp: str, classification: str, confidence: float) -> dict[str, Any]:
    return {
        "observed_at": timestamp,
        "classification": classification,
        "confidence": round(_bounded_float(confidence), 3),
    }


def _confidence_history(rows: Iterable[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        normalized.append(
            _confidence_history_row(
                _safe_time(item.get("observed_at")) or _safe_time(item.get("timestamp")) or "",
                _safe_label(item.get("classification")) or "unknown_application",
                item.get("confidence"),
            )
        )
    normalized.sort(key=lambda item: (str(item.get("observed_at") or ""), str(item.get("classification") or "")))
    return normalized[-MAX_CONFIDENCE_HISTORY:]


def _stability_score(profile: dict[str, Any]) -> float:
    history = [float(row.get("confidence") or 0.0) for row in profile.get("confidence_history") or [] if isinstance(row, dict)]
    if not history:
        return 0.0
    average = sum(history) / len(history)
    spread = max(history) - min(history)
    consistency = max(0.0, 1.0 - spread)
    count = max(0, _safe_int(profile.get("observation_count"), default=len(history)))
    recurrence = min(1.0, count / 5.0)
    return round(min(1.0, max(0.0, average * 0.65 + consistency * 0.20 + recurrence * 0.15)), 3)


def _merge_sorted(left: Any, right: Any, *, numeric: bool = False) -> list[Any]:
    values: set[Any] = set()
    for source in (left, right):
        if isinstance(source, (list, tuple, set)):
            iterable = source
        elif source in {"", "-", None}:
            iterable = []
        else:
            iterable = [source]
        for value in iterable:
            if numeric:
                number = _safe_int(value, default=-1)
                if number >= 0:
                    values.add(number)
            else:
                text = _safe_label(value)
                if text:
                    values.add(text)
    return sorted(values)


def _profile_id(profile_name: str) -> str:
    return "learning-profile-" + sha256(profile_name.encode("utf-8")).hexdigest()[:16]


def _safe_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text or text == "-":
        return ""
    return text[:80]


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bounded_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(min(1.0, max(0.0, number)), 3)


def _bounded_delta(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(min(1.0, max(-1.0, number)), 3)
