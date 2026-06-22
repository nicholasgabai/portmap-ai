from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.attribution.confidence_models import ATTRIBUTION_SAFETY_FLAGS


LEARNING_PROFILE_RECORD_VERSION = 1
MAX_CONFIDENCE_HISTORY = 24


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


def deterministic_learning_profile_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


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
