from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.history.aging_policies import (
    AGING_POLICY_SAFETY_FLAGS,
    build_aging_policy_record,
)
from core_engine.history.snapshots import HISTORICAL_SNAPSHOT_SAFETY_FLAGS


BASELINE_DECAY_RECORD_VERSION = 1

BASELINE_DECAY_SAFETY_FLAGS = {
    **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    **AGING_POLICY_SAFETY_FLAGS,
    "baseline_decay_only": True,
    "metadata_only": True,
    "bounded_retention": True,
    "dry_run_safe": True,
    "advisory_only": True,
    "raw_payload_stored": False,
    "credentials_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


def build_baseline_aging_decay_report(
    *,
    baseline_entries: Iterable[dict[str, Any]] | None = None,
    service_fingerprint_profiles: Iterable[dict[str, Any]] | None = None,
    destination_profiles: Iterable[dict[str, Any]] | None = None,
    historical_snapshots: Iterable[dict[str, Any]] | None = None,
    aging_policy: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    policy = dict(aging_policy or build_aging_policy_record(generated_at=timestamp))
    records: list[dict[str, Any]] = []
    records.extend(build_baseline_decay_records(baseline_entries or [], policy=policy, generated_at=timestamp))
    records.extend(build_stale_fingerprint_records(service_fingerprint_profiles or [], policy=policy, generated_at=timestamp))
    records.extend(build_dormant_destination_records(destination_profiles or [], policy=policy, generated_at=timestamp))
    malformed = [row for row in records if row.get("state") == "malformed"]
    explanations = build_decay_explanation_records(records, generated_at=timestamp)
    summary = summarize_baseline_decay_records(
        records,
        policy=policy,
        historical_snapshots=historical_snapshots,
        generated_at=timestamp,
    )
    dashboard = build_decay_dashboard_record(summary=summary, records=records, generated_at=timestamp)
    export = build_decay_export_summary(summary=summary, records=records, generated_at=timestamp)
    return {
        "record_type": "baseline_aging_decay_report",
        "record_version": BASELINE_DECAY_RECORD_VERSION,
        "report_id": "baseline-aging-decay-" + _digest({"generated_at": timestamp, "records": [row.get("decay_id") for row in records]})[:16],
        "generated_at": timestamp,
        "aging_policy": policy,
        "records": sorted(records, key=lambda item: (str(item.get("record_kind") or ""), str(item.get("source_id") or ""))),
        "malformed_records": malformed,
        "summary": summary,
        "explanations": explanations,
        "dashboard_status": dashboard,
        "api_status": build_decay_api_response(summary=summary, records=records, explanations=explanations, dashboard=dashboard, export=export, generated_at=timestamp),
        "export_summary": export,
        **BASELINE_DECAY_SAFETY_FLAGS,
    }


def build_baseline_decay_records(
    baseline_entries: Iterable[dict[str, Any]],
    *,
    policy: dict[str, Any],
    generated_at: str,
) -> list[dict[str, Any]]:
    return [_build_decay_record(row, policy=policy, generated_at=generated_at, record_kind="baseline_entry") for row in _rows_or_malformed(baseline_entries)]


def build_stale_fingerprint_records(
    service_fingerprint_profiles: Iterable[dict[str, Any]],
    *,
    policy: dict[str, Any],
    generated_at: str,
) -> list[dict[str, Any]]:
    return [_build_decay_record(row, policy=policy, generated_at=generated_at, record_kind="service_fingerprint") for row in _rows_or_malformed(service_fingerprint_profiles)]


def build_dormant_destination_records(
    destination_profiles: Iterable[dict[str, Any]],
    *,
    policy: dict[str, Any],
    generated_at: str,
) -> list[dict[str, Any]]:
    return [_build_decay_record(row, policy=policy, generated_at=generated_at, record_kind="destination_behavior") for row in _rows_or_malformed(destination_profiles)]


def score_baseline_maturity(record: dict[str, Any], *, policy: dict[str, Any], generated_at: str) -> float:
    observations = _observation_count(record)
    age_days = _days_between(str(record.get("first_seen") or record.get("generated_at") or generated_at), generated_at)
    observation_score = min(0.55, observations / max(1, int(policy.get("mature_after_observations") or 1)) * 0.55)
    age_score = min(0.35, age_days / max(1, int(policy.get("mature_after_days") or 1)) * 0.35)
    stability_bonus = 0.1 if record.get("stable_behavior") or record.get("stable_service_profile") or str(record.get("behavior_state")) in {"stable", "stable_destination_behavior"} else 0.0
    return round(min(1.0, observation_score + age_score + stability_bonus), 3)


def apply_confidence_decay(
    confidence: float,
    *,
    age_days: int,
    policy: dict[str, Any],
    dormant: bool = False,
) -> float:
    value = max(0.0, min(1.0, float(confidence)))
    if dormant or age_days >= int(policy.get("dormant_after_days") or 0):
        multiplier = float(policy.get("decay_rate") or 0.5) * 0.5
    elif age_days >= int(policy.get("stale_after_days") or 0):
        multiplier = float(policy.get("decay_rate") or 0.5)
    elif age_days >= int(policy.get("inactive_after_days") or 0):
        multiplier = 1.0 - ((1.0 - float(policy.get("decay_rate") or 0.5)) * 0.5)
    else:
        multiplier = 1.0
    return round(max(float(policy.get("minimum_confidence") or 0.0), value * multiplier), 3)


def summarize_baseline_decay_records(
    records: Iterable[dict[str, Any]],
    *,
    policy: dict[str, Any],
    historical_snapshots: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(records)
    valid = [row for row in rows if row.get("state") != "malformed"]
    snapshot_rows = _rows(historical_snapshots)
    return {
        "record_type": "baseline_aging_decay_summary",
        "record_version": BASELINE_DECAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "policy_id": str(policy.get("policy_id") or ""),
        "record_count": len(rows),
        "valid_record_count": len(valid),
        "malformed_record_count": len(rows) - len(valid),
        "inactive_count": sum(1 for row in valid if row.get("inactive_behavior")),
        "stale_count": sum(1 for row in valid if row.get("stale_behavior")),
        "dormant_count": sum(1 for row in valid if row.get("dormant_behavior")),
        "mature_count": sum(1 for row in valid if row.get("long_term_mature")),
        "average_original_confidence": _average(valid, "original_confidence"),
        "average_decayed_confidence": _average(valid, "decayed_confidence"),
        "snapshot_context_count": len(snapshot_rows),
        "snapshot_context_digests": sorted(str(row.get("snapshot_digest") or "") for row in snapshot_rows if row.get("snapshot_digest")),
        "by_record_kind": _count_by(valid, "record_kind"),
        "by_decay_state": _count_by(valid, "decay_state"),
        **BASELINE_DECAY_SAFETY_FLAGS,
    }


def build_decay_explanation_records(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    explanations = []
    for row in _rows(records):
        state = str(row.get("decay_state") or row.get("state") or "unknown")
        explanation = {
            "record_type": "baseline_decay_explanation",
            "record_version": BASELINE_DECAY_RECORD_VERSION,
            "generated_at": timestamp,
            "source_id": str(row.get("source_id") or ""),
            "record_kind": str(row.get("record_kind") or "unknown"),
            "decay_state": state,
            "what_changed": _change_text(row),
            "why_it_matters": "Stale or dormant metadata should carry lower confidence until it is observed again.",
            "operator_action": "review_if_reappears" if row.get("dormant_behavior") else "continue_monitoring",
            "why_no_enforcement": "Aging and decay are advisory-only metadata summaries and do not trigger blocking, firewall, service, or packet changes.",
            "confidence": float(row.get("decayed_confidence") or 0.0),
            **BASELINE_DECAY_SAFETY_FLAGS,
        }
        explanation["explanation_id"] = "baseline-decay-explanation-" + _digest({"source_id": explanation["source_id"], "state": state})[:16]
        explanations.append(explanation)
    return explanations


def build_decay_dashboard_record(
    *,
    summary: dict[str, Any],
    records: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(records)
    status = "degraded" if int(summary.get("malformed_record_count") or 0) else "review" if int(summary.get("stale_count") or 0) or int(summary.get("dormant_count") or 0) else "supported"
    return {
        "record_type": "baseline_aging_decay_dashboard",
        "record_version": BASELINE_DECAY_RECORD_VERSION,
        "panel": "baseline_aging_decay",
        "generated_at": generated_at or _now(),
        "status": status,
        "metrics": {
            "record_count": int(summary.get("record_count") or 0),
            "inactive_count": int(summary.get("inactive_count") or 0),
            "stale_count": int(summary.get("stale_count") or 0),
            "dormant_count": int(summary.get("dormant_count") or 0),
            "mature_count": int(summary.get("mature_count") or 0),
            "average_decayed_confidence": float(summary.get("average_decayed_confidence") or 0.0),
        },
        "rows": [
            {
                "source_id": row.get("source_id"),
                "record_kind": row.get("record_kind"),
                "decay_state": row.get("decay_state"),
                "age_days": row.get("age_days"),
                "decayed_confidence": row.get("decayed_confidence"),
                "long_term_mature": row.get("long_term_mature"),
            }
            for row in sorted(rows, key=lambda item: (str(item.get("record_kind") or ""), str(item.get("source_id") or "")))[:50]
        ],
        "recommended_review": int(summary.get("stale_count") or 0) > 0 or int(summary.get("dormant_count") or 0) > 0,
        **BASELINE_DECAY_SAFETY_FLAGS,
    }


def build_decay_export_summary(
    *,
    summary: dict[str, Any],
    records: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(records)
    payload = {
        "record_type": "baseline_aging_decay_export_summary",
        "record_version": BASELINE_DECAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "decay_records": len(rows),
            "inactive": int(summary.get("inactive_count") or 0),
            "stale": int(summary.get("stale_count") or 0),
            "dormant": int(summary.get("dormant_count") or 0),
            "mature": int(summary.get("mature_count") or 0),
            "malformed": int(summary.get("malformed_record_count") or 0),
        },
        "decay_record_ids": [str(row.get("decay_id") or "") for row in rows],
        "digest": "",
        **BASELINE_DECAY_SAFETY_FLAGS,
    }
    payload["digest"] = digest_payload({"record_counts": payload["record_counts"], "decay_record_ids": payload["decay_record_ids"]})
    return payload


def build_decay_api_response(
    *,
    summary: dict[str, Any],
    records: Iterable[dict[str, Any]],
    explanations: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    export: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "baseline_aging_decay_api",
        "record_version": BASELINE_DECAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "records": _rows(records),
        "explanations": _rows(explanations),
        "dashboard": dict(dashboard),
        "export_summary": dict(export),
        **BASELINE_DECAY_SAFETY_FLAGS,
    }


def deterministic_baseline_decay_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _build_decay_record(row: dict[str, Any], *, policy: dict[str, Any], generated_at: str, record_kind: str) -> dict[str, Any]:
    if not isinstance(row, dict) or not row.get("record_type"):
        malformed = {
            "record_type": "baseline_decay_record",
            "record_version": BASELINE_DECAY_RECORD_VERSION,
            "generated_at": generated_at,
            "record_kind": record_kind,
            "source_id": "",
            "state": "malformed",
            "decay_state": "malformed",
            "errors": ["input record must be an object with record_type"],
            "original_record_digest": digest_payload(row if isinstance(row, dict) else {}),
            "raw_record_stored": False,
            **BASELINE_DECAY_SAFETY_FLAGS,
        }
        malformed["decay_id"] = "baseline-decay-" + _digest({"kind": record_kind, "error": malformed["original_record_digest"]})[:16]
        return malformed
    domain_summary = row.get("domain_summary") if isinstance(row.get("domain_summary"), dict) else {}
    source_id = _source_id(row, record_kind=record_kind)
    age_days = _days_between(str(row.get("last_seen") or row.get("generated_at") or generated_at), generated_at)
    original_confidence = _confidence(row)
    dormant = _is_dormant(row, age_days=age_days, policy=policy)
    inactive = age_days >= int(policy.get("inactive_after_days") or 0) or bool(row.get("decaying_inactive"))
    stale = age_days >= int(policy.get("stale_after_days") or 0) or bool(row.get("low_confidence_warning"))
    decayed = apply_confidence_decay(original_confidence, age_days=age_days, policy=policy, dormant=dormant)
    maturity = score_baseline_maturity(row, policy=policy, generated_at=generated_at)
    decay_state = _decay_state(inactive=inactive, stale=stale, dormant=dormant, malformed=False)
    record = {
        "record_type": "baseline_decay_record",
        "record_version": BASELINE_DECAY_RECORD_VERSION,
        "generated_at": generated_at,
        "record_kind": record_kind,
        "source_id": source_id,
        "source_record_type": str(row.get("record_type") or ""),
        "display_label": str(row.get("display_label") or domain_summary.get("display_domain") or row.get("baseline_key") or source_id),
        "first_seen": str(row.get("first_seen") or ""),
        "last_seen": str(row.get("last_seen") or ""),
        "age_days": int(age_days),
        "observation_count": _observation_count(row),
        "original_confidence": original_confidence,
        "decayed_confidence": decayed,
        "confidence_delta": round(decayed - original_confidence, 3),
        "inactive_behavior": bool(inactive),
        "stale_behavior": bool(stale),
        "dormant_behavior": bool(dormant),
        "long_term_maturity_score": maturity,
        "long_term_mature": maturity >= 0.75,
        "decay_state": decay_state,
        "source_refs": sorted(str(ref) for ref in row.get("source_refs") or [] if ref),
        "policy_id": str(policy.get("policy_id") or ""),
        **BASELINE_DECAY_SAFETY_FLAGS,
    }
    record["decay_id"] = "baseline-decay-" + _digest({"record_kind": record_kind, "source_id": source_id, "policy": record["policy_id"]})[:16]
    return record


def _source_id(row: dict[str, Any], *, record_kind: str) -> str:
    keys = {
        "baseline_entry": ("baseline_id", "baseline_key"),
        "service_fingerprint": ("profile_id", "fingerprint_key"),
        "destination_behavior": ("profile_id", "destination_key", "destination_record_id"),
    }
    for key in keys.get(record_kind, ("id",)):
        if row.get(key):
            return str(row.get(key))
    return f"{record_kind}-" + _digest(row)[:16]


def _confidence(row: dict[str, Any]) -> float:
    for key in ("confidence", "baseline_confidence"):
        if row.get(key) is not None:
            return round(max(0.0, min(1.0, float(row.get(key) or 0.0))), 3)
    return 0.0


def _observation_count(row: dict[str, Any]) -> int:
    for key in ("observation_count", "recurrence_count", "destination_frequency"):
        if row.get(key) is not None:
            return int(row.get(key) or 0)
    recurrence = row.get("recurrence_timing") if isinstance(row.get("recurrence_timing"), dict) else {}
    return int(recurrence.get("observation_count") or 0)


def _is_dormant(row: dict[str, Any], *, age_days: int, policy: dict[str, Any]) -> bool:
    return bool(
        row.get("dormant")
        or row.get("dormant_behavior")
        or row.get("dormant_reappeared")
        or str(row.get("behavior_state") or "") in {"dormant", "dormant_destination_returned"}
        or age_days >= int(policy.get("dormant_after_days") or 0)
    )


def _decay_state(*, inactive: bool, stale: bool, dormant: bool, malformed: bool) -> str:
    if malformed:
        return "malformed"
    if dormant:
        return "dormant"
    if stale:
        return "stale"
    if inactive:
        return "inactive"
    return "current"


def _change_text(row: dict[str, Any]) -> str:
    if row.get("state") == "malformed":
        return "Malformed metadata was isolated and excluded from confidence decay."
    return (
        f"{row.get('record_kind')} {row.get('source_id')} is {row.get('decay_state')} "
        f"with confidence {row.get('original_confidence')} -> {row.get('decayed_confidence')}."
    )


def _rows_or_malformed(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(value) if isinstance(value, dict) else {} for value in values or []]


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(value) for value in values or [] if isinstance(value, dict)]


def _average(rows: list[dict[str, Any]], key: str) -> float:
    values = [float(row.get(key) or 0.0) for row in rows]
    return round(sum(values) / len(values), 3) if values else 0.0


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _days_between(start: str, end: str) -> int:
    start_dt = _parse_time(start)
    end_dt = _parse_time(end)
    if not start_dt or not end_dt:
        return 0
    return max(0, int((end_dt - start_dt).total_seconds() // 86400))


def _parse_time(value: str) -> datetime | None:
    text = str(value or "")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
