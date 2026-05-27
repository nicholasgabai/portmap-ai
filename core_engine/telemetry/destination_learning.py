from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.dns_visibility import DNS_VISIBILITY_SAFETY_FLAGS, sanitize_domain_name


DESTINATION_LEARNING_RECORD_VERSION = 1
DEFAULT_MAX_DESTINATION_BEHAVIOR_RECORDS = 500
DEFAULT_DESTINATION_MATURITY_THRESHOLD = 3

DESTINATION_LEARNING_SAFETY_FLAGS = {
    **DNS_VISIBILITY_SAFETY_FLAGS,
    "privacy_preserving": True,
    "metadata_only": True,
    "raw_dns_payloads_stored": False,
    "full_dns_payloads_stored": False,
    "credentials_stored": False,
    "browsing_history_verbatim_stored": False,
    "external_reputation_calls": False,
    "user_deanonymization": False,
    "automatic_enforcement": False,
}


class DestinationLearningError(ValueError):
    """Raised when destination learning configuration is malformed."""


def build_destination_learning_records(
    *,
    dns_visibility_report: dict[str, Any] | None = None,
    previous_destinations: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_records: int = DEFAULT_MAX_DESTINATION_BEHAVIOR_RECORDS,
    maturity_threshold: int = DEFAULT_DESTINATION_MATURITY_THRESHOLD,
    hash_domains: bool = False,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _generated_at(dns_visibility_report)
    if int(max_records) <= 0:
        raise DestinationLearningError("max_records must be positive")
    if int(maturity_threshold) <= 0:
        raise DestinationLearningError("maturity_threshold must be positive")
    grouped = _group_dns_observations(dns_visibility_report)
    previous = _previous_index(previous_destinations)
    records = [
        _build_destination_record(
            destination_key=key,
            observations=rows,
            previous=previous.get(key),
            dns_visibility_report=dns_visibility_report,
            generated_at=timestamp,
            maturity_threshold=int(maturity_threshold),
            hash_domains=hash_domains,
        )
        for key, rows in grouped.items()
    ]
    for key, previous_record in previous.items():
        if key not in grouped:
            records.append(_build_dormant_destination(destination_key=key, previous=previous_record, generated_at=timestamp))
    records = sorted(records, key=lambda item: (str(item.get("domain_summary", {}).get("display_domain") or ""), str(item.get("destination_key") or "")))
    dropped = max(0, len(records) - int(max_records))
    selected = records[: int(max_records)]
    for row in selected:
        row["bounded_retention_applied"] = dropped > 0
        row["dropped_destination_count"] = dropped
    return selected


def classify_destination_ip_placeholder(value: Any) -> dict[str, Any]:
    text = str(value or "")
    classification = "unknown"
    if text.startswith("198.51.100.") or text.startswith("203.0.113.") or text.startswith("2001:db8:"):
        classification = "documentation"
    elif text.startswith("224.") or text.startswith("ff"):
        classification = "multicast"
    elif text in {"", "0.0.0.0", "::"}:
        classification = "unknown"
    return {
        "record_type": "destination_ip_classification_placeholder",
        "classification": classification,
        "address_value_stored": False,
        "address_hash": _digest({"address": text})[:16] if text else "",
        **DESTINATION_LEARNING_SAFETY_FLAGS,
    }


def safe_destination_domain_summary(
    domain: str,
    *,
    max_length: int = 80,
    hash_domain: bool = False,
) -> dict[str, Any]:
    safe_domain, governance = sanitize_domain_name(domain, max_length=max_length)
    display = _redacted_domain_display(safe_domain)
    payload = {
        "record_type": "safe_destination_domain_summary",
        "display_domain": "<hashed-domain>" if hash_domain and safe_domain else display,
        "domain_hash": _digest({"domain": safe_domain}) if safe_domain else "",
        "label_count": len([part for part in safe_domain.split(".") if part]),
        "truncated": bool(governance.get("truncated")),
        "redacted": True,
        "hash_only": bool(hash_domain),
        "raw_domain_stored": False,
        "full_domain_stored": False,
        **DESTINATION_LEARNING_SAFETY_FLAGS,
    }
    return payload


def score_destination_learning_confidence(
    *,
    recurrence_density: float,
    timing_stability: float,
    resolver_consistency: float,
    destination_maturity: float,
    observation_count: int,
    anomaly_overlap: int = 0,
) -> float:
    score = 0.12
    score += min(0.2, max(0.0, min(1.0, recurrence_density)) * 0.2)
    score += min(0.18, max(0.0, min(1.0, timing_stability)) * 0.18)
    score += min(0.18, max(0.0, min(1.0, resolver_consistency)) * 0.18)
    score += min(0.2, max(0.0, min(1.0, destination_maturity)) * 0.2)
    score += min(0.12, int(observation_count) * 0.03)
    score -= min(0.18, int(anomaly_overlap) * 0.06)
    return round(max(0.05, min(1.0, score)), 3)


def deterministic_destination_learning_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _build_destination_record(
    *,
    destination_key: str,
    observations: list[dict[str, Any]],
    previous: dict[str, Any] | None,
    dns_visibility_report: dict[str, Any] | None,
    generated_at: str,
    maturity_threshold: int,
    hash_domains: bool,
) -> dict[str, Any]:
    rows = sorted(observations, key=lambda item: str(item.get("timestamp") or ""))
    first_seen = min((str(row.get("timestamp") or "") for row in rows), default="")
    last_seen = max((str(row.get("timestamp") or "") for row in rows), default="")
    resolver_values = sorted({str(row.get("resolver_ip") or "") for row in rows if row.get("resolver_ip")})
    resolver_types = _resolver_type_counts(dns_visibility_report, rows)
    anomalies = _anomaly_count(dns_visibility_report, rows)
    domain = str(rows[0].get("query_name") or rows[0].get("domain") or "") if rows else str((previous or {}).get("domain_summary", {}).get("display_domain") or "")
    summary = safe_destination_domain_summary(domain, hash_domain=hash_domains)
    observation_count = len(rows)
    previous_count = int((previous or {}).get("observation_count") or 0)
    maturity = min(1.0, (observation_count + previous_count) / max(1, int(maturity_threshold)))
    timing_stability = 1.0 if observation_count >= 2 else 0.45
    resolver_consistency = 1.0 if len(resolver_values) <= 1 else 0.45
    confidence = score_destination_learning_confidence(
        recurrence_density=min(1.0, observation_count / max(1, int(maturity_threshold))),
        timing_stability=timing_stability,
        resolver_consistency=resolver_consistency,
        destination_maturity=maturity,
        observation_count=observation_count,
        anomaly_overlap=anomalies,
    )
    novelty = 1.0 if not previous and observation_count < int(maturity_threshold) else max(0.0, 1.0 - maturity)
    answer_values = [value for row in rows for value in row.get("answer_values", [])]
    record = {
        "record_type": "destination_learning_record",
        "record_version": DESTINATION_LEARNING_RECORD_VERSION,
        "generated_at": generated_at,
        "destination_key": destination_key,
        "domain_summary": summary,
        "resolver_summary": {
            "resolver_count": len(resolver_values),
            "resolver_hashes": [_digest({"resolver": value})[:16] for value in resolver_values],
            "resolver_type_counts": resolver_types,
            "stable_resolver": len(resolver_values) <= 1 and bool(resolver_values),
            "resolver_ips_stored": False,
        },
        "destination_ip_classification_placeholders": [classify_destination_ip_placeholder(value) for value in sorted(set(answer_values))],
        "destination_frequency": observation_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "recurrence_timing": {
            "observation_count": observation_count,
            "timing_stability": timing_stability,
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
        "rolling_novelty_score": round(novelty, 3),
        "baseline_confidence": confidence,
        "transport_protocol_associations": _count_by(rows, "transport_protocol"),
        "query_type_associations": _count_by(rows, "query_type"),
        "source_refs": sorted({str(ref) for row in rows for ref in row.get("source_refs", []) if ref}),
        "anomaly_overlap_count": anomalies,
        "bounded_retention_applied": False,
        "dropped_destination_count": 0,
        **DESTINATION_LEARNING_SAFETY_FLAGS,
    }
    record["destination_record_id"] = "destination-learning-" + _digest({"destination_key": destination_key})[:16]
    return record


def _build_dormant_destination(*, destination_key: str, previous: dict[str, Any], generated_at: str) -> dict[str, Any]:
    record = {
        "record_type": "destination_learning_record",
        "record_version": DESTINATION_LEARNING_RECORD_VERSION,
        "generated_at": generated_at,
        "destination_key": destination_key,
        "domain_summary": dict(previous.get("domain_summary") or safe_destination_domain_summary("")),
        "resolver_summary": dict(previous.get("resolver_summary") or {}),
        "destination_ip_classification_placeholders": [],
        "destination_frequency": 0,
        "first_seen": str(previous.get("first_seen") or ""),
        "last_seen": str(previous.get("last_seen") or ""),
        "recurrence_timing": {"observation_count": 0, "timing_stability": 0.0},
        "rolling_novelty_score": 0.0,
        "baseline_confidence": round(max(0.1, float(previous.get("baseline_confidence") or 0.2) * 0.5), 3),
        "transport_protocol_associations": dict(previous.get("transport_protocol_associations") or {}),
        "query_type_associations": dict(previous.get("query_type_associations") or {}),
        "source_refs": sorted(str(ref) for ref in previous.get("source_refs") or [] if ref),
        "anomaly_overlap_count": 0,
        "dormant": True,
        "bounded_retention_applied": False,
        "dropped_destination_count": 0,
        **DESTINATION_LEARNING_SAFETY_FLAGS,
    }
    record["destination_record_id"] = str(previous.get("destination_record_id") or "destination-learning-" + _digest({"destination_key": destination_key})[:16])
    return record


def _group_dns_observations(dns_visibility_report: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(dns_visibility_report, dict):
        return {}
    rows = []
    response_index = {str(row.get("query_id") or ""): row for row in _rows(dns_visibility_report.get("responses"))}
    for query in _rows(dns_visibility_report.get("queries")):
        domain = str(query.get("query_name") or "")
        if not domain:
            continue
        response = response_index.get(str(query.get("query_id") or "")) or {}
        answers = response.get("answers") if isinstance(response.get("answers"), list) else []
        row = {
            "query_name": domain,
            "query_type": query.get("query_type"),
            "timestamp": query.get("timestamp") or query.get("generated_at"),
            "resolver_ip": query.get("resolver_ip"),
            "transport_protocol": query.get("transport_protocol"),
            "response_code": response.get("response_code"),
            "answer_values": [str(answer.get("value") or "") for answer in answers if isinstance(answer, dict)],
            "source_refs": list(query.get("source_refs") or []) + list(response.get("source_refs") or []),
        }
        rows.append(row)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        safe_domain, _governance = sanitize_domain_name(row.get("query_name") or "")
        if not safe_domain:
            continue
        key = _digest({"domain": safe_domain})[:32]
        grouped.setdefault(key, []).append(row)
    return dict(sorted(grouped.items()))


def _resolver_type_counts(dns_visibility_report: dict[str, Any] | None, rows: list[dict[str, Any]]) -> dict[str, int]:
    resolver_values = {str(row.get("resolver_ip") or "") for row in rows}
    counts: dict[str, int] = {}
    for resolver in _rows((dns_visibility_report or {}).get("resolver_summaries") if isinstance(dns_visibility_report, dict) else []):
        if str(resolver.get("resolver_ip") or "") in resolver_values:
            value = str(resolver.get("resolver_type") or "unknown")
            counts[value] = counts.get(value, 0) + 1
    if not counts and resolver_values:
        counts["unknown"] = len(resolver_values)
    return dict(sorted(counts.items()))


def _anomaly_count(dns_visibility_report: dict[str, Any] | None, rows: list[dict[str, Any]]) -> int:
    domains = {str(row.get("query_name") or "") for row in rows}
    count = 0
    for hint in _rows((dns_visibility_report or {}).get("anomaly_hints") if isinstance(dns_visibility_report, dict) else []):
        if str(hint.get("query_name") or "") in domains or str(hint.get("query_ref") or ""):
            count += 1
    return count


def _previous_index(previous_destinations: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index = {}
    for row in _rows(previous_destinations):
        key = str(row.get("destination_key") or "")
        if key:
            index[key] = row
    return index


def _redacted_domain_display(domain: str) -> str:
    parts = [part for part in str(domain).split(".") if part]
    if not parts:
        return ""
    if len(parts) <= 2:
        return ".".join(parts)
    return "<redacted>." + ".".join(parts[-2:])


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _generated_at(record: dict[str, Any] | None) -> str:
    if isinstance(record, dict) and record.get("generated_at"):
        return str(record["generated_at"])
    return _now()


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
