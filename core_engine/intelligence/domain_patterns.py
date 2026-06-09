from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    hash_ioc_value,
    normalize_ioc_source_category,
    normalize_source_mode,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)


DOMAIN_PATTERN_RECORD_VERSION = IOC_RECORD_VERSION
DOMAIN_PATTERN_TYPES = {
    "newly_seen_domain",
    "rare_domain",
    "high_entropy_label",
    "long_domain",
    "suspicious_tld",
    "repeated_subdomain",
    "dns_tunneling_candidate",
    "resolver_change",
    "unknown",
}
DOMAIN_PATTERN_STATES = {"observed", "noteworthy", "review_recommended", "degraded", "unknown"}
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "review"}


@dataclass(frozen=True)
class DomainPatternRecord:
    pattern_id: str
    pattern_type: str
    normalized_domain_hash: str
    domain_preview: str
    pattern_state: str
    confidence_score: float
    pattern_reasons: list[str] = field(default_factory=list)
    source_category: str = "dns"
    source_mode: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    normalized_domain: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "domain_pattern_record",
            "record_version": DOMAIN_PATTERN_RECORD_VERSION,
            "pattern_id": sanitize_reference(self.pattern_id),
            "pattern_type": normalize_domain_pattern_type(self.pattern_type),
            "normalized_domain_hash": str(self.normalized_domain_hash or ""),
            "domain_preview": sanitize_text(self.domain_preview),
            "pattern_state": normalize_domain_pattern_state(self.pattern_state),
            "confidence_score": clamp_score(self.confidence_score),
            "pattern_reasons": [sanitize_text(reason) for reason in self.pattern_reasons],
            "source_category": normalize_ioc_source_category(self.source_category),
            "source_mode": normalize_source_mode(self.source_mode),
            "first_seen": str(self.first_seen or ""),
            "last_seen": str(self.last_seen or ""),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def analyze_domain_patterns(
    observations: Iterable[dict[str, Any]] | dict[str, Any] | None,
    *,
    baseline_domains: Iterable[str] | None = None,
    known_resolvers: Iterable[Any] | None = None,
    generated_at: str | None = None,
) -> list[DomainPatternRecord]:
    rows = [observations] if isinstance(observations, dict) else list(observations or [])
    baseline = {normalize_domain(item) for item in baseline_domains or [] if normalize_domain(item)}
    resolver_hashes = {_hash_resolver(item) for item in known_resolvers or [] if _hash_resolver(item)}
    patterns: list[DomainPatternRecord] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            patterns.append(malformed_domain_pattern_record(index=index, generated_at=generated_at))
            continue
        patterns.extend(
            analyze_domain_pattern(
                row,
                baseline_domains=baseline,
                known_resolver_hashes=resolver_hashes,
                generated_at=generated_at,
            )
        )
    return patterns


def analyze_domain_pattern(
    observation: dict[str, Any],
    *,
    baseline_domains: Iterable[str] | None = None,
    known_resolver_hashes: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> list[DomainPatternRecord]:
    if not isinstance(observation, dict):
        return [malformed_domain_pattern_record(index=0, generated_at=generated_at)]
    domain = normalize_domain(
        observation.get("domain")
        or observation.get("query_name")
        or observation.get("fqdn")
        or observation.get("dns_name")
        or observation.get("value")
    )
    if not domain:
        return [malformed_domain_pattern_record(index=0, generated_at=generated_at)]

    baseline = {normalize_domain(item) for item in baseline_domains or [] if normalize_domain(item)}
    resolver_hashes = {str(item) for item in known_resolver_hashes or [] if item}
    source_mode = normalize_source_mode(observation.get("source_mode") or "unknown")
    source_category = normalize_ioc_source_category(observation.get("source_category") or "dns")
    first_seen = str(observation.get("first_seen") or observation.get("timestamp") or generated_at or now_timestamp())
    last_seen = str(observation.get("last_seen") or observation.get("timestamp") or first_seen)

    findings: list[tuple[str, str, float, list[str]]] = []
    labels = domain.split(".")
    max_label = max(labels, key=len, default="")
    max_entropy = max((label_entropy(label) for label in labels), default=0.0)
    tld = labels[-1] if labels else ""
    observation_count = _safe_float(observation.get("observation_count"), default=0.0)
    frequency = _safe_float(observation.get("frequency"), default=1.0)
    query_type = sanitize_token(observation.get("query_type")).upper()

    if domain not in baseline:
        findings.append(("newly_seen_domain", "noteworthy", 0.55, ["domain not present in provided baseline"]))
    if observation_count and observation_count <= 1 or frequency < 0.05:
        findings.append(("rare_domain", "noteworthy", 0.58, ["low recurrence in provided metadata"]))
    if len(max_label) >= 12 and max_entropy >= 3.2:
        findings.append(("high_entropy_label", "review_recommended", 0.72, ["label entropy exceeds metadata threshold"]))
    if len(domain) >= 80 or len(max_label) >= 40:
        findings.append(("long_domain", "noteworthy", 0.64, ["domain length exceeds metadata threshold"]))
    if tld in SUSPICIOUS_TLDS:
        findings.append(("suspicious_tld", "review_recommended", 0.66, ["top-level label is configured for operator review"]))
    if repeated_subdomain_detected(labels):
        findings.append(("repeated_subdomain", "noteworthy", 0.62, ["repeated subdomain labels observed"]))
    if dns_tunneling_candidate(domain, labels, max_entropy, query_type):
        findings.append(
            (
                "dns_tunneling_candidate",
                "review_recommended",
                0.82,
                ["metadata resembles a high-volume encoded DNS pattern"],
            )
        )
    resolver_value = observation.get("resolver_reference") or observation.get("resolver") or observation.get("resolver_id")
    resolver_hash = _hash_resolver(resolver_value)
    if resolver_hash and resolver_hashes and resolver_hash not in resolver_hashes:
        findings.append(("resolver_change", "noteworthy", 0.6, ["resolver reference differs from provided resolver baseline"]))

    if not findings:
        findings.append(("unknown", "observed", 0.35, ["domain metadata observed without notable pattern"]))

    return [
        build_domain_pattern_record(
            domain,
            pattern_type=pattern_type,
            pattern_state=state,
            confidence_score=confidence,
            pattern_reasons=reasons,
            source_category=source_category,
            source_mode=source_mode,
            first_seen=first_seen,
            last_seen=last_seen,
        )
        for pattern_type, state, confidence, reasons in findings
    ]


def build_domain_pattern_record(
    domain: Any,
    *,
    pattern_type: str = "unknown",
    pattern_state: str = "observed",
    confidence_score: float = 0.5,
    pattern_reasons: list[str] | None = None,
    source_category: str = "dns",
    source_mode: str = "unknown",
    first_seen: str | None = None,
    last_seen: str | None = None,
    advisory_notes: list[str] | None = None,
) -> DomainPatternRecord:
    normalized = normalize_domain(domain)
    timestamp = now_timestamp()
    first = str(first_seen or timestamp)
    last = str(last_seen or first)
    if not normalized:
        normalized = "unknown"
        pattern_state = "degraded"
        pattern_type = "unknown"
    normalized_type = normalize_domain_pattern_type(pattern_type)
    state = normalize_domain_pattern_state(pattern_state)
    domain_hash = hash_domain(normalized)
    record_id = "domain-pattern-" + digest(
        {
            "pattern_type": normalized_type,
            "domain_hash": domain_hash,
            "state": state,
        }
    )[:16]
    notes = list(advisory_notes or [])
    notes.append("metadata-only DNS pattern record; no lookup, verdict, blocking, or enforcement")
    return DomainPatternRecord(
        pattern_id=record_id,
        pattern_type=normalized_type,
        normalized_domain_hash=domain_hash,
        domain_preview=redacted_domain_preview(normalized),
        pattern_state=state,
        confidence_score=clamp_score(confidence_score),
        pattern_reasons=[sanitize_text(reason) for reason in pattern_reasons or []],
        source_category=normalize_ioc_source_category(source_category),
        source_mode=normalize_source_mode(source_mode),
        first_seen=first,
        last_seen=last,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
        normalized_domain=normalized,
    )


def malformed_domain_pattern_record(*, index: int = 0, generated_at: str | None = None) -> DomainPatternRecord:
    timestamp = generated_at or now_timestamp()
    return build_domain_pattern_record(
        "unknown",
        pattern_type="unknown",
        pattern_state="degraded",
        confidence_score=0.0,
        pattern_reasons=[f"malformed DNS observation at bounded index {max(0, index)}"],
        source_category="dns",
        source_mode="unknown",
        first_seen=timestamp,
        last_seen=timestamp,
        advisory_notes=["malformed input was isolated without storing raw DNS history"],
    )


def normalize_domain(value: Any) -> str:
    if value is None:
        return ""
    raw = str(value).strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parts = urlsplit(raw)
        raw = parts.hostname or ""
    raw = raw.split("/")[0].split("?")[0].strip(".")
    raw = raw[2:] if raw.startswith("*.") else raw
    raw = re.sub(r"\.+", ".", raw)
    labels = [label for label in raw.split(".") if label]
    if not labels:
        return ""
    safe_labels = [re.sub(r"[^a-z0-9-]", "", label)[:63] for label in labels]
    safe_labels = [label.strip("-") for label in safe_labels if label.strip("-")]
    return ".".join(safe_labels)[:253]


def hash_domain(normalized_domain: str) -> str:
    return hash_ioc_value(normalized_domain, "domain")


def redacted_domain_preview(normalized_domain: str) -> str:
    return f"domain:{hash_domain(normalized_domain)[:12]}"


def normalize_domain_pattern_type(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in DOMAIN_PATTERN_TYPES else "unknown"


def normalize_domain_pattern_state(value: Any) -> str:
    token = sanitize_token(value).lower()
    return token if token in DOMAIN_PATTERN_STATES else "unknown"


def label_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts = {char: label.count(char) for char in set(label)}
    length = len(label)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)


def repeated_subdomain_detected(labels: list[str]) -> bool:
    if len(labels) < 4:
        return False
    subdomain_labels = labels[:-2]
    return any(subdomain_labels.count(label) >= 3 for label in set(subdomain_labels))


def dns_tunneling_candidate(domain: str, labels: list[str], max_entropy: float, query_type: str) -> bool:
    if not domain:
        return False
    many_labels = len(labels) >= 6 and max(len(label) for label in labels) >= 18
    encoded_label = max_entropy >= 3.3 and max(len(label) for label in labels) >= 24
    txt_style = query_type in {"TXT", "NULL"} and (len(domain) >= 60 or encoded_label)
    return bool(txt_style or (many_labels and encoded_label) or (len(domain) >= 100 and max_entropy >= 3.1))


def _safe_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _hash_resolver(value: Any) -> str:
    token = sanitize_reference(value)
    return digest(token) if token else ""
