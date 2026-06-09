from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    sanitize_reference,
    sanitize_text,
)


WEIGHT_FIELDS = (
    "ioc_weight",
    "dns_weight",
    "signature_weight",
    "correlation_weight",
    "flow_weight",
    "attribution_weight",
    "drift_weight",
    "topology_weight",
    "runtime_health_weight",
    "remediation_weight",
    "guardrail_weight",
)


@dataclass(frozen=True)
class ScoringWeightProfile:
    weight_profile_id: str
    profile_name: str
    enabled: bool
    ioc_weight: float
    dns_weight: float
    signature_weight: float
    correlation_weight: float
    flow_weight: float
    attribution_weight: float
    drift_weight: float
    topology_weight: float
    runtime_health_weight: float
    remediation_weight: float
    guardrail_weight: float
    confidence_floor: float
    confidence_ceiling: float
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "scoring_weight_profile",
            "record_version": IOC_RECORD_VERSION,
            "weight_profile_id": sanitize_reference(self.weight_profile_id),
            "profile_name": sanitize_text(self.profile_name),
            "enabled": bool(self.enabled),
            "ioc_weight": clamp_score(self.ioc_weight),
            "dns_weight": clamp_score(self.dns_weight),
            "signature_weight": clamp_score(self.signature_weight),
            "correlation_weight": clamp_score(self.correlation_weight),
            "flow_weight": clamp_score(self.flow_weight),
            "attribution_weight": clamp_score(self.attribution_weight),
            "drift_weight": clamp_score(self.drift_weight),
            "topology_weight": clamp_score(self.topology_weight),
            "runtime_health_weight": clamp_score(self.runtime_health_weight),
            "remediation_weight": clamp_score(self.remediation_weight),
            "guardrail_weight": clamp_score(self.guardrail_weight),
            "confidence_floor": clamp_score(self.confidence_floor),
            "confidence_ceiling": clamp_score(self.confidence_ceiling),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def default_scoring_weight_profile() -> ScoringWeightProfile:
    return build_scoring_weight_profile(profile_name="default_advisory")


def build_scoring_weight_profile(
    *,
    profile_name: str = "default_advisory",
    enabled: bool = True,
    ioc_weight: float = 1.0,
    dns_weight: float = 0.85,
    signature_weight: float = 1.0,
    correlation_weight: float = 0.95,
    flow_weight: float = 0.55,
    attribution_weight: float = 0.55,
    drift_weight: float = 0.65,
    topology_weight: float = 0.6,
    runtime_health_weight: float = 0.35,
    remediation_weight: float = 0.45,
    guardrail_weight: float = 0.5,
    confidence_floor: float = 0.0,
    confidence_ceiling: float = 1.0,
    advisory_notes: list[str] | None = None,
) -> ScoringWeightProfile:
    floor = clamp_score(confidence_floor)
    ceiling = clamp_score(confidence_ceiling)
    if floor > ceiling:
        floor, ceiling = ceiling, floor
    weights = normalize_weight_values(
        {
            "ioc_weight": ioc_weight,
            "dns_weight": dns_weight,
            "signature_weight": signature_weight,
            "correlation_weight": correlation_weight,
            "flow_weight": flow_weight,
            "attribution_weight": attribution_weight,
            "drift_weight": drift_weight,
            "topology_weight": topology_weight,
            "runtime_health_weight": runtime_health_weight,
            "remediation_weight": remediation_weight,
            "guardrail_weight": guardrail_weight,
        }
    )
    profile = sanitize_reference(profile_name) or "default_advisory"
    notes = list(advisory_notes or [])
    notes.append("advisory scoring weights only; no enforcement tuning or final verdict behavior")
    return ScoringWeightProfile(
        weight_profile_id="scoring-weights-" + digest({"profile_name": profile, "weights": weights, "floor": floor, "ceiling": ceiling})[:16],
        profile_name=profile,
        enabled=bool(enabled),
        confidence_floor=floor,
        confidence_ceiling=ceiling,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
        **weights,
    )


def normalize_weight_values(values: dict[str, Any]) -> dict[str, float]:
    normalized = {field_name: clamp_score(values.get(field_name, 0.0)) for field_name in WEIGHT_FIELDS}
    if not any(normalized.values()):
        normalized = {field_name: (1.0 if field_name in {"ioc_weight", "signature_weight", "correlation_weight"} else 0.5) for field_name in WEIGHT_FIELDS}
    return normalized


def weight_for_category(profile: ScoringWeightProfile, category: str) -> float:
    mapping = {
        "ioc": profile.ioc_weight,
        "dns": profile.dns_weight,
        "signature": profile.signature_weight,
        "correlation": profile.correlation_weight,
        "flow": profile.flow_weight,
        "attribution": profile.attribution_weight,
        "drift": profile.drift_weight,
        "topology": profile.topology_weight,
        "runtime": profile.runtime_health_weight,
        "remediation": profile.remediation_weight,
        "guardrail": profile.guardrail_weight,
    }
    return clamp_score(mapping.get(category, 0.0))


def apply_confidence_bounds(value: Any, profile: ScoringWeightProfile) -> float:
    score = clamp_score(value)
    return round(max(profile.confidence_floor, min(profile.confidence_ceiling, score)), 4)
