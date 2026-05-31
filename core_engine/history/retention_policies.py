from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.history.timeline_replay import TIMELINE_REPLAY_SAFETY_FLAGS


RETENTION_POLICY_RECORD_VERSION = 1

RETENTION_POLICY_SAFETY_FLAGS = {
    **TIMELINE_REPLAY_SAFETY_FLAGS,
    "resource_aware_retention": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "resource_conscious": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "deletion_preview_only": True,
    "automatic_deletion": False,
    "delete_performed": False,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_logs_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


RETENTION_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "default": {
        "profile_label": "default",
        "retention_days": 30,
        "max_snapshots": 30,
        "max_replay_events": 200,
        "max_topology_relationships": 500,
        "max_baseline_records": 500,
        "min_free_storage_mb": 512,
        "critical_free_storage_mb": 128,
        "min_free_memory_mb": 256,
        "critical_free_memory_mb": 128,
        "edge_device_profile": False,
    },
    "edge-device": {
        "profile_label": "edge-device",
        "retention_days": 14,
        "max_snapshots": 15,
        "max_replay_events": 120,
        "max_topology_relationships": 250,
        "max_baseline_records": 250,
        "min_free_storage_mb": 1024,
        "critical_free_storage_mb": 256,
        "min_free_memory_mb": 384,
        "critical_free_memory_mb": 192,
        "edge_device_profile": True,
    },
    "raspberry-pi": {
        "profile_label": "raspberry-pi",
        "retention_days": 10,
        "max_snapshots": 10,
        "max_replay_events": 80,
        "max_topology_relationships": 200,
        "max_baseline_records": 200,
        "min_free_storage_mb": 1024,
        "critical_free_storage_mb": 256,
        "min_free_memory_mb": 512,
        "critical_free_memory_mb": 256,
        "edge_device_profile": True,
    },
}


def build_retention_policy_record(
    *,
    profile_label: str = "default",
    overrides: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    base = dict(RETENTION_PROFILE_DEFAULTS.get(profile_label, RETENTION_PROFILE_DEFAULTS["default"]))
    if overrides:
        for key, value in overrides.items():
            if key in base:
                base[key] = value
    base["profile_label"] = str(base.get("profile_label") or profile_label or "default")
    normalized = _normalize_profile(base)
    policy = {
        "record_type": "historical_retention_policy",
        "record_version": RETENTION_POLICY_RECORD_VERSION,
        "generated_at": timestamp,
        "policy_id": "historical-retention-policy-" + _digest({"profile": normalized, "generated_at": timestamp})[:16],
        "profile_label": normalized["profile_label"],
        "edge_device_profile": bool(normalized["edge_device_profile"]),
        "retention_windows": {
            "retention_days": normalized["retention_days"],
            "max_snapshots": normalized["max_snapshots"],
            "max_replay_events": normalized["max_replay_events"],
            "max_topology_relationships": normalized["max_topology_relationships"],
            "max_baseline_records": normalized["max_baseline_records"],
        },
        "budget_thresholds": {
            "min_free_storage_mb": normalized["min_free_storage_mb"],
            "critical_free_storage_mb": normalized["critical_free_storage_mb"],
            "min_free_memory_mb": normalized["min_free_memory_mb"],
            "critical_free_memory_mb": normalized["critical_free_memory_mb"],
        },
        "category_limits": {
            "snapshots": normalized["max_snapshots"],
            "replay": normalized["max_replay_events"],
            "topology_history": normalized["max_topology_relationships"],
            "behavioral_baselines": normalized["max_baseline_records"],
        },
        "operator_summary": _operator_summary(normalized),
        **RETENTION_POLICY_SAFETY_FLAGS,
    }
    return policy


def get_default_retention_policy(
    profile_label: str = "default",
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return build_retention_policy_record(profile_label=profile_label, generated_at=generated_at)


def get_edge_retention_policy(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_retention_policy_record(profile_label="edge-device", generated_at=generated_at)


def get_raspberry_pi_retention_policy(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_retention_policy_record(profile_label="raspberry-pi", generated_at=generated_at)


def deterministic_retention_policy_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _normalize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_label": str(profile.get("profile_label") or "default"),
        "retention_days": _positive_int(profile.get("retention_days"), 30),
        "max_snapshots": _positive_int(profile.get("max_snapshots"), 30),
        "max_replay_events": _positive_int(profile.get("max_replay_events"), 200),
        "max_topology_relationships": _positive_int(profile.get("max_topology_relationships"), 500),
        "max_baseline_records": _positive_int(profile.get("max_baseline_records"), 500),
        "min_free_storage_mb": _positive_int(profile.get("min_free_storage_mb"), 512),
        "critical_free_storage_mb": _positive_int(profile.get("critical_free_storage_mb"), 128),
        "min_free_memory_mb": _positive_int(profile.get("min_free_memory_mb"), 256),
        "critical_free_memory_mb": _positive_int(profile.get("critical_free_memory_mb"), 128),
        "edge_device_profile": bool(profile.get("edge_device_profile")),
    }


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, parsed)


def _operator_summary(profile: dict[str, Any]) -> str:
    if profile["edge_device_profile"]:
        return "Use bounded metadata retention suitable for edge devices and Raspberry Pi-class deployments."
    return "Use bounded metadata retention suitable for general local development and workstation deployments."


def _digest(payload: Any) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
