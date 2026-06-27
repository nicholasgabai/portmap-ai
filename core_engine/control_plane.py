from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


CONTROL_PLANE_RECORD_VERSION = 1

DEPLOYMENT_STATES = frozenset(
    {"standalone", "local_cluster", "enterprise_cluster", "disconnected", "maintenance", "unknown"}
)
HEALTH_STATES = frozenset({"healthy", "degraded", "unavailable", "unknown"})
SYNCHRONIZATION_STATES = frozenset(
    {"synchronized", "partially_synchronized", "out_of_sync", "unknown"}
)

CONTROL_PLANE_SAFETY_FLAGS = {
    "metadata_only": True,
    "read_only": True,
    "local_model_only": True,
    "network_called": False,
    "hosted_api_started": False,
    "http_server_started": False,
    "socket_opened": False,
    "database_used": False,
    "remote_execution_enabled": False,
    "telemetry_enabled": False,
    "runtime_state_mutated": False,
    "worker_orchestration_changed": False,
    "billing_contacted": False,
    "authentication_provider_contacted": False,
    "customer_provisioning_contacted": False,
}


@dataclass(frozen=True)
class ControlPlaneRecord:
    organization_id: str
    deployment_id: str
    deployment_name: str
    deployment_status: str
    deployment_mode: str
    node_count: int
    worker_count: int
    coordinator_version: str
    schema_version: str
    feature_set: list[str] = field(default_factory=list)
    license_edition: str = "unknown"
    health_status: str = "unknown"
    synchronization_state: str = "unknown"
    policy_version: str = "unknown"
    configuration_version: str = "unknown"
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "control_plane_model",
            "record_version": CONTROL_PLANE_RECORD_VERSION,
            "organization_id": self.organization_id,
            "deployment_id": self.deployment_id,
            "deployment_name": self.deployment_name,
            "deployment_status": self.deployment_status,
            "deployment_mode": self.deployment_mode,
            "node_count": self.node_count,
            "worker_count": self.worker_count,
            "coordinator_version": self.coordinator_version,
            "schema_version": self.schema_version,
            "feature_set": list(self.feature_set),
            "license_edition": self.license_edition,
            "health_status": self.health_status,
            "synchronization_state": self.synchronization_state,
            "policy_version": self.policy_version,
            "configuration_version": self.configuration_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
            **CONTROL_PLANE_SAFETY_FLAGS,
        }


def create_control_plane(
    *,
    organization_id: Any = "",
    deployment_id: Any = "",
    deployment_name: Any = "",
    deployment_status: Any = "unknown",
    deployment_mode: Any = "unknown",
    node_count: Any = 0,
    worker_count: Any = 0,
    coordinator_version: Any = "unknown",
    schema_version: Any = str(CONTROL_PLANE_RECORD_VERSION),
    feature_set: Any = None,
    license_edition: Any = "unknown",
    health_status: Any = "unknown",
    synchronization_state: Any = "unknown",
    policy_version: Any = "unknown",
    configuration_version: Any = "unknown",
    created_at: Any = "",
    updated_at: Any = "",
    metadata: Any = None,
) -> ControlPlaneRecord:
    status = normalize_deployment_state(deployment_status)
    mode = normalize_deployment_state(deployment_mode)
    return ControlPlaneRecord(
        organization_id=_safe_text(organization_id),
        deployment_id=_safe_text(deployment_id),
        deployment_name=_safe_text(deployment_name) or "Local control plane",
        deployment_status=status,
        deployment_mode=mode,
        node_count=_bounded_count(node_count),
        worker_count=_bounded_count(worker_count),
        coordinator_version=_safe_text(coordinator_version) or "unknown",
        schema_version=_safe_text(schema_version) or "unknown",
        feature_set=_normalize_feature_set(feature_set),
        license_edition=_safe_text(license_edition).lower() or "unknown",
        health_status=normalize_health_state(health_status),
        synchronization_state=normalize_synchronization_state(synchronization_state),
        policy_version=_safe_text(policy_version) or "unknown",
        configuration_version=_safe_text(configuration_version) or "unknown",
        created_at=_safe_text(created_at),
        updated_at=_safe_text(updated_at),
        metadata=_normalize_metadata(metadata),
    )


def summarize_control_plane(control_plane: ControlPlaneRecord | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(control_plane, ControlPlaneRecord):
        return control_plane.to_dict()
    if isinstance(control_plane, dict):
        return create_control_plane(
            organization_id=control_plane.get("organization_id", ""),
            deployment_id=control_plane.get("deployment_id", ""),
            deployment_name=control_plane.get("deployment_name", control_plane.get("name", "")),
            deployment_status=control_plane.get("deployment_status", control_plane.get("state", "unknown")),
            deployment_mode=control_plane.get("deployment_mode", "unknown"),
            node_count=control_plane.get("node_count", 0),
            worker_count=control_plane.get("worker_count", 0),
            coordinator_version=control_plane.get("coordinator_version", "unknown"),
            schema_version=control_plane.get("schema_version", "unknown"),
            feature_set=control_plane.get("feature_set", []),
            license_edition=control_plane.get("license_edition", "unknown"),
            health_status=control_plane.get("health_status", "unknown"),
            synchronization_state=control_plane.get("synchronization_state", "unknown"),
            policy_version=control_plane.get("policy_version", "unknown"),
            configuration_version=control_plane.get("configuration_version", "unknown"),
            created_at=control_plane.get("created_at", ""),
            updated_at=control_plane.get("updated_at", ""),
            metadata=control_plane.get("metadata", {}),
        ).to_dict()
    return create_control_plane().to_dict()


def validate_control_plane(
    control_plane: ControlPlaneRecord | dict[str, Any] | None,
    *,
    expected_schema_version: Any | None = None,
    expected_coordinator_version: Any | None = None,
    expected_policy_version: Any | None = None,
    expected_configuration_version: Any | None = None,
    expected_synchronization_state: Any | None = None,
    previous_control_plane: ControlPlaneRecord | dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = summarize_control_plane(control_plane)
    previous = summarize_control_plane(previous_control_plane) if previous_control_plane is not None else None
    reasons: set[str] = set()

    missing_identifiers = [
        field
        for field in ("organization_id", "deployment_id")
        if not summary.get(field)
    ]
    if missing_identifiers:
        reasons.add("missing identifiers: " + ", ".join(missing_identifiers))

    invalid_schema = summary["schema_version"] in {"", "unknown"}
    if invalid_schema:
        reasons.add("schema version is missing or unknown")

    invalid_deployment_state = summary["deployment_status"] == "unknown"
    if invalid_deployment_state:
        reasons.add("deployment state is invalid or unknown")

    invalid_health_state = summary["health_status"] == "unknown"
    if invalid_health_state:
        reasons.add("health status is unknown")

    invalid_sync_state = summary["synchronization_state"] == "unknown"
    if invalid_sync_state:
        reasons.add("synchronization state is unknown")

    version_mismatch = _mismatch(summary["coordinator_version"], expected_coordinator_version)
    if version_mismatch:
        reasons.add("coordinator version mismatch")

    schema_mismatch = _mismatch(summary["schema_version"], expected_schema_version)
    if schema_mismatch:
        reasons.add("schema version mismatch")

    policy_mismatch = _mismatch(summary["policy_version"], expected_policy_version)
    if policy_mismatch:
        reasons.add("policy version mismatch")

    configuration_mismatch = _mismatch(summary["configuration_version"], expected_configuration_version)
    if configuration_mismatch:
        reasons.add("configuration version mismatch")

    synchronization_mismatch = _mismatch(
        summary["synchronization_state"],
        normalize_synchronization_state(expected_synchronization_state)
        if expected_synchronization_state is not None
        else None,
    )
    if synchronization_mismatch:
        reasons.add("synchronization state mismatch")

    health_transition = "none"
    if previous is not None:
        health_transition = compare_health_transition(
            previous.get("health_status"),
            summary.get("health_status"),
        )
        if health_transition in {"degraded", "unavailable"}:
            reasons.add(f"health transitioned to {health_transition}")

    validation_status = _validation_status(
        missing_identifiers=bool(missing_identifiers),
        invalid_schema=invalid_schema,
        invalid_deployment_state=invalid_deployment_state,
        invalid_health_state=invalid_health_state,
        invalid_sync_state=invalid_sync_state,
        mismatched=any(
            [
                version_mismatch,
                schema_mismatch,
                policy_mismatch,
                configuration_mismatch,
                synchronization_mismatch,
            ]
        ),
        health_transition=health_transition,
    )

    return {
        "record_type": "control_plane_validation_summary",
        "record_version": CONTROL_PLANE_RECORD_VERSION,
        "organization_id": summary["organization_id"],
        "deployment_id": summary["deployment_id"],
        "validation_status": validation_status,
        "valid": validation_status == "valid",
        "validation_reasons": sorted(reasons) or ["control plane metadata is valid"],
        "missing_identifiers": missing_identifiers,
        "invalid_schema": invalid_schema,
        "invalid_deployment_state": invalid_deployment_state,
        "version_mismatch": version_mismatch,
        "schema_mismatch": schema_mismatch,
        "policy_mismatch": policy_mismatch,
        "configuration_mismatch": configuration_mismatch,
        "synchronization_mismatch": synchronization_mismatch,
        "health_transition": health_transition,
        "previous_health_status": previous.get("health_status") if previous else "unknown",
        "current_health_status": summary["health_status"],
        "summary": summary,
        **CONTROL_PLANE_SAFETY_FLAGS,
    }


def merge_control_plane_metadata(
    base: ControlPlaneRecord | dict[str, Any] | None,
    overlay: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge local metadata previews without mutating either input."""
    merged = summarize_control_plane(base)
    if not isinstance(overlay, dict):
        return merged

    allowed = {
        "deployment_name",
        "deployment_status",
        "deployment_mode",
        "node_count",
        "worker_count",
        "coordinator_version",
        "schema_version",
        "feature_set",
        "license_edition",
        "health_status",
        "synchronization_state",
        "policy_version",
        "configuration_version",
        "created_at",
        "updated_at",
        "metadata",
    }
    for key in sorted(allowed):
        if key not in overlay:
            continue
        if key == "feature_set":
            merged[key] = sorted(set(merged.get(key, [])) | set(_normalize_feature_set(overlay[key])))
        elif key == "metadata":
            metadata = dict(merged.get("metadata", {}))
            metadata.update(_normalize_metadata(overlay[key]))
            merged[key] = dict(sorted(metadata.items()))
        else:
            merged[key] = deepcopy(overlay[key])
    return summarize_control_plane(merged)


def compare_control_plane_versions(
    left: ControlPlaneRecord | dict[str, Any] | None,
    right: ControlPlaneRecord | dict[str, Any] | None,
) -> dict[str, Any]:
    left_summary = summarize_control_plane(left)
    right_summary = summarize_control_plane(right)
    changed = {
        "coordinator_version_changed": left_summary["coordinator_version"] != right_summary["coordinator_version"],
        "schema_version_changed": left_summary["schema_version"] != right_summary["schema_version"],
        "policy_version_changed": left_summary["policy_version"] != right_summary["policy_version"],
        "configuration_version_changed": left_summary["configuration_version"] != right_summary["configuration_version"],
        "synchronization_state_changed": left_summary["synchronization_state"] != right_summary["synchronization_state"],
        "health_status_changed": left_summary["health_status"] != right_summary["health_status"],
    }
    return {
        "record_type": "control_plane_version_comparison",
        "record_version": CONTROL_PLANE_RECORD_VERSION,
        "left_deployment_id": left_summary["deployment_id"],
        "right_deployment_id": right_summary["deployment_id"],
        **changed,
        "version_mismatch": any(
            changed[key]
            for key in (
                "coordinator_version_changed",
                "schema_version_changed",
                "policy_version_changed",
                "configuration_version_changed",
            )
        ),
        "synchronization_mismatch": changed["synchronization_state_changed"],
        "health_transition": compare_health_transition(
            left_summary["health_status"], right_summary["health_status"]
        ),
        **CONTROL_PLANE_SAFETY_FLAGS,
    }


def compare_synchronization_state(left: Any, right: Any) -> str:
    left_state = normalize_synchronization_state(left)
    right_state = normalize_synchronization_state(right)
    if left_state == right_state:
        return "same"
    if "unknown" in {left_state, right_state}:
        return "unknown"
    if right_state == "synchronized":
        return "improved"
    if left_state == "synchronized" and right_state != "synchronized":
        return "degraded"
    if right_state == "out_of_sync":
        return "degraded"
    return "changed"


def compare_health_transition(left: Any, right: Any) -> str:
    left_state = normalize_health_state(left)
    right_state = normalize_health_state(right)
    order = {"unknown": 0, "unavailable": 1, "degraded": 2, "healthy": 3}
    if left_state == right_state:
        return "none"
    if right_state == "unknown" or left_state == "unknown":
        return "unknown"
    if order[right_state] > order[left_state]:
        return "improved"
    return right_state


def normalize_deployment_state(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in DEPLOYMENT_STATES else "unknown"


def normalize_health_state(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in HEALTH_STATES else "unknown"


def normalize_synchronization_state(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in SYNCHRONIZATION_STATES else "unknown"


def deterministic_control_plane_json(control_plane: ControlPlaneRecord | dict[str, Any] | None) -> str:
    return json.dumps(summarize_control_plane(control_plane), sort_keys=True, separators=(",", ":"))


def _validation_status(
    *,
    missing_identifiers: bool,
    invalid_schema: bool,
    invalid_deployment_state: bool,
    invalid_health_state: bool,
    invalid_sync_state: bool,
    mismatched: bool,
    health_transition: str,
) -> str:
    if missing_identifiers or invalid_schema or invalid_deployment_state:
        return "invalid"
    if invalid_health_state or invalid_sync_state:
        return "unknown"
    if mismatched or health_transition in {"degraded", "unavailable"}:
        return "degraded"
    return "valid"


def _mismatch(current: Any, expected: Any | None) -> bool:
    if expected is None:
        return False
    return _safe_text(current) != _safe_text(expected)


def _normalize_feature_set(features: Any) -> list[str]:
    if isinstance(features, dict):
        values = [_safe_text(key) for key, value in features.items() if value]
    elif isinstance(features, (list, tuple, set)):
        values = [_safe_text(feature) for feature in features]
    elif isinstance(features, str):
        values = [_safe_text(features)]
    else:
        values = []
    return sorted({value for value in values if value})


def _normalize_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in sorted(metadata.items(), key=lambda item: _safe_text(item[0])):
        safe_key = _safe_text(key)
        if safe_key:
            normalized[safe_key] = deepcopy(value)
    return normalized


def _bounded_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return max(0, min(int(value), 1_000_000))
    if isinstance(value, str):
        try:
            return max(0, min(int(value.strip()), 1_000_000))
        except ValueError:
            return 0
    return 0


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())
