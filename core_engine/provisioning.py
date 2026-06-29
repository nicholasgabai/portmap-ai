from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from core_engine.control_plane import summarize_control_plane
from core_engine.licensing import summarize_license


PROVISIONING_RECORD_VERSION = 1

PROVISIONING_STATUSES = frozenset(
    {"draft", "pending", "active", "suspended", "expired", "deprovisioned", "invalid", "unknown"}
)
PROVISIONING_STAGES = frozenset(
    {
        "created",
        "license_attached",
        "control_plane_attached",
        "features_assigned",
        "limits_assigned",
        "ready",
        "blocked",
        "unknown",
    }
)

PROVISIONING_STAGE_ORDER = {
    "unknown": 0,
    "created": 1,
    "license_attached": 2,
    "control_plane_attached": 3,
    "features_assigned": 4,
    "limits_assigned": 5,
    "ready": 6,
    "blocked": 7,
}

PROVISIONING_SAFETY_FLAGS = {
    "metadata_only": True,
    "read_only": True,
    "local_model_only": True,
    "network_called": False,
    "hosted_api_started": False,
    "http_server_started": False,
    "socket_opened": False,
    "database_used": False,
    "customer_portal_started": False,
    "billing_contacted": False,
    "payment_processor_contacted": False,
    "authentication_provider_contacted": False,
    "sso_provider_contacted": False,
    "remote_execution_enabled": False,
    "runtime_state_mutated": False,
    "automatic_provisioning_action": False,
}


@dataclass(frozen=True)
class CustomerProfileRecord:
    customer_id: str
    customer_name: str
    organization_id: str
    tenant_id: str
    deployment_id: str
    license_id: str
    edition: str
    provisioning_status: str
    provisioning_stage: str
    created_at: str
    updated_at: str
    activated_at: str
    expires_at: str
    assigned_features: list[str] = field(default_factory=list)
    assigned_limits: dict[str, Any] = field(default_factory=dict)
    contact_metadata: dict[str, Any] = field(default_factory=dict)
    deployment_region: str = "local"
    notes: list[str] = field(default_factory=list)
    schema_version: str = str(PROVISIONING_RECORD_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "customer_provisioning_profile",
            "record_version": PROVISIONING_RECORD_VERSION,
            "customer_id": self.customer_id,
            "customer_name": self.customer_name,
            "organization_id": self.organization_id,
            "tenant_id": self.tenant_id,
            "deployment_id": self.deployment_id,
            "license_id": self.license_id,
            "edition": self.edition,
            "provisioning_status": self.provisioning_status,
            "provisioning_stage": self.provisioning_stage,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "activated_at": self.activated_at,
            "expires_at": self.expires_at,
            "assigned_features": list(self.assigned_features),
            "assigned_limits": dict(self.assigned_limits),
            "contact_metadata": dict(self.contact_metadata),
            "deployment_region": self.deployment_region,
            "notes": list(self.notes),
            "schema_version": self.schema_version,
            **PROVISIONING_SAFETY_FLAGS,
        }


def create_customer_profile(
    *,
    customer_id: Any = "",
    customer_name: Any = "",
    organization_id: Any = "",
    tenant_id: Any = "",
    deployment_id: Any = "",
    license_id: Any = "",
    edition: Any = "unknown",
    provisioning_status: Any = "draft",
    provisioning_stage: Any = "created",
    created_at: Any = "",
    updated_at: Any = "",
    activated_at: Any = "",
    expires_at: Any = "",
    assigned_features: Any = None,
    assigned_limits: Any = None,
    contact_metadata: Any = None,
    deployment_region: Any = "local",
    notes: Any = None,
    schema_version: Any = str(PROVISIONING_RECORD_VERSION),
) -> CustomerProfileRecord:
    return CustomerProfileRecord(
        customer_id=_safe_text(customer_id),
        customer_name=_safe_text(customer_name) or "Unnamed customer",
        organization_id=_safe_text(organization_id),
        tenant_id=_safe_text(tenant_id),
        deployment_id=_safe_text(deployment_id),
        license_id=_safe_text(license_id),
        edition=_safe_text(edition).lower() or "unknown",
        provisioning_status=normalize_provisioning_status(provisioning_status),
        provisioning_stage=normalize_provisioning_stage(provisioning_stage),
        created_at=_safe_text(created_at),
        updated_at=_safe_text(updated_at),
        activated_at=_safe_text(activated_at),
        expires_at=_safe_text(expires_at),
        assigned_features=_normalize_features(assigned_features),
        assigned_limits=_normalize_limits(assigned_limits),
        contact_metadata=_normalize_mapping(contact_metadata),
        deployment_region=_safe_text(deployment_region) or "local",
        notes=_normalize_notes(notes),
        schema_version=_safe_text(schema_version) or "unknown",
    )


def summarize_customer_profile(profile: CustomerProfileRecord | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(profile, CustomerProfileRecord):
        return profile.to_dict()
    if isinstance(profile, dict):
        return create_customer_profile(
            customer_id=profile.get("customer_id", ""),
            customer_name=profile.get("customer_name", profile.get("name", "")),
            organization_id=profile.get("organization_id", ""),
            tenant_id=profile.get("tenant_id", ""),
            deployment_id=profile.get("deployment_id", ""),
            license_id=profile.get("license_id", ""),
            edition=profile.get("edition", "unknown"),
            provisioning_status=profile.get("provisioning_status", profile.get("status", "unknown")),
            provisioning_stage=profile.get("provisioning_stage", profile.get("stage", "unknown")),
            created_at=profile.get("created_at", ""),
            updated_at=profile.get("updated_at", ""),
            activated_at=profile.get("activated_at", ""),
            expires_at=profile.get("expires_at", ""),
            assigned_features=profile.get("assigned_features", profile.get("features", [])),
            assigned_limits=profile.get("assigned_limits", profile.get("limits", {})),
            contact_metadata=profile.get("contact_metadata", {}),
            deployment_region=profile.get("deployment_region", "local"),
            notes=profile.get("notes", []),
            schema_version=profile.get("schema_version", "unknown"),
        ).to_dict()
    return create_customer_profile(provisioning_status="unknown", provisioning_stage="unknown").to_dict()


def attach_license_to_customer(
    profile: CustomerProfileRecord | dict[str, Any] | None,
    license_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    customer = summarize_customer_profile(profile)
    license_data = _license_summary(license_summary)
    updated = deepcopy(customer)
    updated["license_id"] = license_data.get("license_id", customer.get("license_id", ""))
    updated["edition"] = license_data.get("edition", customer.get("edition", "unknown"))
    updated["expires_at"] = license_data.get("expires_at", customer.get("expires_at", ""))
    if not updated.get("assigned_features"):
        updated["assigned_features"] = list(license_data.get("features", []))
    if not updated.get("assigned_limits"):
        updated["assigned_limits"] = dict(license_data.get("limits", {}))
    updated["provisioning_stage"] = _advance_stage(customer.get("provisioning_stage"), "license_attached")
    return summarize_customer_profile(updated)


def attach_control_plane_to_customer(
    profile: CustomerProfileRecord | dict[str, Any] | None,
    control_plane_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    customer = summarize_customer_profile(profile)
    control_plane = summarize_control_plane(control_plane_summary)
    updated = deepcopy(customer)
    if control_plane.get("organization_id"):
        updated["organization_id"] = control_plane["organization_id"]
    if control_plane.get("deployment_id"):
        updated["deployment_id"] = control_plane["deployment_id"]
    updated["provisioning_stage"] = _advance_stage(customer.get("provisioning_stage"), "control_plane_attached")
    return summarize_customer_profile(updated)


def assign_customer_features(
    profile: CustomerProfileRecord | dict[str, Any] | None,
    features: Any,
) -> dict[str, Any]:
    customer = summarize_customer_profile(profile)
    updated = deepcopy(customer)
    updated["assigned_features"] = sorted(set(customer.get("assigned_features", [])) | set(_normalize_features(features)))
    updated["provisioning_stage"] = _advance_stage(customer.get("provisioning_stage"), "features_assigned")
    return summarize_customer_profile(updated)


def assign_customer_limits(
    profile: CustomerProfileRecord | dict[str, Any] | None,
    limits: Any,
) -> dict[str, Any]:
    customer = summarize_customer_profile(profile)
    updated = deepcopy(customer)
    merged = dict(customer.get("assigned_limits", {}))
    merged.update(_normalize_limits(limits))
    updated["assigned_limits"] = dict(sorted(merged.items()))
    updated["provisioning_stage"] = _advance_stage(customer.get("provisioning_stage"), "limits_assigned")
    return summarize_customer_profile(updated)


def validate_customer_profile(
    profile: CustomerProfileRecord | dict[str, Any] | None,
    *,
    license_summary: dict[str, Any] | None = None,
    control_plane_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    customer = summarize_customer_profile(profile)
    license_data = _license_summary(license_summary) if license_summary is not None else None
    control_plane = summarize_control_plane(control_plane_summary) if control_plane_summary is not None else None
    reasons: set[str] = set()

    missing_identifiers = [
        field
        for field in ("customer_id", "organization_id", "tenant_id", "deployment_id")
        if not customer.get(field)
    ]
    if missing_identifiers:
        reasons.add("missing required identifiers: " + ", ".join(missing_identifiers))

    invalid_status = customer["provisioning_status"] == "unknown"
    if invalid_status:
        reasons.add("provisioning status is invalid or unknown")

    invalid_stage = customer["provisioning_stage"] == "unknown"
    if invalid_stage:
        reasons.add("provisioning stage is invalid or unknown")

    missing_features = len(customer.get("assigned_features", [])) == 0
    if missing_features:
        reasons.add("assigned features are missing")

    missing_limits = len(customer.get("assigned_limits", {})) == 0
    if missing_limits:
        reasons.add("assigned limits are missing")

    expired_license = False
    license_customer_mismatch = False
    if license_data is not None:
        license_status = license_data.get("status", "unknown")
        expired_license = license_status == "expired"
        if expired_license:
            reasons.add("attached license is expired")
        if license_status in {"invalid", "missing", "unknown"}:
            reasons.add(f"attached license status is {license_status}")
        if customer.get("license_id") and license_data.get("license_id") and customer["license_id"] != license_data["license_id"]:
            license_customer_mismatch = True
        license_customer_id = _safe_text(license_data.get("metadata", {}).get("customer_id"))
        if license_customer_id and customer.get("customer_id") and license_customer_id != customer["customer_id"]:
            license_customer_mismatch = True
        if license_customer_mismatch:
            reasons.add("license/customer mismatch")

    control_plane_customer_mismatch = False
    if control_plane is not None:
        if customer.get("organization_id") and control_plane.get("organization_id") and customer["organization_id"] != control_plane["organization_id"]:
            control_plane_customer_mismatch = True
        if customer.get("deployment_id") and control_plane.get("deployment_id") and customer["deployment_id"] != control_plane["deployment_id"]:
            control_plane_customer_mismatch = True
        if control_plane_customer_mismatch:
            reasons.add("control-plane/customer mismatch")

    readiness = evaluate_customer_readiness(
        customer,
        license_summary=license_data,
        control_plane_summary=control_plane,
    )
    if readiness["readiness_status"] == "blocked":
        reasons.add("readiness is blocked")

    validation_status = _validation_status(
        missing_identifiers=bool(missing_identifiers),
        invalid_status=invalid_status,
        invalid_stage=invalid_stage,
        expired_license=expired_license,
        license_customer_mismatch=license_customer_mismatch,
        control_plane_customer_mismatch=control_plane_customer_mismatch,
        missing_features=missing_features,
        missing_limits=missing_limits,
        readiness_status=readiness["readiness_status"],
    )

    return {
        "record_type": "customer_provisioning_validation",
        "record_version": PROVISIONING_RECORD_VERSION,
        "customer_id": customer["customer_id"],
        "organization_id": customer["organization_id"],
        "tenant_id": customer["tenant_id"],
        "deployment_id": customer["deployment_id"],
        "validation_status": validation_status,
        "valid": validation_status == "valid",
        "validation_reasons": sorted(reasons) or ["customer provisioning profile is valid"],
        "missing_identifiers": missing_identifiers,
        "invalid_status": invalid_status,
        "invalid_stage": invalid_stage,
        "expired_license": expired_license,
        "license_customer_mismatch": license_customer_mismatch,
        "control_plane_customer_mismatch": control_plane_customer_mismatch,
        "missing_features": missing_features,
        "missing_limits": missing_limits,
        "readiness": readiness,
        "summary": customer,
        **PROVISIONING_SAFETY_FLAGS,
    }


def evaluate_customer_readiness(
    profile: CustomerProfileRecord | dict[str, Any] | None,
    *,
    license_summary: dict[str, Any] | None = None,
    control_plane_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    customer = summarize_customer_profile(profile)
    license_data = _license_summary(license_summary) if license_summary is not None else None
    control_plane = summarize_control_plane(control_plane_summary) if control_plane_summary is not None else None
    blockers: set[str] = set()

    if customer["provisioning_status"] in {"invalid", "suspended", "expired", "deprovisioned", "unknown"}:
        blockers.add(f"provisioning status is {customer['provisioning_status']}")
    if customer["provisioning_stage"] in {"blocked", "unknown"}:
        blockers.add(f"provisioning stage is {customer['provisioning_stage']}")
    if not customer.get("customer_id") or not customer.get("organization_id") or not customer.get("tenant_id") or not customer.get("deployment_id"):
        blockers.add("required identifiers are incomplete")
    if not customer.get("assigned_features"):
        blockers.add("assigned features are missing")
    if not customer.get("assigned_limits"):
        blockers.add("assigned limits are missing")
    if license_data is None:
        blockers.add("license is not attached")
    elif license_data.get("status") not in {"valid", "grace_period"}:
        blockers.add(f"license status is {license_data.get('status', 'unknown')}")
    if control_plane is None:
        blockers.add("control plane is not attached")
    elif control_plane.get("health_status") in {"unavailable", "unknown"}:
        blockers.add(f"control plane health is {control_plane.get('health_status', 'unknown')}")

    readiness_status = "blocked" if blockers else "ready"
    next_step = "review blockers before provisioning can continue" if blockers else "profile is ready for later operator-approved provisioning"
    return {
        "record_type": "customer_provisioning_readiness",
        "record_version": PROVISIONING_RECORD_VERSION,
        "customer_id": customer["customer_id"],
        "readiness_status": readiness_status,
        "readiness_ready": readiness_status == "ready",
        "readiness_blockers": sorted(blockers),
        "readiness_next_step": next_step,
        **PROVISIONING_SAFETY_FLAGS,
    }


def deterministic_customer_profile_json(profile: CustomerProfileRecord | dict[str, Any] | None) -> str:
    return json.dumps(summarize_customer_profile(profile), sort_keys=True, separators=(",", ":"))


def normalize_provisioning_status(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in PROVISIONING_STATUSES else "unknown"


def normalize_provisioning_stage(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in PROVISIONING_STAGES else "unknown"


def _license_summary(license_summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(license_summary, dict):
        return summarize_license(None)
    if license_summary.get("record_type") == "license_validation_summary":
        return deepcopy(license_summary)
    return summarize_license(license_summary)


def _advance_stage(current: Any, target: str) -> str:
    normalized = normalize_provisioning_stage(current)
    if PROVISIONING_STAGE_ORDER.get(normalized, 0) >= PROVISIONING_STAGE_ORDER.get(target, 0):
        return normalized
    return target


def _validation_status(
    *,
    missing_identifiers: bool,
    invalid_status: bool,
    invalid_stage: bool,
    expired_license: bool,
    license_customer_mismatch: bool,
    control_plane_customer_mismatch: bool,
    missing_features: bool,
    missing_limits: bool,
    readiness_status: str,
) -> str:
    if missing_identifiers or invalid_status or invalid_stage or license_customer_mismatch or control_plane_customer_mismatch:
        return "invalid"
    if expired_license or missing_features or missing_limits or readiness_status == "blocked":
        return "blocked"
    return "valid"


def _normalize_features(features: Any) -> list[str]:
    if isinstance(features, dict):
        values = [_safe_text(key) for key, value in features.items() if value]
    elif isinstance(features, (list, tuple, set)):
        values = [_safe_text(feature) for feature in features]
    elif isinstance(features, str):
        values = [_safe_text(features)]
    else:
        values = []
    return sorted({value for value in values if value})


def _normalize_limits(limits: Any) -> dict[str, Any]:
    if not isinstance(limits, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in sorted(limits.items(), key=lambda item: _safe_text(item[0])):
        safe_key = _safe_text(key)
        if safe_key:
            normalized[safe_key] = deepcopy(value)
    return normalized


def _normalize_mapping(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in sorted(metadata.items(), key=lambda item: _safe_text(item[0])):
        safe_key = _safe_text(key)
        if safe_key:
            normalized[safe_key] = deepcopy(value)
    return normalized


def _normalize_notes(notes: Any) -> list[str]:
    if isinstance(notes, str):
        values = [_safe_text(notes)]
    elif isinstance(notes, (list, tuple, set)):
        values = [_safe_text(note) for note in notes]
    else:
        values = []
    return sorted({value for value in values if value})


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())
