from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


PLUGIN_RECORD_VERSION = 1
SUPPORTED_PERMISSIONS = {"execute_local", "read_fixture", "read_metadata", "write_temp"}
SUPPORTED_OUTPUT_TYPES = {"json", "metadata", "text"}
VALID_LIFECYCLE_STATES = {"registered", "enabled", "disabled", "retired"}
MANIFEST_STATUS_SEVERITY = {
    "valid": "info",
    "invalid": "medium",
    "malformed": "high",
}
SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


class PluginManifestError(ValueError):
    """Raised when a plugin manifest cannot be normalized safely."""


def validate_plugin_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    errors = _manifest_errors(manifest)
    status = "valid" if not errors else "invalid"
    result = {
        "ok": not errors,
        "status": status,
        "classification": status,
        "record_version": PLUGIN_RECORD_VERSION,
        "diagnostic_type": "plugin_manifest",
        "plugin_id": _safe_plugin_id(manifest),
        "manifest_id": _manifest_id(manifest) if isinstance(manifest, dict) else "",
        "errors": errors,
        "warnings": _manifest_warnings(manifest) if isinstance(manifest, dict) else [],
        **SAFETY_FLAGS,
    }
    result["summary"] = summarize_manifest_result(result)
    result["integration_hooks"] = _integration_hooks(result)
    result["result_id"] = _stable_id("plugin-manifest", result["plugin_id"], result["classification"], result["manifest_id"])
    return result


def normalize_plugin_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    result = validate_plugin_manifest(manifest)
    if not result["ok"]:
        raise PluginManifestError("; ".join(result["errors"]))
    command = [str(item) for item in manifest["command"]]
    permissions = sorted({str(item) for item in manifest.get("permissions") or []})
    outputs = sorted({str(item) for item in manifest.get("outputs") or ["text"]})
    lifecycle_state = str(manifest.get("lifecycle_state") or "registered")
    return {
        "plugin_id": str(manifest["plugin_id"]).strip(),
        "name": str(manifest["name"]).strip(),
        "version": str(manifest["version"]).strip(),
        "description": str(manifest["description"]).strip(),
        "command": command,
        "capabilities": sorted({str(item) for item in manifest.get("capabilities") or []}),
        "permissions": permissions,
        "outputs": outputs,
        "lifecycle_state": lifecycle_state,
        "metadata": dict(manifest.get("metadata") or {}),
        "manifest_id": result["manifest_id"],
        "record_version": PLUGIN_RECORD_VERSION,
        **SAFETY_FLAGS,
    }


def summarize_manifest_result(result: dict[str, Any]) -> dict[str, Any]:
    classification = str(result.get("classification") or "invalid")
    errors = list(result.get("errors") or [])
    warnings = list(result.get("warnings") or [])
    return {
        "plugin_id": str(result.get("plugin_id") or ""),
        "manifest_id": str(result.get("manifest_id") or ""),
        "classification": classification,
        "severity": MANIFEST_STATUS_SEVERITY.get(classification, "medium"),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "recommended_review": bool(errors),
        **SAFETY_FLAGS,
    }


def build_manifest_event(
    result: dict[str, Any],
    *,
    source: str = "plugins.manifest",
    timestamp: str | None = None,
) -> dict[str, Any]:
    summary = summarize_manifest_result(result)
    severity = summary["severity"]
    event_type = "system_notice" if severity in {"info", "low"} else "policy_review_required"
    message = _operator_summary(summary)
    return {
        "event_id": _stable_id("evt", result.get("result_id"), event_type, message),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "timestamp": timestamp or _now(),
        "message": message,
        "asset_ref": None,
        "service_ref": None,
        "flow_ref": None,
        "snapshot_ref": None,
        "finding_ref": _stable_id("finding", result.get("result_id"), summary["classification"]),
        "metadata": {
            "diagnostic_type": "plugin_manifest",
            "plugin_id": summary["plugin_id"],
            "classification": summary["classification"],
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_manifest_finding(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_manifest_result(result)
    return {
        "finding_id": _stable_id("finding", result.get("result_id"), summary["classification"], summary["plugin_id"]),
        "finding_type": "plugin_manifest_result",
        "category": "plugin_registry",
        "severity": summary["severity"],
        "title": "Plugin Manifest Result",
        "summary": _operator_summary(summary),
        "evidence_refs": [f"plugin:{summary['plugin_id']}", f"manifest:{summary['manifest_id']}"],
        "recommended_review": summary["recommended_review"],
        "source_refs": [source_ref or f"plugin:{summary['plugin_id']}"],
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def build_manifest_storage_record(result: dict[str, Any], *, record_type: str = "plugin_manifest") -> dict[str, Any]:
    summary = summarize_manifest_result(result)
    return {
        "record_id": _stable_id("storage", result.get("result_id"), record_type, summary),
        "record_type": record_type,
        "summary": summary,
        "payload": {
            "status": result.get("status"),
            "classification": result.get("classification"),
            "plugin_id": result.get("plugin_id"),
            "manifest_id": result.get("manifest_id"),
            "errors": list(result.get("errors") or []),
            "warnings": list(result.get("warnings") or []),
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def _manifest_errors(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manifest must be an object"]
    errors: list[str] = []
    for field in ("plugin_id", "name", "version", "description"):
        if not isinstance(manifest.get(field), str) or not manifest.get(field, "").strip():
            errors.append(f"{field} must be a non-empty string")
    command = manifest.get("command")
    if not isinstance(command, list) or not command:
        errors.append("command must be a non-empty list")
    elif any(not isinstance(item, str) or not item.strip() for item in command):
        errors.append("command entries must be non-empty strings")
    _list_errors(errors, manifest, "capabilities", allow_empty=True)
    permissions = _list_errors(errors, manifest, "permissions", allow_empty=True)
    outputs = _list_errors(errors, manifest, "outputs", allow_empty=True)
    unsupported_permissions = sorted(set(permissions) - SUPPORTED_PERMISSIONS)
    unsupported_outputs = sorted(set(outputs) - SUPPORTED_OUTPUT_TYPES)
    if unsupported_permissions:
        errors.append(f"permissions contain unsupported values: {', '.join(unsupported_permissions)}")
    if unsupported_outputs:
        errors.append(f"outputs contain unsupported values: {', '.join(unsupported_outputs)}")
    lifecycle_state = manifest.get("lifecycle_state", "registered")
    if lifecycle_state not in VALID_LIFECYCLE_STATES:
        errors.append(f"lifecycle_state must be one of {', '.join(sorted(VALID_LIFECYCLE_STATES))}")
    if not isinstance(manifest.get("metadata", {}), dict):
        errors.append("metadata must be an object")
    return errors


def _manifest_warnings(manifest: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if "execute_local" not in set(manifest.get("permissions") or []):
        warnings.append("manifest does not request execute_local permission")
    if not manifest.get("capabilities"):
        warnings.append("manifest declares no capabilities")
    return warnings


def _list_errors(errors: list[str], manifest: dict[str, Any], field: str, *, allow_empty: bool) -> list[str]:
    value = manifest.get(field, [])
    if value is None:
        value = []
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []
    if not allow_empty and not value:
        errors.append(f"{field} must not be empty")
    rows: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field} entries must be non-empty strings")
            continue
        rows.append(item.strip())
    return rows


def _safe_plugin_id(manifest: Any) -> str:
    if not isinstance(manifest, dict):
        return ""
    value = manifest.get("plugin_id")
    return str(value).strip() if isinstance(value, str) else ""


def _manifest_id(manifest: dict[str, Any]) -> str:
    material = {
        "plugin_id": manifest.get("plugin_id"),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "command": manifest.get("command"),
        "capabilities": manifest.get("capabilities"),
        "permissions": manifest.get("permissions"),
    }
    return _stable_id("manifest", material)


def _integration_hooks(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "event_pipeline_ready": True,
        "storage_ready": True,
        "scheduler_ready": True,
        "dashboard_ready": True,
        "policy_review_ready": result.get("classification") != "valid",
        "timeline_ready": True,
        "correlation_ready": True,
    }


def _operator_summary(summary: dict[str, Any]) -> str:
    plugin_id = str(summary.get("plugin_id") or "unknown-plugin")
    classification = str(summary.get("classification") or "unknown")
    if classification == "valid":
        return f"Plugin manifest {plugin_id} validated for local registry use."
    return f"Plugin manifest {plugin_id} classified as {classification} for operator review."


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
