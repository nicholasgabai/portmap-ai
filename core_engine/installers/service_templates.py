from __future__ import annotations

import re
import shlex
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


SERVICE_TEMPLATE_RECORD_VERSION = 1
SUPPORTED_PLATFORMS = {"systemd", "windows"}
VALID_CLASSIFICATIONS = {"valid", "invalid", "unsupported"}
CLASSIFICATION_SEVERITY = {
    "valid": "info",
    "invalid": "medium",
    "unsupported": "high",
}
SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
    "dry_run": True,
    "install_executed": False,
    "service_enabled": False,
    "service_started": False,
    "privilege_escalation": False,
}


def validate_service_definition(definition: dict[str, Any]) -> dict[str, Any]:
    errors = _definition_errors(definition)
    classification = "valid" if not errors else "invalid"
    result = {
        "ok": not errors,
        "status": classification,
        "classification": classification,
        "record_version": SERVICE_TEMPLATE_RECORD_VERSION,
        "diagnostic_type": "service_lifecycle_template",
        "service_id": _safe_string(definition.get("service_id")) if isinstance(definition, dict) else "",
        "errors": errors,
        "warnings": _definition_warnings(definition) if isinstance(definition, dict) else [],
        **SAFETY_FLAGS,
    }
    result["summary"] = summarize_service_template_result(result)
    result["integration_hooks"] = _integration_hooks(result)
    result["result_id"] = _stable_id("service-template", result["service_id"], result["classification"], result["errors"])
    return result


def generate_systemd_unit(definition: dict[str, Any]) -> dict[str, Any]:
    validation = validate_service_definition(definition)
    if not validation["ok"]:
        return _template_result("systemd", definition, validation, "")
    command = " ".join(_systemd_quote(str(part)) for part in definition["command"])
    lines = [
        "[Unit]",
        f"Description={_safe_string(definition['description'])}",
        "After=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={command}",
        "Restart=on-failure",
        "RestartSec=5",
    ]
    working_directory = _safe_string(definition.get("working_directory"))
    environment_file = _safe_string(definition.get("environment_file"))
    user = _safe_string(definition.get("user"))
    if working_directory:
        lines.append(f"WorkingDirectory={working_directory}")
    if environment_file:
        lines.append(f"EnvironmentFile={environment_file}")
    if user:
        lines.append(f"User={user}")
    lines.extend(
        [
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]
    )
    return _template_result("systemd", definition, validation, "\n".join(lines))


def generate_windows_service_template(definition: dict[str, Any]) -> dict[str, Any]:
    validation = validate_service_definition(definition)
    if not validation["ok"]:
        return _template_result("windows", definition, validation, "")
    command = " ".join(_windows_quote(str(part)) for part in definition["command"])
    service_name = _safe_string(definition["name"])
    display_name = _safe_string(definition.get("display_name") or definition["name"])
    description = _safe_string(definition["description"])
    lines = [
        "REM Dry-run service template. Review before operator execution.",
        f'sc.exe create "{service_name}" binPath= "{command}" start= demand DisplayName= "{display_name}"',
        f'sc.exe description "{service_name}" "{description}"',
        "REM No service installation, enable, or start action was executed by PortMap-AI.",
        "",
    ]
    environment_file = _safe_string(definition.get("environment_file"))
    if environment_file:
        lines.insert(1, f"REM Optional environment file placeholder: {environment_file}")
    return _template_result("windows", definition, validation, "\r\n".join(lines))


def generate_service_templates(
    definition: dict[str, Any],
    *,
    platforms: list[str] | None = None,
) -> dict[str, Any]:
    requested = platforms or ["systemd", "windows"]
    unsupported = sorted(set(requested) - SUPPORTED_PLATFORMS)
    templates: dict[str, dict[str, Any]] = {}
    errors = [f"unsupported platform {platform}" for platform in unsupported]
    for platform in requested:
        if platform == "systemd":
            templates[platform] = generate_systemd_unit(definition)
        elif platform == "windows":
            templates[platform] = generate_windows_service_template(definition)
    validation = validate_service_definition(definition)
    classification = "unsupported" if unsupported else validation["classification"]
    result = {
        "ok": not errors and validation["ok"],
        "status": classification,
        "classification": classification,
        "record_version": SERVICE_TEMPLATE_RECORD_VERSION,
        "diagnostic_type": "service_lifecycle_template",
        "service_id": validation.get("service_id"),
        "platforms": requested,
        "templates": templates,
        "errors": [*validation.get("errors", []), *errors],
        "warnings": validation.get("warnings", []),
        **SAFETY_FLAGS,
    }
    result["summary"] = summarize_service_template_result(result)
    result["integration_hooks"] = _integration_hooks(result)
    result["result_id"] = _stable_id("service-template", result["service_id"], requested, result["classification"], result["errors"])
    return result


def summarize_service_template_result(result: dict[str, Any]) -> dict[str, Any]:
    classification = str(result.get("classification") or "invalid")
    templates = result.get("templates") or {}
    return {
        "service_id": str(result.get("service_id") or ""),
        "classification": classification,
        "severity": CLASSIFICATION_SEVERITY.get(classification, "medium"),
        "platform_count": len(templates),
        "template_count": sum(1 for item in templates.values() if isinstance(item, dict) and item.get("template_text")),
        "error_count": len(result.get("errors") or []),
        "warning_count": len(result.get("warnings") or []),
        "recommended_review": classification != "valid",
        **SAFETY_FLAGS,
    }


def build_service_template_event(
    result: dict[str, Any],
    *,
    source: str = "installers.service_templates",
    timestamp: str | None = None,
) -> dict[str, Any]:
    summary = summarize_service_template_result(result)
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
        "service_ref": f"service-template:{summary['service_id']}",
        "flow_ref": None,
        "snapshot_ref": None,
        "finding_ref": _stable_id("finding", result.get("result_id"), summary["classification"]),
        "metadata": {
            "diagnostic_type": "service_lifecycle_template",
            "classification": summary["classification"],
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_service_template_finding(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_service_template_result(result)
    return {
        "finding_id": _stable_id("finding", result.get("result_id"), summary["classification"], summary["service_id"]),
        "finding_type": "service_template_result",
        "category": "service_lifecycle_template",
        "severity": summary["severity"],
        "title": "Service Template Result",
        "summary": _operator_summary(summary),
        "evidence_refs": [f"service-template:{summary['service_id']}", f"templates:{summary['template_count']}"],
        "recommended_review": summary["recommended_review"],
        "source_refs": [source_ref or f"service-template:{summary['service_id']}"],
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def build_service_template_storage_record(result: dict[str, Any], *, record_type: str = "service_lifecycle_template") -> dict[str, Any]:
    summary = summarize_service_template_result(result)
    return {
        "record_id": _stable_id("storage", result.get("result_id"), record_type, summary),
        "record_type": record_type,
        "summary": summary,
        "payload": {
            "status": result.get("status"),
            "classification": result.get("classification"),
            "service_id": result.get("service_id"),
            "platforms": list(result.get("platforms") or []),
            "template_summaries": {
                platform: {
                    "template_id": item.get("template_id"),
                    "line_count": item.get("line_count"),
                    "template_length": item.get("template_length"),
                }
                for platform, item in (result.get("templates") or {}).items()
                if isinstance(item, dict)
            },
            "errors": list(result.get("errors") or []),
            "warnings": list(result.get("warnings") or []),
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_service_template_timeline_entry(
    result: dict[str, Any],
    *,
    timestamp: str | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    summary = summarize_service_template_result(result)
    text = _operator_summary(summary)
    return {
        "timeline_id": _stable_id("timeline", result.get("result_id"), text),
        "timestamp": timestamp or _now(),
        "category": "service_lifecycle_template",
        "severity": summary["severity"],
        "title": "Service Lifecycle Template",
        "summary": text,
        "asset_ref": None,
        "service_ref": f"service-template:{summary['service_id']}",
        "snapshot_ref": None,
        "source_refs": [source_ref or f"service-template:{summary['service_id']}"],
        "recommended_review": summary["recommended_review"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_service_template_dashboard_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = summarize_service_template_result(result)
    return {
        "panel": "service_lifecycle_template",
        "status": summary["classification"],
        "service_id": summary["service_id"],
        "template_count": summary["template_count"],
        "recommended_review": summary["recommended_review"],
        "install_executed": False,
        "service_enabled": False,
        "service_started": False,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_service_template_correlation_record(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    finding = build_service_template_finding(result, source_ref=source_ref)
    classification = str(result.get("classification") or "invalid")
    score = {"valid": 0.0, "invalid": 0.35, "unsupported": 0.6}.get(classification, 0.4)
    return {
        **finding,
        "correlation_key": f"service_lifecycle_template:{finding['category']}:{finding['severity']}",
        "score": score,
        "confidence": 0.9 if classification == "valid" else 0.75,
    }


def _template_result(platform: str, definition: dict[str, Any], validation: dict[str, Any], template_text: str) -> dict[str, Any]:
    service_id = validation.get("service_id") or _safe_string(definition.get("service_id")) if isinstance(definition, dict) else ""
    return {
        "ok": validation["ok"],
        "status": validation["classification"],
        "classification": validation["classification"],
        "platform": platform,
        "service_id": service_id,
        "template_id": _stable_id("template", platform, service_id, template_text),
        "template_text": template_text,
        "template_length": len(template_text),
        "line_count": len(template_text.splitlines()) if template_text else 0,
        "errors": list(validation.get("errors") or []),
        "warnings": list(validation.get("warnings") or []),
        **SAFETY_FLAGS,
    }


def _definition_errors(definition: Any) -> list[str]:
    if not isinstance(definition, dict):
        return ["service definition must be an object"]
    errors: list[str] = []
    for field in ("service_id", "name", "description"):
        if not _safe_string(definition.get(field)):
            errors.append(f"{field} must be a non-empty string")
    command = definition.get("command")
    if not isinstance(command, list) or not command:
        errors.append("command must be a non-empty list")
    elif any(not _safe_string(part) for part in command):
        errors.append("command entries must be non-empty strings")
    for path_field in ("working_directory", "environment_file"):
        value = definition.get(path_field)
        if value is not None and not _valid_path_value(value):
            errors.append(f"{path_field} must be a placeholder or operator-provided path string")
    if definition.get("user") is not None and not _safe_string(definition.get("user")):
        errors.append("user must be a non-empty string when provided")
    if definition.get("metadata") is not None and not isinstance(definition.get("metadata"), dict):
        errors.append("metadata must be an object when provided")
    return errors


def _definition_warnings(definition: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if not definition.get("environment_file"):
        warnings.append("environment_file is not configured")
    if _path_mode(definition.get("working_directory")) == "operator_provided":
        warnings.append("working_directory should be reviewed by the operator before use")
    if _path_mode(definition.get("environment_file")) == "operator_provided":
        warnings.append("environment_file should be reviewed by the operator before use")
    return warnings


def _valid_path_value(value: Any) -> bool:
    text = _safe_string(value)
    if not text:
        return False
    return "\n" not in text and "\r" not in text and "\x00" not in text


def _path_mode(value: Any) -> str:
    text = _safe_string(value)
    if not text:
        return "unset"
    if re.fullmatch(r"<[A-Za-z0-9_.:-]+>", text):
        return "placeholder"
    return "operator_provided"


def _safe_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if "\n" in text or "\r" in text or "\x00" in text:
        return ""
    return text


def _windows_quote(value: str) -> str:
    escaped = value.replace('"', r"\"")
    return f'"{escaped}"' if " " in escaped or "<" in escaped or ">" in escaped else escaped


def _systemd_quote(value: str) -> str:
    if re.fullmatch(r"<[A-Za-z0-9_.:-]+>", value):
        return value
    return shlex.quote(value)


def _integration_hooks(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "event_pipeline_ready": True,
        "storage_ready": True,
        "runtime_ready": True,
        "dashboard_ready": True,
        "policy_review_ready": result.get("classification") != "valid",
        "timeline_ready": True,
        "correlation_ready": True,
    }


def _operator_summary(summary: dict[str, Any]) -> str:
    service_id = str(summary.get("service_id") or "unknown-service")
    classification = str(summary.get("classification") or "unknown")
    count = int(summary.get("template_count") or 0)
    if classification == "valid":
        return f"Service lifecycle templates generated for {service_id} with {count} dry-run templates."
    return f"Service lifecycle template request for {service_id} classified as {classification} for operator review."


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
