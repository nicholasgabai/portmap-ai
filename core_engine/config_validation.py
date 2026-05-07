"""Configuration validation helpers for PortMap-AI."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable
from urllib.parse import urlparse

from core_engine.config_loader import load_node_config

VALID_ROLES = {"orchestrator", "master", "worker"}
VALID_REMEDIATION_MODES = {"prompt", "silent"}


@dataclass
class ValidationResult:
    path: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_int(value: Any) -> int | None:
    if _is_int(value):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _validate_port(result: ValidationResult, config: Dict[str, Any], key: str) -> None:
    if key not in config or config.get(key) is None:
        return
    value = _parse_int(config.get(key))
    if value is None:
        result.add_error(f"{key} must be an integer")
        return
    if not 1 <= value <= 65535:
        result.add_error(f"{key} must be between 1 and 65535")


def _validate_positive_int(result: ValidationResult, config: Dict[str, Any], key: str) -> None:
    if key not in config or config.get(key) is None:
        return
    value = _parse_int(config.get(key))
    if value is None:
        result.add_error(f"{key} must be an integer")
        return
    if value <= 0:
        result.add_error(f"{key} must be greater than 0")


def _validate_nonnegative_int(result: ValidationResult, config: Dict[str, Any], key: str) -> None:
    if key not in config or config.get(key) is None:
        return
    value = _parse_int(config.get(key))
    if value is None:
        result.add_error(f"{key} must be an integer")
        return
    if value < 0:
        result.add_error(f"{key} must be 0 or greater")


def _validate_host(result: ValidationResult, config: Dict[str, Any], key: str) -> None:
    if key not in config or config.get(key) is None:
        return
    value = config.get(key)
    if not isinstance(value, str) or not value.strip():
        result.add_error(f"{key} must be a non-empty string")


def _validate_bool(result: ValidationResult, config: Dict[str, Any], key: str, prefix: str = "") -> None:
    if key not in config:
        return
    if not isinstance(config.get(key), bool):
        result.add_error(f"{prefix}{key} must be a boolean")


def _role_from_config(config: Dict[str, Any], result: ValidationResult) -> str | None:
    role = config.get("node_role")
    legacy_mode = config.get("mode")
    if role is None and legacy_mode is not None:
        role = legacy_mode
        result.add_warning("mode is a legacy key; prefer node_role")
    if not isinstance(role, str) or not role:
        result.add_error("node_role is required")
        return None
    role = role.lower()
    if role not in VALID_ROLES:
        result.add_error(f"node_role must be one of: {', '.join(sorted(VALID_ROLES))}")
        return None
    return role


def _validate_url(result: ValidationResult, config: Dict[str, Any], key: str) -> None:
    if key not in config or config.get(key) in {None, ""}:
        return
    value = config.get(key)
    if not isinstance(value, str):
        result.add_error(f"{key} must be a URL string")
        return
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        result.add_error(f"{key} must be an http(s) URL")


def _validate_string_list(result: ValidationResult, config: Dict[str, Any], key: str) -> None:
    if key not in config:
        return
    value = config.get(key)
    if not isinstance(value, list):
        result.add_error(f"{key} must be a list")
        return
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            result.add_error(f"{key}[{index}] must be a non-empty string")


def _validate_tls(result: ValidationResult, settings: Dict[str, Any], config: Dict[str, Any]) -> None:
    tls = settings.get("tls") if isinstance(settings.get("tls"), dict) else {}
    node_tls = config.get("tls") if isinstance(config.get("tls"), dict) else {}
    merged = {**tls, **node_tls}
    if not merged:
        return
    for key in ("enabled", "verify", "require_client_auth"):
        _validate_bool(result, merged, key, prefix="tls.")
    for key in ("certfile", "keyfile", "cafile", "server_hostname"):
        if key in merged and merged.get(key) is not None and not isinstance(merged.get(key), str):
            result.add_error(f"tls.{key} must be a string")


def _validate_firewall(result: ValidationResult, settings: Dict[str, Any]) -> None:
    firewall = settings.get("firewall")
    if firewall is None:
        return
    if not isinstance(firewall, dict):
        result.add_error("firewall must be an object")
        return
    plugin = firewall.get("plugin")
    if plugin is not None and (not isinstance(plugin, str) or not plugin.strip()):
        result.add_error("firewall.plugin must be a non-empty string")
    if "dry_run" in firewall and not isinstance(firewall.get("dry_run"), bool):
        result.add_error("firewall.dry_run must be a boolean")
    options = firewall.get("options")
    if options is not None and not isinstance(options, dict):
        result.add_error("firewall.options must be an object")
    if isinstance(options, dict) and "dry_run" in options and not isinstance(options.get("dry_run"), bool):
        result.add_error("firewall.options.dry_run must be a boolean")


def _validate_remediation_safety(result: ValidationResult, settings: Dict[str, Any]) -> None:
    safety = settings.get("remediation_safety")
    if safety is None:
        return
    if not isinstance(safety, dict):
        result.add_error("remediation_safety must be an object")
        return
    for key in ("active_enforcement_enabled", "require_confirmation"):
        if key in safety and not isinstance(safety.get(key), bool):
            result.add_error(f"remediation_safety.{key} must be a boolean")
    token = safety.get("confirmation_token")
    if token is not None and not isinstance(token, str):
        result.add_error("remediation_safety.confirmation_token must be a string")


def _validate_expected_services(result: ValidationResult, settings: Dict[str, Any]) -> None:
    expected = settings.get("expected_services")
    if expected is None:
        return
    if not isinstance(expected, list):
        result.add_error("expected_services must be a list")
        return
    for index, service in enumerate(expected):
        if not isinstance(service, dict):
            result.add_error(f"expected_services[{index}] must be an object")
            continue
        _validate_port(result, service, "port")
        for key in ("protocol", "program", "reason"):
            if key in service and service.get(key) is not None and not isinstance(service.get(key), str):
                result.add_error(f"expected_services[{index}].{key} must be a string")


def _validate_auth(result: ValidationResult, config: Dict[str, Any], settings: Dict[str, Any], role: str | None) -> None:
    auth_token = config.get("auth_token")
    if auth_token is not None and not isinstance(auth_token, str):
        result.add_error("auth_token must be a string")
    orchestrator_token = settings.get("orchestrator_token")
    if orchestrator_token is not None and not isinstance(orchestrator_token, str):
        result.add_error("orchestrator_token must be a string")
    node_token = config.get("orchestrator_token")
    if node_token is not None and not isinstance(node_token, str):
        result.add_error("orchestrator_token must be a string")

    effective = auth_token or orchestrator_token if role == "orchestrator" else node_token or orchestrator_token
    if isinstance(effective, str):
        if not effective:
            result.add_warning("orchestrator token is empty; API auth is disabled or node auth will fail")
        elif effective in {"test-token", "portmap-dev-token"}:
            result.add_warning("default development orchestrator token is configured; replace it before remote or shared deployments")
        elif len(effective) < 12:
            result.add_warning("orchestrator token is short; use a longer random value for shared or remote deployments")


def validate_config(
    config: Dict[str, Any],
    settings: Dict[str, Any] | None = None,
    path: str | None = None,
    expected_role: str | None = None,
) -> ValidationResult:
    settings = settings or {}
    result = ValidationResult(path=path)
    role = _role_from_config(config, result)
    if expected_role:
        expected_role = expected_role.lower()
        if expected_role not in VALID_ROLES:
            result.add_error(f"expected_role must be one of: {', '.join(sorted(VALID_ROLES))}")
        elif role and role != expected_role:
            result.add_error(f"expected node_role {expected_role}, got {role}")

    for key in ("port", "listen_port"):
        _validate_port(result, config, key)
    _validate_nonnegative_int(result, config, "scan_interval")
    _validate_nonnegative_int(result, config, "node_stale_after")
    for key in ("timeout",):
        _validate_positive_int(result, config, key)
    for key in ("log_max_bytes", "log_backup_count"):
        _validate_nonnegative_int(result, config, key)
    for key in ("master_ip", "bind_ip", "listen_ip"):
        _validate_host(result, config, key)
    for key in ("orchestrator_url",):
        _validate_url(result, config, key)
    _validate_string_list(result, config, "accepted_nodes")
    _validate_string_list(result, config, "features")

    if role == "worker":
        if "node_id" not in config and "worker_id" in config:
            result.add_warning("worker_id is a legacy key; prefer node_id")
        if not config.get("node_id") and not config.get("worker_id"):
            result.add_error("worker configs require node_id")
        if config.get("master_ip") is None:
            result.add_warning("worker master_ip is empty; config is standalone/offline only")
        if config.get("port") is None:
            result.add_warning("worker port is empty; config is standalone/offline only")
    elif role == "master":
        if "listen_port" in config and "port" not in config:
            result.add_warning("listen_port is a legacy key; prefer port")
        if "listen_ip" in config and "master_ip" not in config:
            result.add_warning("listen_ip is a legacy key; prefer master_ip")
    elif role == "orchestrator":
        if not config.get("auth_token") and not settings.get("orchestrator_token"):
            result.add_warning("orchestrator auth token is empty; API will run without bearer auth")

    remediation_mode = settings.get("remediation_mode")
    if remediation_mode is not None and remediation_mode not in VALID_REMEDIATION_MODES:
        result.add_error("remediation_mode must be prompt or silent")
    threshold = settings.get("remediation_threshold")
    if threshold is not None:
        try:
            threshold_value = float(threshold)
        except (TypeError, ValueError):
            threshold_value = None
        if threshold_value is None or isinstance(threshold, bool):
            result.add_error("remediation_threshold must be a number")
        elif not 0 <= threshold_value <= 1:
            result.add_error("remediation_threshold must be between 0 and 1")

    for key in ("log_max_bytes", "log_backup_count"):
        _validate_nonnegative_int(result, settings, key)
    _validate_url(result, settings, "orchestrator_url")
    if "export_dir" in settings and not isinstance(settings.get("export_dir"), str):
        result.add_error("export_dir must be a string")
    _validate_tls(result, settings, config)
    _validate_firewall(result, settings)
    _validate_remediation_safety(result, settings)
    _validate_expected_services(result, settings)
    _validate_auth(result, config, settings, role)
    return result


def require_valid_config(
    config: Dict[str, Any],
    settings: Dict[str, Any] | None = None,
    *,
    path: str | None = None,
    expected_role: str | None = None,
) -> ValidationResult:
    result = validate_config(config, settings, path=path, expected_role=expected_role)
    if not result.ok:
        raise ValueError(format_validation_result(result))
    return result


def validate_config_file(
    path: str,
    *,
    profile: str | None = None,
    include_settings: bool = True,
    expected_role: str | None = None,
) -> ValidationResult:
    try:
        config, settings = load_node_config(path, defaults={}, include_settings=include_settings, profile=profile)
    except Exception as exc:
        return ValidationResult(path=path, errors=[str(exc)])
    return validate_config(config, settings, path=path, expected_role=expected_role)


def validate_config_files(
    paths: Iterable[str],
    *,
    profile: str | None = None,
    expected_role: str | None = None,
) -> list[ValidationResult]:
    return [
        validate_config_file(str(Path(path)), profile=profile, expected_role=expected_role)
        for path in paths
    ]


def format_validation_result(result: ValidationResult) -> str:
    label = result.path or "<config>"
    status = "OK" if result.ok else "ERROR"
    lines = [f"{status} {label}"]
    for message in result.errors:
        lines.append(f"  error: {message}")
    for message in result.warnings:
        lines.append(f"  warning: {message}")
    return "\n".join(lines)
