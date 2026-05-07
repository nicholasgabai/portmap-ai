from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from core_engine.config_loader import (
    APP_ROOT,
    DATA_DIR,
    DEFAULT_SETTINGS_FILE,
    LOG_DIR,
    ensure_runtime_dirs,
    get_default_export_dir,
    get_default_orchestrator_token,
    get_default_orchestrator_url,
    load_settings,
    save_settings,
)
from core_engine.stack_launcher import DEFAULT_MASTER_CFG, DEFAULT_ORCHESTRATOR_CFG, DEFAULT_WORKER_CFG


def platform_support_status(system: str | None = None, machine: str | None = None) -> dict[str, str]:
    system = system or platform.system()
    machine = machine or platform.machine()
    normalized = system.lower()
    arch = machine.lower()

    if normalized == "darwin":
        level = "supported"
        notes = "macOS local development and CLI/TUI operation"
    elif normalized == "linux":
        level = "supported"
        if arch in {"aarch64", "arm64", "armv7l", "armv6l"}:
            notes = "Linux ARM supported through the same local install path; Raspberry Pi OS uses systemd service templates"
        else:
            notes = "Linux local install, service, and server operation"
    elif normalized == "windows":
        level = "experimental"
        notes = "Windows scripts exist, but native service packaging remains a future phase"
    else:
        level = "unknown"
        notes = "Untested OS; use Python packaging path only after validation"

    return {
        "system": system,
        "machine": machine,
        "level": level,
        "notes": notes,
    }


def runtime_paths() -> dict[str, str]:
    return {
        "app_root": str(APP_ROOT),
        "data_dir": str(DATA_DIR),
        "log_dir": str(LOG_DIR),
        "settings_file": str(DEFAULT_SETTINGS_FILE),
        "export_dir": get_default_export_dir(),
    }


def default_runtime_settings() -> dict[str, Any]:
    return {
        "enable_autolearn": False,
        "remediation_mode": "prompt",
        "remediation_threshold": 0.75,
        "orchestrator_url": get_default_orchestrator_url(),
        "orchestrator_token": get_default_orchestrator_token(),
        "export_dir": get_default_export_dir(),
        "expected_services": [],
        "log_max_bytes": 5 * 1024 * 1024,
        "log_backup_count": 5,
        "tls": {
            "enabled": False,
            "verify": True,
            "require_client_auth": False,
        },
    }


def initialize_runtime(*, force: bool = False) -> dict[str, Any]:
    ensure_runtime_dirs()
    settings = default_runtime_settings()
    existing = load_settings(defaults={})
    if existing and not force:
        settings = {**settings, **existing}
        created_settings = False
    else:
        created_settings = True
    save_settings(settings)
    export_dir = Path(str(settings.get("export_dir") or get_default_export_dir())).expanduser()
    export_dir.mkdir(parents=True, exist_ok=True)

    return {
        "paths": runtime_paths(),
        "settings_file_created": created_settings,
        "settings": settings,
        "next_steps": [
            "portmap doctor",
            "portmap stack --verbose",
            "portmap tui",
        ],
    }


def packaging_diagnostics() -> dict[str, Any]:
    support = platform_support_status()
    checks = []

    py_ok = sys.version_info >= (3, 11)
    checks.append({
        "name": "python_version",
        "ok": py_ok,
        "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    })

    for name, path in {
        "orchestrator_config": DEFAULT_ORCHESTRATOR_CFG,
        "master_config": DEFAULT_MASTER_CFG,
        "worker_config": DEFAULT_WORKER_CFG,
    }.items():
        checks.append({"name": name, "ok": Path(path).exists(), "detail": path})

    for command in ("portmap", "portmap-orchestrator", "portmap-master", "portmap-worker"):
        checks.append({"name": f"command:{command}", "ok": shutil.which(command) is not None, "detail": command})

    service_manager = "systemd" if support["system"].lower() == "linux" else "manual"
    if support["system"].lower() == "darwin":
        service_manager = "launchd_future"
    elif support["system"].lower() == "windows":
        service_manager = "windows_service_future"

    return {
        "platform": support,
        "runtime_paths": runtime_paths(),
        "service_manager": service_manager,
        "checks": checks,
        "ok": all(item["ok"] for item in checks if not item["name"].startswith("command:")),
    }
