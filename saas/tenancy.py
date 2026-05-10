from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,126}[A-Za-z0-9]$")
VALID_TENANT_STATUS = {"active", "suspended", "archived"}
VALID_WORKSPACE_MODES = {"local", "cloud_optional", "cloud_sync"}


@dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    name: str
    status: str = "active"
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "status": self.status,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class WorkspaceConfig:
    workspace_id: str
    tenant_id: str
    org_id: str
    name: str
    environment: str = "local"
    sync_mode: str = "local"
    settings: dict[str, Any] = field(default_factory=dict)
    updated_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "tenant_id": self.tenant_id,
            "org_id": self.org_id,
            "name": self.name,
            "environment": self.environment,
            "sync_mode": self.sync_mode,
            "settings": dict(self.settings),
            "updated_at": self.updated_at,
        }


def validate_tenant_record(record: TenantRecord | dict[str, Any]) -> list[str]:
    data = record.to_dict() if isinstance(record, TenantRecord) else record
    if not isinstance(data, dict):
        return ["tenant record must be an object"]
    errors: list[str] = []
    errors.extend(_validate_id("tenant_id", data.get("tenant_id")))
    if not isinstance(data.get("name"), str) or not data.get("name", "").strip():
        errors.append("tenant name must be a non-empty string")
    if data.get("status", "active") not in VALID_TENANT_STATUS:
        errors.append(f"tenant status must be one of: {', '.join(sorted(VALID_TENANT_STATUS))}")
    if not isinstance(data.get("metadata", {}), dict):
        errors.append("tenant metadata must be an object")
    return errors


def validate_workspace_config(config: WorkspaceConfig | dict[str, Any]) -> list[str]:
    data = config.to_dict() if isinstance(config, WorkspaceConfig) else config
    if not isinstance(data, dict):
        return ["workspace config must be an object"]
    errors: list[str] = []
    errors.extend(_validate_id("workspace_id", data.get("workspace_id")))
    errors.extend(_validate_id("tenant_id", data.get("tenant_id")))
    errors.extend(_validate_id("org_id", data.get("org_id")))
    if not isinstance(data.get("name"), str) or not data.get("name", "").strip():
        errors.append("workspace name must be a non-empty string")
    if not isinstance(data.get("environment", ""), str) or not data.get("environment"):
        errors.append("workspace environment must be a non-empty string")
    if data.get("sync_mode", "local") not in VALID_WORKSPACE_MODES:
        errors.append(f"sync_mode must be one of: {', '.join(sorted(VALID_WORKSPACE_MODES))}")
    if not isinstance(data.get("settings", {}), dict):
        errors.append("workspace settings must be an object")
    return errors


def save_workspace_config(config: WorkspaceConfig | dict[str, Any], path: Path | str) -> dict[str, Any]:
    data = config.to_dict() if isinstance(config, WorkspaceConfig) else dict(config)
    errors = validate_workspace_config(data)
    if errors:
        raise ValueError("; ".join(errors))
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(data, indent=2, sort_keys=True))
    return {
        "ok": True,
        "path": str(destination),
        "workspace_id": data["workspace_id"],
        "tenant_id": data["tenant_id"],
        "local_only": data.get("sync_mode") == "local",
    }


def load_workspace_config(path: Path | str) -> WorkspaceConfig:
    data = json.loads(Path(path).read_text())
    errors = validate_workspace_config(data)
    if errors:
        raise ValueError("; ".join(errors))
    return WorkspaceConfig(
        workspace_id=data["workspace_id"],
        tenant_id=data["tenant_id"],
        org_id=data["org_id"],
        name=data["name"],
        environment=data.get("environment", "local"),
        sync_mode=data.get("sync_mode", "local"),
        settings=data.get("settings") or {},
        updated_at=int(data.get("updated_at") or time.time()),
    )


def same_tenant(*records: dict[str, Any]) -> bool:
    tenant_ids = {str(record.get("tenant_id") or "") for record in records if record}
    return len(tenant_ids) <= 1 and "" not in tenant_ids


def _validate_id(name: str, value: Any) -> list[str]:
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        return [f"{name} must be 3-128 characters using letters, numbers, dot, underscore, colon, or dash"]
    return []


__all__ = [
    "ID_PATTERN",
    "VALID_TENANT_STATUS",
    "VALID_WORKSPACE_MODES",
    "TenantRecord",
    "WorkspaceConfig",
    "load_workspace_config",
    "same_tenant",
    "save_workspace_config",
    "validate_tenant_record",
    "validate_workspace_config",
]
