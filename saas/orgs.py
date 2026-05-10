from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.rbac import normalize_roles, permissions_for_roles, validate_roles
from saas.tenancy import same_tenant, validate_tenant_record


@dataclass(frozen=True)
class OrganizationRecord:
    org_id: str
    tenant_id: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class TeamRecord:
    team_id: str
    tenant_id: str
    org_id: str
    name: str
    roles: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "team_id": self.team_id,
            "tenant_id": self.tenant_id,
            "org_id": self.org_id,
            "name": self.name,
            "roles": list(self.roles),
            "members": list(self.members),
        }


def build_org_directory(
    *,
    tenant: dict[str, Any],
    organizations: Iterable[OrganizationRecord | dict[str, Any]],
    teams: Iterable[TeamRecord | dict[str, Any]] = (),
    user_roles: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    tenant_errors = validate_tenant_record(tenant)
    if tenant_errors:
        raise ValueError("; ".join(tenant_errors))
    tenant_id = str(tenant["tenant_id"])
    org_rows = [_org_dict(item) for item in organizations]
    team_rows = [_team_dict(item) for item in teams]
    for row in [*org_rows, *team_rows]:
        if row.get("tenant_id") != tenant_id:
            raise ValueError("organization and team records must stay within the same tenant")
    org_ids = {row["org_id"] for row in org_rows}
    for team in team_rows:
        if team["org_id"] not in org_ids:
            raise ValueError(f"team {team['team_id']} references unknown org_id {team['org_id']}")
        role_errors = validate_roles(team.get("roles") or [])
        if role_errors:
            raise ValueError("; ".join(role_errors))
    return {
        "ok": True,
        "tenant": dict(tenant),
        "organizations": org_rows,
        "teams": team_rows,
        "user_roles": {user: normalize_roles(roles) for user, roles in (user_roles or {}).items()},
        "tenant_isolated": all(same_tenant({"tenant_id": tenant_id}, row) for row in [*org_rows, *team_rows]),
    }


def effective_user_access(directory: dict[str, Any], user_id: str) -> dict[str, Any]:
    roles = normalize_roles((directory.get("user_roles") or {}).get(user_id) or [])
    teams = []
    for team in directory.get("teams") or []:
        if user_id in set(team.get("members") or []):
            teams.append(team)
            roles.extend(normalize_roles(team.get("roles") or []))
    role_list = normalize_roles(roles)
    return {
        "ok": True,
        "user_id": user_id,
        "tenant_id": (directory.get("tenant") or {}).get("tenant_id"),
        "roles": role_list,
        "teams": [team["team_id"] for team in teams],
        "effective_permissions": sorted(permissions_for_roles(role_list)),
    }


def organizations_for_tenant(directory: dict[str, Any], tenant_id: str) -> list[dict[str, Any]]:
    return [org for org in directory.get("organizations") or [] if org.get("tenant_id") == tenant_id]


def _org_dict(item: OrganizationRecord | dict[str, Any]) -> dict[str, Any]:
    data = item.to_dict() if isinstance(item, OrganizationRecord) else dict(item)
    for key in ("org_id", "tenant_id", "name"):
        if not data.get(key):
            raise ValueError(f"organization {key} is required")
    if not isinstance(data.get("metadata", {}), dict):
        raise ValueError("organization metadata must be an object")
    return data


def _team_dict(item: TeamRecord | dict[str, Any]) -> dict[str, Any]:
    data = item.to_dict() if isinstance(item, TeamRecord) else dict(item)
    for key in ("team_id", "tenant_id", "org_id", "name"):
        if not data.get(key):
            raise ValueError(f"team {key} is required")
    if not isinstance(data.get("members", []), list):
        raise ValueError("team members must be a list")
    data["roles"] = normalize_roles(data.get("roles") or [])
    data["members"] = [str(item) for item in data.get("members") or []]
    return data


__all__ = [
    "OrganizationRecord",
    "TeamRecord",
    "build_org_directory",
    "effective_user_access",
    "organizations_for_tenant",
]
