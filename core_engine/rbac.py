from __future__ import annotations

from typing import Any, Iterable


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {
        "read:health",
        "read:metrics",
        "read:nodes",
        "read:logs",
        "read:scan_results",
        "read:vulnerabilities",
    },
    "analyst": {
        "execute:scan",
        "generate:recommendations",
        "manage:expected_services",
        "acknowledge:alerts",
    },
    "admin": {
        "manage:users",
        "manage:agents",
        "manage:config",
        "approve:remediation",
        "read:audit",
    },
    "agent": {
        "submit:telemetry",
        "read:commands",
        "heartbeat:orchestrator",
    },
}
ROLE_INHERITANCE: dict[str, tuple[str, ...]] = {
    "viewer": (),
    "analyst": ("viewer",),
    "admin": ("analyst",),
    "agent": (),
}


def normalize_roles(roles: str | Iterable[str] | None) -> list[str]:
    if roles is None:
        return []
    raw_roles = [roles] if isinstance(roles, str) else list(roles)
    normalized: list[str] = []
    for raw in raw_roles:
        for part in str(raw).split(","):
            role = part.strip().lower()
            if role and role not in normalized:
                normalized.append(role)
    return normalized


def validate_roles(roles: str | Iterable[str] | None) -> list[str]:
    errors: list[str] = []
    for role in normalize_roles(roles):
        if role not in ROLE_PERMISSIONS:
            errors.append(f"unknown role: {role}")
    return errors


def permissions_for_roles(roles: str | Iterable[str] | None) -> set[str]:
    permissions: set[str] = set()
    seen: set[str] = set()

    def add_role(role: str) -> None:
        if role in seen or role not in ROLE_PERMISSIONS:
            return
        seen.add(role)
        for parent in ROLE_INHERITANCE.get(role, ()):
            add_role(parent)
        permissions.update(ROLE_PERMISSIONS[role])

    for role in normalize_roles(roles):
        add_role(role)
    return permissions


def has_permission(roles: str | Iterable[str] | None, permission: str) -> bool:
    return permission in permissions_for_roles(roles)


def authorize(roles: str | Iterable[str] | None, permission: str) -> dict[str, Any]:
    role_list = normalize_roles(roles)
    errors = validate_roles(role_list)
    granted = not errors and has_permission(role_list, permission)
    return {
        "ok": granted,
        "roles": role_list,
        "permission": permission,
        "granted": granted,
        "errors": errors,
        "effective_permissions": sorted(permissions_for_roles(role_list)),
    }


def role_report() -> dict[str, Any]:
    return {
        "ok": True,
        "roles": {
            role: {
                "inherits": list(ROLE_INHERITANCE.get(role, ())),
                "permissions": sorted(permissions_for_roles([role])),
            }
            for role in sorted(ROLE_PERMISSIONS)
        },
    }
