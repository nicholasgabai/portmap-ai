from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


PROVIDER_NAMES = frozenset(
    {
        "windows_defender_firewall",
        "linux_nftables",
        "linux_ufw",
        "linux_iptables",
        "macos_pf",
        "raspberry_pi_edge",
        "generic_manual_operator",
    }
)
READINESS_STATES = frozenset({"ready", "degraded", "unavailable", "unknown"})
SUPPORTED_ACTIONS = frozenset(
    {
        "rate_limit_preview",
        "block_port_preview",
        "block_destination_preview",
        "quarantine_service_preview",
        "isolate_node_preview",
        "manual_review",
    }
)

_PROVIDER_PLATFORMS = {
    "windows_defender_firewall": {"windows"},
    "linux_nftables": {"linux", "raspberry_pi", "linux_arm"},
    "linux_ufw": {"linux", "raspberry_pi", "linux_arm"},
    "linux_iptables": {"linux", "raspberry_pi", "linux_arm"},
    "macos_pf": {"macos"},
    "raspberry_pi_edge": {"raspberry_pi", "linux_arm"},
    "generic_manual_operator": {"macos", "linux", "raspberry_pi", "linux_arm", "windows", "unknown"},
}

_PROVIDER_ACTIONS = {
    "windows_defender_firewall": {
        "block_port_preview",
        "block_destination_preview",
        "quarantine_service_preview",
        "manual_review",
    },
    "linux_nftables": {
        "rate_limit_preview",
        "block_port_preview",
        "block_destination_preview",
        "quarantine_service_preview",
        "isolate_node_preview",
        "manual_review",
    },
    "linux_ufw": {"block_port_preview", "block_destination_preview", "manual_review"},
    "linux_iptables": {
        "rate_limit_preview",
        "block_port_preview",
        "block_destination_preview",
        "manual_review",
    },
    "macos_pf": {"block_port_preview", "block_destination_preview", "manual_review"},
    "raspberry_pi_edge": {
        "rate_limit_preview",
        "block_port_preview",
        "block_destination_preview",
        "manual_review",
    },
    "generic_manual_operator": {"manual_review"},
}


class IsolationProviderError(ValueError):
    """Raised when provider readiness input is malformed or unsafe."""


@dataclass(slots=True)
class IsolationProviderReadiness:
    provider_name: str
    platform_family: str
    supported_actions: list[str] = field(default_factory=list)
    unavailable_actions: list[str] = field(default_factory=list)
    readiness_state: str = "unknown"
    permission_required: bool = True
    elevation_required: bool = True
    dry_run_supported: bool = True
    command_preview: str = "manual operator review only"
    safety_warnings: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        if self.provider_name not in PROVIDER_NAMES:
            raise IsolationProviderError(f"unsupported provider_name: {self.provider_name}")
        _required_str(self.platform_family, "platform_family")
        if self.readiness_state not in READINESS_STATES:
            raise IsolationProviderError(f"unsupported readiness_state: {self.readiness_state}")
        self.supported_actions = _validate_actions(self.supported_actions, "supported_actions")
        self.unavailable_actions = _validate_actions(self.unavailable_actions, "unavailable_actions")
        if not isinstance(self.permission_required, bool):
            raise IsolationProviderError("permission_required must be boolean")
        if not isinstance(self.elevation_required, bool):
            raise IsolationProviderError("elevation_required must be boolean")
        if not self.dry_run_supported:
            raise IsolationProviderError("provider readiness records must support dry-run preview")
        self.command_preview = sanitize_command_preview(self.command_preview)
        if not _is_string_list(self.safety_warnings):
            raise IsolationProviderError("safety_warnings must be a list of strings")
        if not _is_string_list(self.advisory_notes):
            raise IsolationProviderError("advisory_notes must be a list of strings")


def build_provider_readiness(
    provider_name: str,
    *,
    platform_family: str = "unknown",
    available: bool | None = None,
    now: str | None = None,
) -> IsolationProviderReadiness:
    if provider_name not in PROVIDER_NAMES:
        return IsolationProviderReadiness(
            provider_name="generic_manual_operator",
            platform_family=_normalize_platform(platform_family),
            supported_actions=["manual_review"],
            unavailable_actions=sorted(SUPPORTED_ACTIONS - {"manual_review"}),
            readiness_state="unknown",
            permission_required=False,
            elevation_required=False,
            command_preview="manual operator review only",
            safety_warnings=["Requested provider is unsupported; no containment command is available."],
            advisory_notes=[f"Unsupported provider was mapped to manual review: {str(provider_name)[:48]}"],
            created_at=now or _now(),
        )

    platform = _normalize_platform(platform_family)
    supported_platform = platform in _PROVIDER_PLATFORMS[provider_name]
    supported = sorted(_PROVIDER_ACTIONS[provider_name])
    unavailable = sorted(SUPPORTED_ACTIONS - set(supported))
    if available is False:
        state = "unavailable"
    elif not supported_platform:
        state = "unavailable" if platform != "unknown" else "unknown"
    elif provider_name == "generic_manual_operator":
        state = "ready"
    elif provider_name == "raspberry_pi_edge":
        state = "degraded"
    else:
        state = "ready" if available is not False else "unavailable"

    permission_required = provider_name != "generic_manual_operator"
    elevation_required = provider_name not in {"generic_manual_operator"}
    warnings = [
        "Command preview is sanitized and must not be executed by PortMap-AI.",
        "Operator approval and rollback planning are required before any future containment action.",
    ]
    if state != "ready":
        warnings.append(f"Provider readiness is {state}; use manual review or collect platform capability evidence.")
    if provider_name == "raspberry_pi_edge":
        warnings.append("Raspberry Pi edge containment should account for limited CPU, memory, and remote access risk.")

    return IsolationProviderReadiness(
        provider_name=provider_name,
        platform_family=platform,
        supported_actions=supported,
        unavailable_actions=unavailable,
        readiness_state=state,
        permission_required=permission_required,
        elevation_required=elevation_required,
        dry_run_supported=True,
        command_preview=_command_preview(provider_name),
        safety_warnings=warnings,
        advisory_notes=_provider_notes(provider_name, platform, state),
        created_at=now or _now(),
    )


def provider_readiness_to_dict(provider: IsolationProviderReadiness) -> dict[str, Any]:
    return {
        "record_type": "isolation_provider_readiness",
        "provider_name": provider.provider_name,
        "platform_family": provider.platform_family,
        "supported_actions": list(provider.supported_actions),
        "unavailable_actions": list(provider.unavailable_actions),
        "readiness_state": provider.readiness_state,
        "permission_required": provider.permission_required,
        "elevation_required": provider.elevation_required,
        "dry_run_supported": provider.dry_run_supported,
        "command_preview": provider.command_preview,
        "safety_warnings": list(provider.safety_warnings),
        "advisory_notes": list(provider.advisory_notes),
        "created_at": provider.created_at,
        "preview_only": True,
        "destructive_action": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_provider_matrix(platform_family: str = "unknown", *, now: str | None = None) -> list[IsolationProviderReadiness]:
    return [build_provider_readiness(name, platform_family=platform_family, now=now) for name in sorted(PROVIDER_NAMES)]


def deterministic_provider_readiness_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def sanitize_command_preview(command_preview: str) -> str:
    text = str(command_preview or "manual operator review only")
    replacements = [
        (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<redacted-address>"),
        (r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", "<redacted-mac>"),
        ("/" + r"Users/[^ \n\t]+", "<redacted-path>"),
        (r"--password(?:=|\s+)[^ \n\t]+", "--password <redacted>"),
        (r"--token(?:=|\s+)[^ \n\t]+", "--token <redacted>"),
    ]
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)
    return text[:240]


def _command_preview(provider_name: str) -> str:
    return {
        "windows_defender_firewall": "Windows Defender Firewall dry-run preview for <target>",
        "linux_nftables": "nft dry-run preview for <target>",
        "linux_ufw": "ufw dry-run preview for <target>",
        "linux_iptables": "iptables dry-run preview for <target>",
        "macos_pf": "pfctl dry-run preview for <target>",
        "raspberry_pi_edge": "Raspberry Pi edge dry-run preview for <target>",
        "generic_manual_operator": "manual operator review only",
    }[provider_name]


def _provider_notes(provider_name: str, platform: str, state: str) -> list[str]:
    notes = [f"{provider_name} readiness modeled for {platform} as {state}."]
    if provider_name != "generic_manual_operator":
        notes.append("No subprocess, firewall API, service API, or process API is called.")
    return notes


def _normalize_platform(platform_family: str) -> str:
    value = str(platform_family or "unknown").lower().strip()
    aliases = {
        "darwin": "macos",
        "mac": "macos",
        "osx": "macos",
        "linux_arm": "linux_arm",
        "raspberrypi": "raspberry_pi",
        "raspberry-pi": "raspberry_pi",
        "raspberry_pi/linux_arm": "raspberry_pi",
        "win32": "windows",
    }
    return aliases.get(value, value if value else "unknown")


def _validate_actions(actions: list[str], field_name: str) -> list[str]:
    if not isinstance(actions, list):
        raise IsolationProviderError(f"{field_name} must be a list")
    normalized = []
    for action in actions:
        if action not in SUPPORTED_ACTIONS:
            raise IsolationProviderError(f"unsupported action in {field_name}: {action}")
        normalized.append(action)
    return sorted(set(normalized))


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise IsolationProviderError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, IsolationProviderReadiness):
        return provider_readiness_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
