from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


class FirewallError(Exception):
    """Raised when a firewall plugin fails to apply an action."""


@dataclass
class FirewallContext:
    logger: Any = None


class FirewallPlugin:
    """Base class for firewall enforcement plugins."""

    name: str = "base"
    supports_dry_run: bool = True

    def __init__(self, options: Dict[str, Any] | None = None, context: FirewallContext | None = None):
        self.options = options or {}
        self.context = context or FirewallContext()

    def configure(self) -> None:
        """Hook called after instantiation."""

    def apply_action(self, connection: Dict[str, Any], decision: str, reason: str, dry_run: bool = False) -> None:
        raise NotImplementedError
