from __future__ import annotations

from typing import Dict

from .base import FirewallPlugin


class NoOpFirewallPlugin(FirewallPlugin):
    """Default plugin that only logs remediation actions."""

    name = "noop"

    def apply_action(self, connection: Dict[str, any], decision: str, reason: str, dry_run: bool = False) -> None:
        logger = getattr(self.context, "logger", None)
        message = f"[FIREWALL noop] decision={decision} reason={reason} connection={connection}"
        if logger:
            logger.info(message)
        else:
            print(message)
