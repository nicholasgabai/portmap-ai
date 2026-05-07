from __future__ import annotations

import logging
from typing import Dict, Optional

from core_engine.firewall_plugins import FirewallPlugin, FirewallContext, get_plugin_class
from core_engine.firewall_plugins.base import FirewallError
from core_engine.remediation_safety import is_destructive_decision

_PLUGIN: Optional[FirewallPlugin] = None


def configure_firewall(config: Dict[str, any] | None = None, logger: Optional[logging.Logger] = None) -> None:
    """Initialize the firewall plugin from configuration."""
    global _PLUGIN
    cfg = config or {}
    plugin_name = cfg.get("plugin", "noop")
    options = cfg.get("options", {})
    dry_run = cfg.get("dry_run")
    context = FirewallContext(logger=logger or logging.getLogger("portmap.firewall"))
    plugin_cls = get_plugin_class(plugin_name)
    plugin = plugin_cls(options=options, context=context)
    if dry_run is not None:
        plugin.options.setdefault("dry_run", dry_run)
    plugin.configure()
    _PLUGIN = plugin
    if context.logger:
        context.logger.info("[FIREWALL] using plugin '%s'", plugin_name)


def get_plugin() -> FirewallPlugin:
    if _PLUGIN is None:
        configure_firewall()
    return _PLUGIN


def execute_firewall_action(connection: Dict[str, any], decision: str, reason: str = "", dry_run: bool = False):
    plugin = get_plugin()
    if is_destructive_decision(decision) and not dry_run and bool(plugin.options.get("dry_run", True)):
        dry_run = True
    try:
        plugin.apply_action(connection, decision, reason, dry_run=dry_run)
    except FirewallError as exc:
        logger = getattr(plugin.context, "logger", None) or logging.getLogger("portmap.firewall")
        logger.error("Firewall action failed: %s", exc)
