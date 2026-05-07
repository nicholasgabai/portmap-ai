"""Firewall plugin registry and loader."""

from __future__ import annotations

import importlib
from typing import Dict, Type

from .base import FirewallContext, FirewallPlugin

PLUGIN_MAP: Dict[str, str] = {
    "noop": "core_engine.firewall_plugins.noop:NoOpFirewallPlugin",
    "linux_iptables": "core_engine.firewall_plugins.linux_iptables:IPTablesFirewallPlugin",
}


def get_plugin_class(name: str) -> Type[FirewallPlugin]:
    try:
        target = PLUGIN_MAP[name]
    except KeyError as exc:
        raise ValueError(f"Unknown firewall plugin '{name}'") from exc
    module_name, class_name = target.split(":", 1)
    module = importlib.import_module(module_name)
    plugin_cls = getattr(module, class_name)
    if not issubclass(plugin_cls, FirewallPlugin):
        raise TypeError(f"Plugin {name} is not a FirewallPlugin")
    return plugin_cls


__all__ = ["get_plugin_class", "PLUGIN_MAP", "FirewallPlugin", "FirewallContext"]
