from __future__ import annotations

import subprocess
from typing import Dict

from core_engine import platform_utils

from .base import FirewallError, FirewallPlugin


class IPTablesFirewallPlugin(FirewallPlugin):
    """Linux iptables-based firewall plugin.

    Currently defaults to dry-run mode; set options["dry_run"] = False to execute commands.
    """

    name = "linux_iptables"

    def configure(self) -> None:
        self.chain = self.options.get("chain", "PORTMAP_BLOCK")
        self.dry_run = bool(self.options.get("dry_run", True))
        self.log_command = bool(self.options.get("log_command", True))
        self._iptables_path = platform_utils.find_executable("iptables")
        if not self._iptables_path:
            if not self.dry_run:
                raise FirewallError("iptables not found; enable dry_run or install iptables")
        logger = getattr(self.context, "logger", None)
        if logger:
            mode = "dry-run" if self.dry_run else "active"
            logger.info("[FIREWALL iptables] initialized chain=%s mode=%s", self.chain, mode)

    def apply_action(self, connection: Dict[str, any], decision: str, reason: str, dry_run: bool = False) -> None:
        effective_dry_run = self.dry_run or dry_run
        logger = getattr(self.context, "logger", None)

        if decision == "block":
            command = [
                self._iptables_path or "iptables",
                "-I",
                self.chain,
                "-p",
                str(connection.get("protocol", "tcp")).lower(),
                "--dport",
                str(connection.get("port")),
                "-j",
                "DROP",
            ]
            if self.log_command and logger:
                logger.info("[FIREWALL iptables] command=%s reason=%s", " ".join(command), reason)
            if effective_dry_run:
                return
            try:
                platform_utils.run_command(command, check=True)
            except subprocess.CalledProcessError as exc:
                raise FirewallError(f"iptables command failed: {exc}") from exc
        else:
            if logger:
                logger.info("[FIREWALL iptables] decision=%s reason=%s (no action)", decision, reason)
