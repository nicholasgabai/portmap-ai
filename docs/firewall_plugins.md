# Firewall Plugin Architecture (Proposal)

To replace the existing logging stub with real enforcement, PortMap-AI will use a plugin-style firewall system with the following goals:

1. **Cross-platform support** – allow different implementations per OS (Linux, macOS, Windows, custom appliances).
2. **Safety first** – ship with a no-op plugin enabled by default; operators explicitly opt-in to real firewall changes.
3. **Simple API** – remediation pipeline calls a single interface; plugins handle OS-specific details.
4. **Sandbox-friendly** – plugins support "dry-run" mode so integration tests/sandboxes can log intent without touching the OS firewall.

## Plugin model

```python
class FirewallPlugin:
    name = "noop"
    supports_dry_run = True

    def configure(self, config: dict) -> None:
        """Apply plugin-specific configuration after load."""

    def apply_action(self, connection: dict, decision: str, reason: str, dry_run: bool = False) -> None:
        """Execute the firewall change or raise FirewallError."""
```

The plugin is selected by:

- CLI flag `--firewall-plugin=<name>` (master/worker/orchestrator as needed), or
- Config field `"firewall": {"plugin": "iptables", "options": {...}}`

## Built-in plugins

| Plugin | Target | Notes |
|--------|--------|-------|
| `noop` | All    | Logs action only (default). |
| `linux_iptables` | Linux | Uses `iptables`/`ipset` for block/review actions; supports dry-run via logging. |
| `linux_nfqueue` | Linux | Future: leverage NFQUEUE for dynamic decisions. |
| `mac_pf` | macOS | Future: integrate via pfctl anchor scripts. |
| `windows_native` | Windows | Future: interface with `netsh advfirewall`. |

## Operator safety labels

The dashboard reports firewall safety in plain language:

- `noop (dry_run)` means PortMap-AI is only watching, scoring, and logging. It does not change the firewall.
- `linux_iptables (dry_run)` means PortMap-AI can build Linux firewall commands, but it only logs the command it would run.
- `linux_iptables (active)` means a real firewall plugin is allowed to apply changes. Use this only after testing dry-run mode.

Dry-run is the safe default. Operators must explicitly set `dry_run` to `false` before active enforcement is possible.

## Configuration example

```json
{
  "firewall": {
    "plugin": "linux_iptables",
    "options": {
      "chain": "PORTMAP_BLOCK",
      "dry_run": true,
      "log_command": true
    }
  }
}
```

## Failure handling

- Plugin errors bubble up to dispatcher; remediation falls back to "monitor" with error log.
- Plugins should be idempotent where possible (ensure rule exists before adding, etc.).

## Testing strategy

- Unit tests for plugin loader + noop plugin.
- Integration tests using `dry_run=True` verifying command strings (do not modify host firewall in CI).
- Optional Linux-specific tests gated behind environment variable.

## Roadmap

1. Implement loader + noop + linux_iptables (dry-run only for now).
2. Extend dispatcher to pull plugin from configs/settings.
3. Add orchestrator CLI/API to toggle dry-run live.
4. Document plugin authoring guide.
