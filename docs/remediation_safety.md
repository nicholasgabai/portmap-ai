# Remediation Safety

Phase 7 adds a second safety gate around destructive remediation.

Safe defaults:

- `remediation_mode` defaults to `prompt`.
- Firewall plugins default to dry-run behavior.
- Destructive remediation decisions are forced to dry-run unless active enforcement is explicitly enabled.
- Active destructive commands require confirmation by default.
- Every command outcome is audit logged.

Destructive decisions:

- `block`
- `drop`
- `kill`
- `kill_process`
- `terminate`

To allow an active destructive command, all of the following must be true:

- The firewall plugin is configured with `dry_run: false`.
- `remediation_safety.active_enforcement_enabled` is `true`.
- The command includes `"confirmed": true`.
- If `remediation_safety.confirmation_token` is set, the command must include the matching `confirmation_token`.

Example dry-run config:

```json
{
  "remediation_mode": "prompt",
  "firewall": {
    "plugin": "linux_iptables",
    "options": {
      "dry_run": true
    }
  }
}
```

Example active enforcement config:

```json
{
  "remediation_mode": "silent",
  "firewall": {
    "plugin": "linux_iptables",
    "options": {
      "dry_run": false
    }
  },
  "remediation_safety": {
    "active_enforcement_enabled": true,
    "require_confirmation": true,
    "confirmation_token": "replace-this-token"
  }
}
```

An unconfirmed destructive command is rewritten to dry-run with a `metadata.safety_reason`, such as:

- `active_enforcement_disabled`
- `confirmation_required`
- `firewall_dry_run`
- `confirmed_active`

This means a misconfigured master or stale orchestrator command should not silently apply a destructive firewall change.
