# Cross-Platform Firewall Provider Readiness

Phase 102 adds dry-run firewall provider readiness records for Windows, macOS, Linux, and Raspberry Pi/Linux ARM. The records summarize provider availability, permission requirements, rule previews, safety warnings, and dashboard/API-ready views.

This phase does not add, modify, enable, or remove firewall rules. It does not modify Windows Defender Firewall, macOS `pf`, `nftables`, `ufw`, or `iptables`. It does not request elevation, install firewall tooling, or enable automatic blocking.

## Provider Summaries

- Windows: Windows Defender Firewall preview provider.
- macOS: `pf` preview provider.
- Linux: `nftables`, `ufw`, and `iptables` preview providers.
- Raspberry Pi/Linux ARM: Linux provider summaries with edge-device review warnings.
- Unknown platforms: unknown provider state records.

## Safety Fields

Every readiness report includes explicit safety fields:

```json
{
  "dry_run_only": true,
  "rule_preview_only": true,
  "rule_applied": false,
  "firewall_rules_changed": false,
  "automatic_blocking": false,
  "provider_install_attempted": false,
  "admin_elevation_requested": false
}
```

## Sanitized Example

```json
{
  "record_type": "cross_platform_firewall_readiness_report",
  "summary": {
    "status": "degraded",
    "platform_family": "linux",
    "provider_status": "degraded",
    "permission_status": "degraded",
    "rule_preview_count": 3,
    "operator_review_required": true
  },
  "dashboard_status": {
    "panel": "cross_platform_firewall_provider_readiness",
    "status": "degraded"
  },
  "rules_applied_count": 0,
  "firewall_rules_changed": false,
  "automatic_blocking": false
}
```

## Validation

Use sanitized fixtures and temporary local paths only.

- Run `python -m pytest tests/test_cross_platform_firewall_provider_readiness.py`.
- Run the full test suite before release.
- Confirm no real firewall commands, hostnames, usernames, IP addresses, MAC addresses, runtime logs, screenshots, or provider installation artifacts are staged.
- Keep `docs/real_device_validation.md` unstaged unless separately scrubbed and approved.
