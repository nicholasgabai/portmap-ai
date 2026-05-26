# Cross-Platform Runtime Detection

Phase 99 adds local runtime compatibility records for macOS, Linux, Raspberry Pi/Linux ARM, Windows, and unknown platforms. The records are designed for CLI, dashboard, API, validation, and export workflows.

The detection layer is advisory and dry-run only. It does not install services, change firewall rules, enable packet capture, request elevated permissions, store payload bytes, or include host-specific identifiers in public examples.

## What It Records

- Platform family: `macos`, `linux`, `raspberry-pi-linux-arm`, `windows`, or `unknown`.
- OS release and architecture summaries.
- Python runtime version and support summary.
- Admin/root/elevated permission status without requesting elevation.
- Capability placeholders for packet capture, firewall providers, service-mode previews, and local path/export safety.
- Dashboard/API-ready dictionaries for compatibility panels.

## Example

```json
{
  "record_type": "runtime_compatibility_report",
  "platform": {
    "platform_family": "linux",
    "os": {
      "system": "Linux",
      "release": "kernel-placeholder",
      "family": "linux"
    },
    "architecture": {
      "machine": "x86_64",
      "is_arm": false,
      "is_64_bit": true
    },
    "permissions": {
      "elevated": false,
      "elevation_requested": false
    }
  },
  "summary": {
    "status": "degraded",
    "operator_summary": "linux runtime compatibility requires operator review before privileged workflows."
  },
  "packet_capture_enabled": false,
  "firewall_rules_changed": false,
  "service_installed": false,
  "raw_payload_stored": false
}
```

## Safety Notes

- Permission detection reports current state only.
- Packet capture support is a placeholder until later readiness checks run.
- Firewall providers are preview-only and never apply rules.
- Service-mode output remains preview-only and never installs or starts services.
- Path/export records use placeholders such as `<portmap-export-dir>`.

## Validation

Use sanitized fixtures and temporary local paths only.

- Run `python -m pytest tests/test_cross_platform_runtime_detection.py`.
- Run the full test suite before release.
- Confirm public docs contain no real hostnames, usernames, IP addresses, MAC addresses, private paths, logs, screenshots, or runtime artifacts.
- Keep `docs/real_device_validation.md` unstaged unless separately scrubbed and approved.
