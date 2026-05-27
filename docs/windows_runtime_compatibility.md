# Windows Runtime Compatibility

Phase 100 adds Windows compatibility records for local dry-run operation. These records are designed for validation, dashboard/API views, export summaries, and future CLI output.

The Windows compatibility layer is preview-only. It does not install, start, stop, or configure Windows services. It does not modify Windows Firewall, write registry keys, request elevation, assume Npcap is installed, or store packet payloads.

## Records

- Windows runtime compatibility report.
- Windows-safe runtime profile defaults.
- Sanitized Windows log, export, cache, data, and database path summaries.
- Windows process/socket visibility capability summaries with safe degraded fallback behavior.
- Windows permission/elevation status summaries that do not request elevation.
- Windows service-mode readiness preview records.
- Dashboard/API-ready dictionaries.

## Sanitized Example

```json
{
  "record_type": "windows_runtime_compatibility_report",
  "platform": {
    "platform_family": "windows",
    "os": {
      "system": "Windows",
      "release": "windows-release-placeholder"
    }
  },
  "windows_profile_defaults": {
    "profile_id": "runtime-windows-preview",
    "runtime_mode": "dry-run",
    "storage": {
      "database_path": "<windows-data-dir>\\portmap.db"
    },
    "export": {
      "output_path": "<windows-export-dir>\\bundle.json"
    }
  },
  "windows_service_installed": false,
  "windows_firewall_modified": false,
  "registry_keys_written": false,
  "npcap_assumed_installed": false,
  "raw_payload_stored": false
}
```

## Fallback Behavior

Process and socket attribution can be unavailable or permission-limited on Windows. The compatibility records report this as a degraded state and keep command-line arguments hidden. Service-mode support remains a preview for manual operator review.

## Validation

Use sanitized fixtures only.

- Run `python -m pytest tests/test_windows_runtime_compatibility.py`.
- Run the full test suite before release.
- Confirm public docs contain no real hostnames, usernames, IP addresses, MAC addresses, private paths, runtime logs, screenshots, tokens, or registry exports.
- Keep `docs/real_device_validation.md` unstaged unless separately scrubbed and approved.
