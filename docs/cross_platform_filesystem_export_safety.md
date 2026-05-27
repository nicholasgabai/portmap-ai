# Cross-Platform Filesystem And Export Safety

Phase 103 adds read-only filesystem and export safety records for macOS, Linux/Raspberry Pi, Windows, and unknown platforms. The records normalize public path summaries, classify runtime artifacts, flag private validation files, and provide dashboard/API-ready safety views.

This phase does not delete files, move files, write exports, create archives, or stage private artifacts.

## Safety Coverage

- Safe log path summaries.
- Safe export path summaries.
- Safe cache and database path summaries.
- OS-specific path separator normalization.
- Runtime artifact classification for logs, screenshots, archives, databases, cache folders, environment files, and generated build output.
- Private-file warning records for `docs/real_device_validation.md`.
- Public documentation safety checks for private identifiers.

## Sanitized Example

```json
{
  "record_type": "cross_platform_filesystem_safety_report",
  "summary": {
    "status": "blocked",
    "artifact_blocked_count": 1,
    "private_warning_count": 1,
    "public_doc_blocked_count": 0
  },
  "dashboard_status": {
    "panel": "cross_platform_filesystem_export_safety",
    "status": "blocked"
  },
  "path_deleted": false,
  "file_deleted": false,
  "file_moved": false,
  "private_file_staged": true
}
```

## Operator Notes

- Keep private validation notes unstaged unless separately scrubbed and approved.
- Do not stage runtime logs, screenshots, archives, database files, cache folders, environment files, or build output.
- Export paths remain operator-provided and local-only.
- Archive creation requires an explicit operator-provided output path.

## Validation

Use sanitized fixtures and temporary local paths only.

- Run `python -m pytest tests/test_cross_platform_filesystem_export_safety.py`.
- Run the full test suite before release.
- Confirm no private validation files, logs, screenshots, archives, database files, cache folders, environment files, or runtime artifacts are staged.
- Confirm public docs contain no real hostnames, usernames, IP addresses, MAC addresses, SSH details, private paths, tokens, or raw validation artifacts.
