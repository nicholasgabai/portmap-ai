# Cross-Platform Packet Capture Readiness

Phase 101 adds dry-run packet capture readiness records for macOS, Linux, Raspberry Pi/Linux ARM, and Windows. The records summarize backend availability, interface suitability, permission requirements, passive-mode warnings, and dashboard/API-ready views.

This phase does not capture packets. It does not enable promiscuous mode, change interface settings, install packet capture providers, request admin/root elevation, start sniffing loops, or store packet payloads.

## Backend Summaries

- macOS: BPF and libpcap readiness summaries.
- Linux: libpcap, AF_PACKET, and Scapy readiness summaries.
- Raspberry Pi/Linux ARM: Linux backend summaries with edge-device resource warnings.
- Windows: Npcap, WinPcap, and Scapy readiness summaries without assuming any provider is installed.
- Unknown platforms: unknown backend state records for operator review.

## Safety Fields

Every readiness report includes explicit safety fields:

```json
{
  "capture_started": false,
  "capture_loop_started": false,
  "promiscuous_mode_enabled": false,
  "interface_mode_changed": false,
  "provider_install_attempted": false,
  "admin_elevation_requested": false,
  "packet_payload_storage_prohibited": true,
  "raw_payload_stored": false
}
```

## Sanitized Example

```json
{
  "record_type": "cross_platform_capture_readiness_report",
  "summary": {
    "status": "degraded",
    "platform_family": "linux",
    "backend_status": "degraded",
    "permission_status": "degraded",
    "selected_interface_count": 1
  },
  "dashboard_status": {
    "panel": "cross_platform_packet_capture_readiness",
    "status": "degraded"
  },
  "packet_payload_storage_prohibited": true,
  "packets_captured": 0,
  "raw_payload_stored": false
}
```

## Validation

Use sanitized fixtures and temporary local paths only.

- Run `python -m pytest tests/test_cross_platform_packet_capture_readiness.py`.
- Run the full test suite before release.
- Confirm no packet payloads, real hostnames, usernames, IP addresses, MAC addresses, runtime logs, screenshots, or provider installer artifacts are staged.
- Keep `docs/real_device_validation.md` unstaged unless separately scrubbed and approved.
