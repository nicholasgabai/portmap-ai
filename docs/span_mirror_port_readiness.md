# SPAN / Mirror-Port Readiness

Phase 97 adds dry-run readiness records for future passive SPAN and mirror-port telemetry. The records help an operator decide whether a selected interface, traffic volume, and resource budget are suitable before any live capture work is attempted.

This feature does not enable promiscuous mode, change interface modes, start capture loops, modify router or switch settings, install services, or store raw packet payloads.

## Readiness Records

The gateway package exposes two record layers:

- `span_mirror_profile` stores the selected interface name, expected traffic volume, edge-device flag, passive capture requirements, and privilege requirement notes.
- `span_readiness_report` combines a profile with local interface inventory metadata, resource checks, packet-loss risk, telemetry scaling guidance, operator checklist rows, dashboard records, and API-compatible dictionaries.

Every record includes safety fields such as:

- `passive_capture_required: true`
- `promiscuous_mode_enabled: false`
- `interface_mode_changed: false`
- `capture_loop_started: false`
- `switch_settings_modified: false`
- `router_settings_modified: false`
- `raw_payload_stored: false`

## Checks

Readiness checks are deterministic and local-only:

- Interface capability summary from the passive interface inventory.
- Expected traffic volume warning thresholds.
- Resource budget checks with Raspberry Pi-aware limits.
- Manual privilege requirement summary.
- Packet-loss risk summary.
- Telemetry scaling recommendations for future bounded windows.
- Operator checklist rows for pass, review, and blocked states.

## Safe Example

```python
from core_engine.gateway import build_span_readiness_report

report = build_span_readiness_report(
    interface_name="mirror-placeholder",
    expected_traffic_mbps=40,
    expected_packet_rate=4000,
    generated_at="2026-01-01T00:00:00+00:00",
)
```

Use sanitized placeholders in public examples. Do not commit real switch/router configurations, interface captures, screenshots, runtime logs, hostnames, usernames, MAC addresses, tokens, or private validation notes.
