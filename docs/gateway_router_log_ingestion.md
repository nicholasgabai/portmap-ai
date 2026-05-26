# Gateway And Router Log Ingestion

Phase 96 adds sanitized router and firewall log parsing helpers for local fixture-based gateway visibility. It parses operator-provided log lines into metadata-only records for review, topology correlation, local runtime events, dashboard summaries, and export bundles.

This feature does not start syslog listeners, modify router settings, commit real router logs, transmit logs externally, or perform automatic blocking.

## Inputs

The parser accepts local sanitized strings with syslog-style prefixes and key/value fields.

Supported field aliases include:

- `action`, `act`, `policy`
- `proto`, `protocol`
- `src`, `src_ip`, `source`
- `spt`, `src_port`, `sport`
- `dst`, `dst_ip`, `destination`
- `dpt`, `dst_port`, `dport`
- `nat`, `nat_src`, `snat`, `nat_dst`, `dnat`

Malformed lines are converted into safe malformed records. The original raw line is not stored.

## Records

Gateway log records include normalized timestamps, source device references, allow/deny/NAT actions, source and destination endpoint metadata, translated NAT endpoint metadata, severity summaries, parse warnings, runtime event hooks, topology edge hooks, and export-ready summaries.

All records include safety fields such as:

- `raw_payload_stored: false`
- `external_listener_started: false`
- `router_settings_modified: false`
- `automatic_blocking: false`
- `external_transmission_enabled: false`

## Integration Hooks

Gateway records expose dictionary-only integration hooks:

- `runtime_event` uses the existing local event model with `system_notice`.
- `topology_edge` uses gateway-observed source and destination metadata when both endpoints are present.
- `export_summary` provides deterministic counts and digest material for later export bundle workflows.

These hooks do not publish events, write storage, or change topology automatically.

## Safe Example

```python
from core_engine.gateway import parse_gateway_log_lines

report = parse_gateway_log_lines(
    [
        "2026-01-01T00:00:01+00:00 gateway-placeholder "
        "action=allow proto=tcp src=203.0.113.10 spt=53000 "
        "dst=198.51.100.20 dpt=443"
    ],
    generated_at="2026-01-01T00:00:00+00:00",
)
```

Use sanitized fixtures only. Do not commit real router logs, screenshots, private paths, hostnames, usernames, MAC addresses, tokens, or runtime artifacts.
