# Flow Telemetry Enrichment

Phase 93 adds metadata-only enrichment on top of reconstructed telemetry flows. It improves the quality of operator summaries before gateway and router-adjacent modes are implemented.

This feature does not capture packets, store raw payload bytes, inject traffic, decrypt traffic, block traffic, or change router or host network settings.

## Records

`core_engine.telemetry.flow_observations` builds one enriched observation per reconstructed flow:

- flow reference and digest
- transport and flow classification
- first-seen and last-seen timestamps
- packet and byte counters
- forward and reverse packet counters
- local versus remote endpoint classification
- direction inference such as outbound, inbound, internal, external, or unknown
- service-port hint and service-name correlation
- state transition summary compared with a previous observation
- confidence score
- telemetry quality flags

All records include the existing telemetry safety fields, including:

- `raw_payload_stored: false`
- `payload_bytes_stored: 0`
- `metadata_only: true`
- `automatic_blocking: false`
- `traffic_injection: false`

## Enrichment Report

`core_engine.telemetry.flow_enrichment.enrich_flow_records` builds a bounded report from reconstructed flow records. The report includes:

- enriched observations
- rolling flow statistics
- aggregate packet and byte counters
- counts by direction, service, transport, transition state, and quality level
- dropped observation count when `max_observations` bounds are applied
- dashboard-ready status
- API-compatible dictionaries

The default observation bound is intentionally finite for Raspberry Pi and edge-device operation.

## Direction And Endpoint Scope

Endpoint scope uses operator-provided local CIDR ranges. Public examples use documentation-safe placeholder ranges only.

```python
from core_engine.telemetry import enrich_flow_records

report = enrich_flow_records(
    flows,
    local_cidrs=["203.0.113.0/24", "2001:db8:100::/48"],
    generated_at="2026-01-01T00:00:00+00:00",
)
```

Direction labels are advisory. If endpoint data is missing, malformed, or not covered by local CIDR hints, the direction is reported as `unknown` rather than guessed silently.

## State Transitions

When a previous enriched observation is available, the enrichment layer reports transition reasons such as:

- `packet_count_increased`
- `byte_count_increased`
- `classification_changed`
- `direction_changed`
- `service_hint_changed`

State transitions are local review evidence only. They do not execute remediation or enforcement.

## Dashboard And API Use

The dashboard summary exposes metrics and rows suitable for local operator views:

- observation count
- packet and byte totals
- average confidence
- rolling packet and byte rates
- direction and service summaries
- per-flow quality levels

Dashboard rows intentionally omit raw packet contents and sensitive process details.

## Safety Notes

Phase 93 is a data-quality layer for later gateway readiness work. It is not inline gateway enforcement and does not modify traffic. Public documentation and tests use sanitized placeholders only.
