# DNS and Destination Behavior Learning

Phase 108 adds privacy-preserving DNS and destination behavior learning on top of existing DNS visibility records.

The feature is metadata-only and advisory. It does not store raw packet payloads, full DNS payloads, credentials, browsing history verbatim, or private resolver addresses. It does not call external reputation services, deanonymize users, modify DNS settings, block traffic, or change firewall state.

## Inputs

`core_engine/telemetry/dns_behavior.py` consumes existing DNS visibility reports, including:

- DNS query metadata
- DNS response metadata
- resolver summaries
- timing summaries
- domain-to-flow correlation summaries
- encrypted DNS limitation records
- anomaly hints
- optional previous destination records

## Destination Learning Records

`core_engine/telemetry/destination_learning.py` builds destination records with:

- redacted or hashed domain summaries
- resolver summaries with resolver hashes, not resolver IP storage
- destination IP classification placeholders
- destination frequency
- first-seen and last-seen timestamps
- recurrence timing summaries
- rolling novelty score
- baseline confidence
- transport and query-type association summaries

Destination records are deterministic, bounded, and export safe.

## DNS Behavior Profiles

DNS behavior profiles classify recurring destination behavior with advisory labels:

- `stable_destination_behavior`
- `newly_observed_destination`
- `recurring_destination`
- `unusual_resolver_behavior`
- `dormant_destination_returned`
- `destination_drift_detected`
- `baseline_consistent_destination`

Confidence scoring uses recurrence density, timing stability, resolver consistency, destination maturity, observation count, and anomaly overlap.

## Runtime Integration

DNS destination behavior reports provide:

- `summary`
- `dashboard_status`
- `api_status`
- `export_summary`

Reports can be passed to `build_live_telemetry_operator_summary()` as `dns_destination_behavior_report`. The live telemetry summary then includes a `dns_destination_behavior` panel with stable, new, unusual resolver, dormant return, drift, and confidence metrics.

## Privacy Controls

Supported privacy controls include:

- safe truncation
- redacted display domains
- optional domain hashes
- resolver hashes instead of resolver IP storage
- destination IP classification placeholders
- bounded retention
- export-safe summaries

Public examples should use sanitized fixture domains such as `<redacted>.example.test`.

## Safety Checklist

- Metadata only.
- No raw packet payloads.
- No full DNS payloads.
- No credentials.
- No verbatim browsing history.
- No external reputation calls.
- No user deanonymization.
- No DNS setting changes.
- No firewall changes or automatic blocking.
