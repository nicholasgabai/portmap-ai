# Service Behavior Fingerprints

Phase 107 adds metadata-only service behavior fingerprinting for recurring process, service, protocol, port, transport, direction, DNS-summary, platform, and interface-class combinations.

This feature is advisory. It does not store packet payloads, credentials, full DNS queries, command-line arguments, user documents, or enforcement actions. It does not call external services or modify firewall state.

## Records

`core_engine/telemetry/service_fingerprints.py` builds service behavior fingerprint reports from existing telemetry summaries:

- minimized process/service attribution records
- enriched flow observations
- redacted DNS visibility summaries
- optional previous service fingerprint profiles

Each fingerprint record includes:

- `process_name`
- `service_name`
- `protocol`
- `port`
- `transport`
- `flow_role`
- `dns_association_summary`
- `runtime_platform`
- `interface_class`
- `connection_direction`
- `classification_labels`
- `confidence`

DNS associations store redacted domain summaries only. Full DNS query content is not retained.

## Profiles

`core_engine/telemetry/fingerprint_profiles.py` groups fingerprint records into recurring service profiles.

Profiles include:

- first and last seen timestamps
- observation and recurrence counts
- expected behavior summaries
- stable profile classification
- unusual combination detection
- low-confidence warnings
- dormant and reappearing service tracking
- dashboard/API/export-ready dictionaries

Supported advisory labels include:

- `stable_service_behavior`
- `newly_observed_service`
- `uncommon_protocol_binding`
- `unusual_process_port_pair`
- `dormant_service_returned`
- `baseline_consistent`

## Confidence

Confidence is advisory and based on:

- recurrence
- timing consistency
- protocol stability
- port consistency
- historical maturity
- observation density

No ML model, remote learning, or external reputation lookup is used.

## Runtime Integration

Service fingerprint reports can be passed to `build_live_telemetry_operator_summary()` as `service_fingerprint_report`.

The resulting operator summary includes a `service_fingerprints` panel with:

- profile count
- stable profile count
- unusual combination count
- dormant reappeared count
- average confidence
- review recommendation flag

Export summaries include deterministic digests and record counts for local operator-controlled bundles.

## Safety Checklist

- Metadata only.
- No packet payload storage.
- No credentials or command-line arguments.
- No full DNS query retention.
- No firewall changes.
- No automatic blocking.
- No external service calls.
- Cross-platform deterministic behavior for Linux, macOS, and Windows fixtures.
