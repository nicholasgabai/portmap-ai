# Bidirectional Flow Reconstruction

Phase 129 adds metadata-only bidirectional flow reconstruction and session-aware relationship modeling for socket observations.

This phase does not inspect packet payloads, store packet payloads, generate PCAPs, require kernel drivers, use deep packet inspection, store credentials, modify traffic, inject traffic, or block traffic.

## Purpose

Phase 129 helps PortMap-AI correlate repeated socket, process, service, transport, and destination metadata into normalized session records and relationship summaries.

It answers these operator questions:

- Which local socket observations describe the same session?
- Is a session inbound, outbound, loopback, or unknown direction?
- Is a session active, transient, recurring, dormant, or unknown?
- Which process and service attribution is available?
- Which relationships are strong enough for later behavioral attribution?
- Which records remain safe for dashboard, API, export, and future federation summaries?

## Modules

- `core_engine.flows.session_tracking`
- `core_engine.flows.flow_reconstruction`

These modules build on earlier telemetry, attribution, DNS visibility, and flow enrichment records. They are a higher-level flow intelligence layer and do not replace the Phase 89 packet-metadata flow reconstruction helpers.

## Session Tracking Records

Normalized session records include:

- `session_id`
- `flow_direction`
- `local_endpoint_class`
- `remote_endpoint_class`
- `local_port`
- `remote_port`
- `protocol`
- `transport_state`
- `process_attribution`
- `service_attribution`
- `source_mode`
- `session_state`
- `observed_timestamps`
- `session_duration_preview`
- `confidence_score`
- `advisory_notes`

Supported directions:

- `inbound`
- `outbound`
- `local_loopback`
- `unknown_direction`

Supported session states:

- `active`
- `transient`
- `recurring`
- `dormant`
- `unknown`

## Relationship Reconstruction

Bidirectional reconstruction outputs:

- `flow_pairs`
- `flow_relationships`
- `inferred_sessions`
- `transient_sessions`
- `recurring_sessions`

Records include:

- `relationship_strength`
- `recurrence_score`
- `drift_detected`
- `reconstruction_confidence`
- `session_classification`

Repeated observations collapse into stable session IDs. Previous observations can raise recurrence scores, while dormant recurring observations can produce drift hints for operator review.

## Source Mode Preservation

Phase 129 preserves `source_mode` values:

- `live`
- `simulated`
- `fixture`
- `replay`
- `unknown`

Live/default unresolved attribution remains `Unknown` or `Unattributed`. Fixture or simulated labels must stay explicit and must not be mixed into live records.

## Safety Fields

Every output includes explicit safety posture:

- `metadata_only: true`
- `raw_payload_stored: false`
- `payload_bytes_stored: 0`
- `packet_payload_inspected: false`
- `deep_packet_inspection: false`
- `pcap_generated: false`
- `credential_material_stored: false`
- `local_only: true`
- `advisory_only: true`
- `automatic_changes: false`

## Future Behavioral Attribution Path

Phase 129 prepares later Milestone V work by creating stable metadata-only session and relationship records. Future phases can correlate these records with packet metadata, cross-node relationships, dynamic application attribution, behavioral drift detection, and topology intelligence.

Future work must preserve the same safety posture unless a later milestone explicitly adds an operator-approved capability.

## Validation Notes

Phase 129 validation uses sanitized fixture records only.

- Run `python -m pytest`.
- Run `git diff --check`.
- Confirm no payload contents, PCAPs, kernel driver artifacts, credentials, logs, screenshots, archives, database files, environment files, runtime artifacts, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
