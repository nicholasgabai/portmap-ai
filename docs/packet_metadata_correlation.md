# Packet Metadata Correlation

Phase 130 adds metadata-only packet and flow correlation records for PortMap-AI.

The goal is to connect packet-derived metadata, socket observations, reconstructed flow sessions, process and service attribution, DNS or destination behavior, protocol hints, and topology relationships into export-safe evidence summaries.

Phase 130 does not inspect packet payloads, store raw packets, generate PCAP files, log raw DNS browsing history, collect credentials, or perform enforcement.

## Correlation Model

`core_engine.flows.metadata_correlation` builds correlation records with:

- `correlation_id`
- `correlation_type`
- `correlation_state`
- `source_mode`
- `session_reference`
- `flow_reference`
- `protocol_hint`
- `destination_class`
- `dns_correlation_state`
- `topology_correlation_state`
- `metadata_confidence`
- `drift_detected`
- `advisory_notes`

Supported states are:

- `correlated`
- `partially_correlated`
- `uncorrelated`
- `conflicting`
- `unknown`

Inputs can include sanitized packet metadata, socket observations, normalized sessions, flow pairs, redacted DNS or destination behavior summaries, protocol metadata summaries, and topology relationship records.

## Process Correlation

`core_engine.flows.process_correlation` connects process and service attribution to reconstructed sessions.

Process correlation records include:

- `process_correlation_id`
- `session_reference`
- `process_attribution`
- `service_attribution`
- `attribution_source`
- `attribution_confidence`
- `attribution_state`
- `conflict_reason`
- `operator_summary`
- `source_mode`

Supported attribution states are:

- `attributed`
- `partially_attributed`
- `unattributed`
- `conflicting`
- `unknown`

Live unresolved attribution remains `Unknown` or `Unattributed`. Demo labels such as `dummy_app` and `dummy_db` are valid only when `source_mode` is explicitly `fixture` or `simulated`.

## Source Modes

Phase 130 preserves the existing source-mode model:

- `live`
- `simulated`
- `fixture`
- `replay`
- `unknown`

TUI, dashboard, API, and export consumers can use `source_mode` to distinguish live operator observations from test fixtures, simulations, and replayed historical summaries.

## Payload Safety

Correlation builders intentionally ignore payload-like input keys such as raw packet bytes, payload contents, PCAP paths, or DNS payload fields.

Every public record includes safety fields showing:

- `metadata_only: true`
- `raw_payload_stored: false`
- `packet_payload_inspected: false`
- `pcap_generated: false`
- `credential_material_stored: false`
- `automatic_changes: false`

## Operator Use

Phase 130 prepares later dynamic attribution and topology intelligence work by creating stable evidence references across packet, session, DNS, protocol, process, and topology layers.

Operators should treat correlation output as advisory evidence. Conflicts and partial correlations should be reviewed rather than enforced automatically.

## Validation

Tests use sanitized fixture records only. Public examples must avoid real hostnames, IP addresses, usernames, MAC addresses, packet payloads, PCAP files, runtime logs, screenshots, credentials, certificates, keys, and private validation notes.
