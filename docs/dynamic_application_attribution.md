# Dynamic Application Attribution

Phase 132 adds metadata-only dynamic application attribution for PortMap-AI.

The goal is to infer probable generic application and service classes from process hints, service hints, protocol metadata, destination behavior, flow or session behavior, and recurring behavioral signatures.

Phase 132 does not inspect packet payloads, store raw packets, generate PCAP files, store raw DNS browsing history, store hostnames, store IP addresses, store usernames, store MAC addresses, create hardcoded live identities, or perform enforcement.

## Attribution Records

`core_engine.attribution.probabilistic_apps` builds probable application attribution records with:

- `attribution_id`
- `observed_entity_reference`
- `candidate_app_class`
- `candidate_service_class`
- `process_hint`
- `service_hint`
- `protocol_hint`
- `destination_behavior_hint`
- `flow_behavior_hint`
- `source_mode`
- `attribution_state`
- `confidence_score`
- `evidence_summary`
- `advisory_notes`

Supported attribution states are:

- `attributed`
- `probable`
- `possible`
- `unattributed`
- `conflicting`
- `unknown`

Multiple candidates can be produced for one observation and are sorted by confidence.

## Confidence Ladder

`core_engine.attribution.confidence_models` combines bounded metadata signals:

- process confidence
- service confidence
- protocol confidence
- destination confidence
- flow confidence
- recurrence confidence
- conflict penalty

Scores are deterministic and bounded from `0.0` to `1.0`. Strong recurring metadata signals increase confidence. Conflicting signals reduce confidence.

## Behavioral Signatures

`core_engine.attribution.signature_learning` builds metadata-only behavioral signature records for:

- `recurring_port_pattern`
- `protocol_pattern`
- `destination_pattern`
- `timing_pattern`
- `process_service_pattern`
- `flow_relationship_pattern`

Signature records include recurrence, stability, drift, source mode, privacy mode, confidence, and advisory notes.

DNS and destination evidence must be redacted or hashed before use in public records. Raw DNS browsing history is not stored.

## Source Mode Rules

Phase 132 preserves the shared source-mode model:

- `live`
- `simulated`
- `fixture`
- `replay`
- `unknown`

Live/default unresolved attribution remains `Unknown` or `Unattributed`.

`dummy_app` and `dummy_db` are valid only in explicit `fixture` or `simulated` mode. They are not emitted as live/default application identities.

## Future Path

Phase 132 prepares future AI attribution work by creating stable generic candidate classes, confidence breakdowns, and behavioral signature records. Later work can add richer learned attribution while preserving the same privacy and source-mode boundaries.

## Validation

Tests use sanitized fixture records only. Public examples must avoid payloads, packet captures, raw DNS logs, hostnames, IP addresses, usernames, MAC addresses, runtime logs, screenshots, credentials, certificates, keys, and private validation notes.
