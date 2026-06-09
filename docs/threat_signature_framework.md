# Threat Signature Framework

Phase 149 adds local metadata-only threat signature records and deterministic signature matching for PortMap-AI. The framework connects IOC matches, DNS pattern records, flow metadata, protocol hints, application attribution, topology relationships, and runtime health summaries into advisory signature match records.

The framework does not load external feeds, inspect payloads, block activity, modify host state, or generate final threat verdicts.

## Model Scope

The implementation lives in:

- `core_engine/intelligence/signature_records.py`
- `core_engine/intelligence/signature_matching.py`

Signature records include:

- signature identifier and name
- signature type
- enabled state
- severity level
- confidence score
- metadata-only match conditions
- tags
- source category and source mode
- advisory notes
- preview-only and non-destructive safety flags

Supported signature types are:

- `ioc_match`
- `dns_pattern`
- `flow_behavior`
- `protocol_behavior`
- `application_attribution`
- `topology_relationship`
- `runtime_health`
- `composite`
- `unknown`

## Match Conditions

Match conditions are local dictionary fields evaluated against provided metadata records. Examples include IOC match state, DNS pattern type, flow protocol, protocol hint, attribution state, topology relationship state, and runtime health state.

The framework rejects conditions that attempt to describe enforcement, blocking, quarantine, process termination, service disablement, firewall changes, or destructive actions. Unsafe conditions fail validation before a signature record is created.

## Matching Outputs

Signature matching produces export-safe match records with:

- match state
- sanitized match reason
- matched references
- supporting IOC references
- supporting DNS pattern references
- supporting flow, protocol, attribution, and topology references
- bounded confidence score
- severity level
- source mode
- preview-only and non-destructive safety flags

Supported match states are `matched`, `partial_match`, `not_matched`, `invalid`, `degraded`, and `unknown`.

## Integration Points

Phase 149 can consume:

- Phase 147 IOC match records
- Phase 148 DNS pattern records
- Milestone V flow and protocol metadata
- dynamic application attribution summaries
- topology relationship summaries
- runtime health summaries

Composite signatures can require multiple local metadata signals before returning a matched state.

## Safety Boundary

Threat signatures are local and advisory only. They do not:

- call external feeds
- make network requests
- inspect packet payloads
- store raw payloads
- store raw DNS history
- mark signatures or observations as malicious
- generate final threat verdicts
- block traffic
- modify firewall, process, or service state
- create enforcement actions

Future rule-feed and packet-intelligence work can build on these records, but any feed loading, packet capture, or supervised response path must remain separate, explicit, bounded, and operator-controlled.
