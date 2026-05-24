# Protocol Metadata Extraction

Phase 90 adds safe protocol metadata summaries and service fingerprints on top of reconstructed flow records.

This phase does not retain credentials, store packet payload contents, perform decryption, inject traffic, modify traffic, block traffic, open listeners, or transmit telemetry externally. It summarizes already-available metadata fields and applies governance controls before output.

## Purpose

Protocol metadata extraction answers these operator questions:

- Which application-layer protocol is suggested by a flow?
- Which HTTP, TLS, or DNS metadata fields are safe to retain?
- Which service fingerprint best explains the flow?
- How confident is the protocol classification?
- Were sensitive fields removed or long metadata fields truncated?
- Are there protocol/service mismatches or missing encrypted-session metadata?
- Which protocol summaries are safe for dashboards, APIs, topology, review, and exports?

## Modules

- `core_engine.telemetry.protocol_metadata`
- `core_engine.telemetry.fingerprints`

The helpers reuse Phase 88 packet windows and Phase 89 flow records. They accept explicit metadata dictionaries from sanitized fixtures or later approved ingestion paths and return local-only records.

## Metadata Summaries

HTTP summaries can include:

- method
- host
- path without query string
- status code
- header names only
- content type label

TLS summaries can include:

- TLS version
- record version
- SNI
- ALPN
- cipher family
- handshake type
- certificate issuer summary
- encrypted-session marker

DNS summaries can include:

- query name
- query type
- response code
- answer count
- opcode

Sensitive fields are removed before output. Payload and content fields are not retained.

## Fingerprints And Confidence

Protocol fingerprint records include:

- flow reference
- protocol label
- transport protocol
- service association
- confidence score
- evidence references
- metadata digest

Confidence combines metadata presence, service association, and default port hints. The score is advisory only.

## Governance Fields

Every protocol output includes explicit controls:

- `credentials_retained: false`
- `payload_contents_retained: false`
- `decryption_performed: false`
- `traffic_injected: false`
- `automatic_blocking: false`
- `raw_payload_stored: false`
- `administrator_controlled: true`

## Sanitized Example

```json
{
  "record_type": "protocol_metadata_record",
  "protocol": "tls",
  "selected_metadata": {
    "protocol": "tls",
    "status": "ok",
    "fields": {
      "tls_version": "TLS 1.3",
      "encrypted_session": true,
      "decryption_performed": false
    }
  },
  "protocol_fingerprint": {
    "protocol": "tls",
    "confidence": 0.95
  },
  "credentials_retained": false,
  "payload_contents_retained": false
}
```

## Operator Workflow

1. Reconstruct Phase 89 flow records.
2. Provide sanitized HTTP, TLS, or DNS metadata fields from an approved source.
3. Extract protocol metadata records.
4. Review confidence, governance, truncation, and anomaly summaries.
5. Forward only metadata summaries to dashboard, topology, review, export, or later intelligence phases.

## Validation Notes

Phase 90 validation uses sanitized fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no credentials, packet payloads, DPI content, logs, screenshots, archives, database files, environment files, runtime artifacts, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
