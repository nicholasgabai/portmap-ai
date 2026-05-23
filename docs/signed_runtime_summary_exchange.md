# Signed Runtime Summary Exchange

Phase 78 adds signed runtime summary exchange records for trusted federation. The records wrap already-produced runtime, health, topology, review, export, and visibility summaries in deterministic envelopes with digest and signature metadata.

This phase does not open network listeners, contact peers, store private signing material, or transmit data. It provides local records and validation hooks for later live federation phases.

## Scope

The implementation provides:

- canonical JSON serialization
- deterministic SHA-256 payload digest generation
- signed runtime summary envelopes
- signature metadata records
- signing status records
- verification status records
- trusted peer validation hooks
- replay-window validation hooks
- source and destination node attribution
- exchange-ready summary records

The implementation reuses Phase 77 trust profiles and transport sessions. It does not create a parallel trust schema.

## Canonical JSON And Digests

`core_engine.federation.signing.canonical_json()` serializes records with sorted keys and compact separators. `deterministic_digest()` returns a `sha256:` digest for that canonical representation.

Only structured summary payloads are hashed. Raw payload bytes are not stored.

## Signature Metadata

`build_signature_metadata()` creates metadata with:

- `source_node_id`
- `key_reference`
- `signature_algorithm`
- `payload_digest`
- `signed_at`
- `signing_status`

Private signing material is explicitly disabled:

```json
{
  "private_signing_material_stored": false,
  "raw_private_key_stored": false,
  "signature_metadata_only": true
}
```

Tests and public docs use placeholder key references only.

## Exchange Envelope

`build_signed_runtime_summary_envelope()` creates an exchange-ready envelope containing:

- source and destination node references
- trust profile and transport session references
- trust scope label
- summary record type
- summary payload
- payload digest record
- signature metadata
- signing status
- verification status
- sequence and nonce fields
- replay-window metadata

The envelope is local data. No listener is opened and no destination node is contacted.

## Validation Hooks

`validate_signed_runtime_summary_envelope()` checks:

- summary digest consistency
- signature metadata consistency
- trusted peer approval
- transport session alignment
- nonce presence
- duplicate nonce detection when a caller provides seen nonces
- sequence monotonicity when a caller provides last accepted sequence records
- expiration and replay-window bounds

`verify_signed_runtime_summary_envelope()` returns an envelope copy with an updated verification status and exchange status.

Verification is metadata validation in this phase. Cryptographic signature verification is represented as disabled until later phases add key management and signing implementations.

## Safety Boundaries

Phase 78 remains:

- local-first
- trusted-node scoped
- operator-approved
- source-attributed
- replay-window aware
- remote-control disabled
- private-key-free in repository, docs, and tests

It does not add untrusted discovery, public exposure, background collection, network listeners, remote command execution, automatic enforcement, or external transport.
