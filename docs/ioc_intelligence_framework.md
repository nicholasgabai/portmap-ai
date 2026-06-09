# IOC Intelligence Framework

Phase 147 adds metadata-only IOC intelligence records for PortMap-AI. The framework lets future DNS analytics, local signatures, AI correlation, advisory scoring, and local hunt queries consume normalized indicator summaries without raw indicator export, external lookups, enforcement, or final threat verdicts.

## Scope

The IOC framework provides:

- IOC records with deterministic normalization.
- Hash-only export identifiers for indicator values.
- Redacted value previews.
- Source categories for DNS, flow, socket, process, TLS, packet metadata, topology, manual input, and unknown sources.
- Source-mode preservation for live, simulated, fixture, replay, and unknown records.
- Bounded inventory summaries.
- Local exact, normalized, and simple wildcard matching.
- JSON-safe and CSV-row-safe export summaries.

## Supported IOC Types

Supported IOC types are:

- `ipv4`
- `ipv6`
- `domain`
- `fqdn`
- `url`
- `sha256`
- `md5`
- `process_name`
- `tls_sni`
- `certificate_fingerprint`
- `dns_pattern`
- `unknown`

Indicator values are normalized in memory for local matching, then exported only as `value_hash` plus a redacted `value_preview`. The raw value is not included in export dictionaries.

## Source Categories

IOC source categories are:

- `dns`
- `flow`
- `socket`
- `process`
- `tls`
- `packet`
- `topology`
- `manual`
- `unknown`

The `packet` source category is reserved for metadata-only packet-derived records. It does not permit payload storage, PCAP generation, or raw packet export.

## Inventory Model

IOC inventories deduplicate records by normalized type and value hash. Duplicate records merge tags, source-mode context, timestamps, metadata summaries, confidence, and advisory notes.

Inventory summaries include:

- IOC count.
- Type counts.
- Source-category counts.
- Source-mode rollups.
- Confidence summaries.
- First-seen and last-seen windows.
- Bounded IOC rows.
- Export-safety fields.

`max_iocs` prevents unbounded inventory growth.

## Local Matching

IOC matching is local only. It supports:

- Exact normalized matches.
- Normalized partial matches.
- Simple wildcard pattern matches for pattern-style indicators.
- Invalid and malformed candidate handling.

Match records are advisory and include confidence, match reason, source category, source mode, preview-only safety fields, and destructive-action false flags.

## Export Safety

Exports are designed for operator review and downstream local consumers:

- Raw IOC values are not exported.
- Private identifiers are redacted.
- Raw packet payloads are not stored.
- Raw DNS browsing history is not stored.
- External lookups are not performed.
- Remote feeds are not loaded.
- No malicious flag is emitted.
- No threat verdict field is emitted.
- Enforcement action creation remains false.

CSV rows include only redacted previews, hashes, source summaries, timestamps, confidence, and safety fields.

## Future Consumers

Future Milestone Y phases can consume IOC records as local evidence:

- Phase 148 DNS threat analytics can compare DNS behavior summaries against local IOC records.
- Phase 149 local signatures can reference IOC hashes and source categories.
- Phase 150 AI correlation can include IOC matches in bounded evidence chains.
- Phase 151 threat scoring can use IOC match confidence as advisory weighting.
- Phase 152 hunt queries can search local metadata summaries by IOC type, source category, hash, and match state.

## Safety Boundary

Phase 147 does not:

- Call external threat feeds.
- Make network requests.
- Generate final threat verdicts.
- Mark IOCs malicious.
- Enforce blocking.
- Modify firewall, process, or service state.
- Store raw payloads.
- Store raw DNS history.
- Export private identifiers.
- Store credentials, certificates, or keys.

The IOC framework is metadata-only, advisory-first, bounded, source-mode preserving, and export safe.
