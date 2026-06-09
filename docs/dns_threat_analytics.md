# DNS Threat Analytics

Phase 148 adds metadata-only DNS threat analytics readiness models for PortMap-AI. The models summarize DNS observations, resolver behavior, domain pattern heuristics, IOC matches, and optional destination behavior into advisory operator records without storing raw DNS history, making DNS lookups, calling external feeds, blocking domains, or producing final threat verdicts.

## Model Scope

The implementation lives in:

- `core_engine/intelligence/domain_patterns.py`
- `core_engine/intelligence/dns_analytics.py`

`domain_patterns.py` builds domain pattern analysis records for:

- newly seen domains
- rare domains
- high-entropy labels
- long domains
- suspicious top-level labels
- repeated subdomains
- DNS tunneling candidates
- resolver changes
- unknown or degraded observations

`dns_analytics.py` rolls DNS observations, domain pattern records, IOC inventory or match records, resolver behavior, and optional destination summaries into a bounded DNS analytics record.

## Export Safety

DNS analytics exports are hash-first and redaction-first:

- normalized domains are hashed before export
- domain previews use hash prefixes only
- resolver references are hashed summaries
- raw DNS browsing history is not stored
- packet payloads are not stored
- private identifiers are not exported
- source mode is preserved for live, fixture, simulated, replay, or unknown sources

The exported dictionaries include `preview_only=true`, `destructive_action=false`, `external_lookup_performed=false`, `raw_dns_history_stored=false`, and `enforcement_action_created=false`.

## Pattern Heuristics

The heuristics are deterministic and metadata-only. They look at label length, label entropy, repeated labels, query type hints, recurrence metadata, resolver references, and whether a normalized domain appears in a provided local baseline.

These are advisory signals only. A DNS tunneling candidate or IOC match means operator review is recommended; it is not a final threat verdict and it does not mark any domain as malicious.

## Resolver Behavior

Resolver behavior summaries count sanitized resolver references and flag resolver changes when multiple resolver references appear in the same bounded observation set. The summary does not export raw resolver values and does not perform DNS resolution.

## IOC Integration

Phase 148 can consume Phase 147 IOC inventory and IOC match records. If an IOC inventory is provided without match records, DNS analytics can perform local deterministic matching against normalized DNS candidates. This matching is local only and does not load remote feeds or reputation services.

## Safety Boundary

DNS threat analytics does not:

- perform DNS lookups
- call external threat feeds
- store raw DNS history
- inspect packet payloads
- block domains
- modify firewall, process, or service state
- generate final threat verdicts
- mark domains as malicious
- create enforcement actions

Future packet and DNS tab work can render these records in dashboard or TUI views while keeping the same metadata-only and advisory-first boundary.
