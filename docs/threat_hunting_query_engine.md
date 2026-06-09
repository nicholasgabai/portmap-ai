# Phase 152 - Threat Hunting Query Engine

Phase 152 completes Milestone Y by adding a metadata-only local threat hunting query framework. The query engine searches, filters, summarizes, and correlates supplied IOC intelligence, DNS analytics, signature matches, AI correlation records, advisory threat scoring records, timeline windows, topology summaries, fleet visibility records, and risk dashboard summaries.

The engine is deterministic and local. It does not call external APIs, perform network requests, inspect packet payloads, generate final threat verdicts, label entities as malicious, execute enforcement, modify firewall rules, stop processes, disable services, store raw payloads, or retain raw DNS history.

## Query Language

The implementation lives in:

- `core_engine/intelligence/query_language.py`
- `core_engine/intelligence/hunting_queries.py`

`ThreatHuntQuery` records include:

- `query_id`
- `query_name`
- `query_type`
- `query_expression`
- `filters`
- `source_scopes`
- `enabled`
- `result_limit`
- `preview_only`
- `destructive_action`
- `advisory_notes`

Supported query types are:

- `ioc_search`
- `dns_search`
- `signature_search`
- `correlation_search`
- `scoring_search`
- `timeline_search`
- `topology_search`
- `fleet_search`
- `composite_search`
- `unknown`

Filters support equality checks, contains checks, confidence thresholds, severity thresholds, source-mode filters, and bounded result limits. Query records validate unsupported filter operators and remain local to caller-provided metadata.

## Hunting Results

`ThreatHuntResult` records summarize matches without exporting raw records. Each matched record is reduced to a sanitized reference, record type, source scope, confidence score, severity level, source mode, and short summary.

Hunt states are:

- `results_found`
- `no_results`
- `degraded`
- `empty`
- `invalid`
- `unknown`

Result ordering is deterministic by severity, confidence, and reference. Result windows are bounded by the query result limit, with a hard maximum to prevent unbounded exports.

## Search Scopes

The engine can consume local metadata supplied by callers:

- IOC inventories and IOC match records
- DNS analytics and domain pattern records
- signature match records
- AI correlation summaries and evidence chains
- advisory threat scoring records
- timeline summaries and timeline events
- topology summaries
- fleet visibility summaries
- risk dashboard summaries and risk cards

Composite searches can span all supported scopes while preserving source mode and export-safe serialization.

## Safety Boundary

Phase 152 guarantees:

- no external lookups or remote search
- no packet payload inspection
- no raw packet or raw DNS history storage
- no private identifier export
- no final threat verdict fields
- no malicious labels
- no enforcement, blocking, process, service, firewall, or quarantine actions
- preview-only and destructive-action-safe records

## Milestone Y Completion

With Phase 152 complete, Milestone Y provides a metadata-only detection readiness layer:

- Phase 147 IOC intelligence records and local matching
- Phase 148 DNS threat analytics
- Phase 149 local threat signatures
- Phase 150 deterministic AI correlation chains
- Phase 151 advisory threat scoring
- Phase 152 local threat hunting queries

Future Milestone Z distributed infrastructure can consume these records as local, bounded, export-safe metadata. Any future distributed query or telemetry bus work must preserve the no-verdict, no-enforcement, no-payload, and no-external-lookup boundaries unless a separate operator-approved design explicitly changes them.
