# Phase 147-152 Threat Intelligence And Detection Expansion Plan

Milestone Y extends PortMap-AI from visual intelligence into metadata-only threat intelligence and detection readiness. The focus is IOC records, DNS threat analytics, local signatures, AI correlation records, expanded advisory scoring, and local threat-hunting query models that can support future security workflows without external lookups, enforcement, blocking, or final threat verdicts.

This is a planning document only. It does not contact threat feeds, store packet payloads, retain raw DNS history, modify firewalls, stop processes, disable services, execute remediation, quarantine nodes, store credentials, create threat verdicts, or perform destructive automation.

## Milestone Y: Threat Intelligence And Detection Expansion

Goal:
Extend PortMap-AI from visual intelligence into metadata-only threat intelligence and detection readiness by adding IOC models, DNS threat analytics, signatures, AI correlation records, expanded threat scoring, and threat-hunting query models without enforcement, blocking, external lookups, or live threat verdicts.

All work should remain:

- metadata-only
- advisory-first
- local-first
- source-mode preserving
- bounded
- export-safe
- dry-run safe
- privacy-preserving
- Raspberry Pi/Linux ARM compatible
- macOS/Linux/Windows aware
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 147:

- Milestone V provides reconstructed sessions, flow summaries, metadata correlations, process/service correlations, relationship edges, attribution candidates, drift records, trust-zone records, dependency records, and source-mode-safe live runtime bridge summaries.
- Milestone W provides advisory policy evaluations, remediation previews, incident candidates, provider readiness, safety guardrails, rollback simulations, and enforcement-mode models.
- Milestone X provides topology graphs, historical timeline windows, asset inventory summaries, risk dashboard cards, fleet visibility panels, and visualization operator/readiness records.
- Behavioral and historical intelligence layers provide local baselines, temporal anomalies, service fingerprints, DNS/destination learning, adaptive risk weighting, historical snapshots, aging/decay, replay windows, and retention summaries.

Milestone Y should add threat-intelligence-ready model contracts and local matching/correlation records. It should not introduce remote threat feeds, external reputation lookups, autonomous verdicts, active blocking, or host/network changes.

## Phase 147 - IOC Intelligence Framework

Status: Complete Baseline

Goal:
Build metadata-only IOC records, inventories, matching summaries, and export-safe rollups for locally supplied indicators.

Build:

- `core_engine/intelligence/ioc_records.py`
- `core_engine/intelligence/ioc_inventory.py`
- `core_engine/intelligence/ioc_matching.py`
- `core_engine/intelligence/ioc_exports.py`
- `tests/test_ioc_intelligence_framework.py`
- `docs/ioc_intelligence_framework.md`

Features:

- IOC records with indicator class, source classification, confidence, source mode, redacted previews, value hashes, and advisory notes.
- IOC inventory summaries with bounded retention and export-safe dictionaries.
- IOC matching against DNS, flow, socket, process, TLS metadata, packet metadata, topology, and manual source classifications.
- IOC match records with match state, confidence, evidence references, and no verdict fields.
- IOC export summaries for dashboard/API/export consumers.
- Malformed IOC handling with degraded/invalid records.
- JSON-safe and CSV-row-safe dictionaries.

Acceptance:

- IOC records are deterministic from sanitized fixtures.
- Source classifications include `dns`, `flow`, `socket`, `process`, `tls`, `packet`, `topology`, and `manual`.
- Matching remains metadata-only and advisory.
- No external threat-feed lookup or reputation query is performed.
- No raw payloads, credentials, raw DNS history, private identifiers, or enforcement actions are introduced.
- No malicious flag or threat verdict field is emitted.

## Phase 148 - DNS Threat Analytics

Status: Complete baseline

Goal:
Build DNS behavior risk summaries and suspicious DNS indicator records from redacted or hashed metadata without storing raw DNS browsing history.

Build:

- `core_engine/intelligence/dns_analytics.py`
- `core_engine/intelligence/domain_patterns.py`
- `tests/test_dns_threat_analytics.py`
- `docs/dns_threat_analytics.md`

Features:

- DNS behavior risk summaries.
- Domain pattern analysis using sanitized, redacted, or hashed summaries.
- Resolver behavior summaries.
- Suspicious DNS indicator records.
- DNS recurrence and drift references from existing DNS/destination learning.
- Advisory confidence and limitation fields.
- Dashboard/API/export-safe DNS threat dictionaries.

Acceptance:

- Raw DNS browsing history is not stored.
- Domain examples in docs are sanitized placeholders only.
- Resolver and destination summaries remain metadata-only.
- Suspicious indicators are advisory signals, not threat verdicts.
- No external DNS reputation service or remote lookup is called.
- Domain previews are hash-prefixed and export-safe.
- IOC inventory and match records are consumed locally without remote feeds.
- No blocking, malicious flags, or enforcement records are emitted.

## Phase 149 - Threat Signature Framework

Status: Planned

Goal:
Build local metadata-only threat signature records and deterministic matching summaries without remote feeds.

Build:

- `core_engine/threat/signatures.py`
- `core_engine/threat/signature_matching.py`
- `tests/test_threat_signature_framework.py`
- `docs/threat_signature_framework.md`

Features:

- Local signature records with signature class, match fields, severity, confidence, source mode, and advisory notes.
- Metadata-only matching against flow, DNS, process, service, TLS metadata, topology, attribution, drift, and asset summaries.
- Rule confidence summaries.
- Signature bundle summaries.
- Invalid and unsupported signature handling.
- Dashboard/API/export-safe signature dictionaries.

Acceptance:

- Signature matching is deterministic and bounded.
- Rule confidence stays within bounded scoring ranges.
- No remote feed loading is introduced.
- No payload inspection, raw packet storage, raw DNS history, credential storage, or enforcement behavior is introduced.

## Phase 150 - AI Correlation Layer

Status: Planned

Goal:
Build multi-signal correlation records and evidence chains that combine IOC, DNS, signature, flow, attribution, drift, topology, policy, risk, and runtime context without autonomous verdicts.

Build:

- `core_engine/threat/ai_correlation.py`
- `core_engine/threat/evidence_chains.py`
- `tests/test_ai_correlation_layer.py`
- `docs/ai_correlation_layer.md`

Features:

- Multi-signal correlation records.
- Evidence chain records with bounded evidence references.
- Confidence summaries and signal agreement summaries.
- Conflict and uncertainty summaries.
- Source-mode preservation.
- Dashboard/API/export-safe correlation dictionaries.
- Empty/degraded/unavailable state handling.

Acceptance:

- Correlation records do not produce final threat verdicts.
- Evidence chains reference export-safe IDs and summaries only.
- Confidence scoring is bounded and deterministic.
- No payload inspection, external services, autonomous remediation, or enforcement is introduced.

## Phase 151 - Threat Scoring Expansion

Status: Planned

Goal:
Expand advisory threat scoring inputs to include IOC, signature, DNS threat analytics, AI correlation, drift, topology, attribution, policy, and remediation-preview context.

Build:

- `core_engine/threat/threat_scoring.py`
- `core_engine/threat/scoring_weights.py`
- `tests/test_threat_scoring_expansion.py`
- `docs/threat_scoring_expansion.md`

Features:

- Expanded scoring input records.
- IOC, signature, DNS, and correlation weighting helpers.
- Advisory risk scoring only.
- Confidence dampening for low-quality or conflicting evidence.
- Safety and limitation summaries.
- Dashboard/API/export-safe scoring dictionaries.

Acceptance:

- Scores remain bounded and deterministic.
- Low-confidence evidence dampens score movement.
- Threat scoring does not become a final verdict.
- No blocking, firewall, process, service, quarantine, or remediation action is executed.

## Phase 152 - Threat Hunting Queries

Status: Planned

Goal:
Build local query model records, hunt result summaries, and saved hunt templates for metadata-only threat hunting without external search.

Build:

- `core_engine/threat/hunt_queries.py`
- `core_engine/threat/hunt_results.py`
- `tests/test_threat_hunting_queries.py`
- `docs/threat_hunting_queries.md`

Features:

- Local hunt query model records.
- Saved hunt templates.
- Hunt result summaries.
- Query scope, source mode, confidence, and limitation fields.
- Bounded result windows.
- Dashboard/API/export-safe hunt dictionaries.
- Malformed query handling.

Acceptance:

- Queries run only against local metadata records supplied by callers.
- No external search or remote feed lookup is introduced.
- Results are bounded and export safe.
- Private identifiers, raw payloads, raw DNS history, credentials, certs, keys, logs, screenshots, runtime artifacts, and databases are not stored in docs or exports.

## Milestone Y Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Run `python -m pytest`.
- Run `git diff --check`.
- Review staged diffs.
- Run a sensitive-data scan.
- Run an artifact/private-file check.
- Confirm `docs/real_device_validation.md` remains unstaged.
- Confirm `testfile.txt` remains unstaged if present.
- Confirm no logs, artifacts, screenshots, caches, runtime outputs, databases, private credentials, certificates, or keys are staged.
- Confirm docs contain no real hostnames, address literals, usernames, hardware identifiers, SSH details, tokens, credentials, certificates, keys, or private paths.
- Confirm all records preserve source mode.
- Confirm IOC, DNS, signature, correlation, scoring, and hunt records remain bounded.
- Confirm no live enforcement, firewall changes, service actions, process actions, external lookups, packet payload storage, raw packet storage, or raw DNS history is introduced.

## macOS Validation Checklist

- Generate IOC records from sanitized fixtures.
- Generate DNS threat summaries from redacted or hashed DNS summaries.
- Generate local signature matches from metadata-only fixtures.
- Generate AI correlation and evidence chain records from sanitized Milestone V, W, and X summaries.
- Generate advisory threat scores without verdict fields.
- Generate local hunt query and result records without external search.
- Confirm package docs and tests include the new plan.

## Raspberry Pi / Linux ARM Validation Checklist

- Pull only after the Mac push succeeds.
- Run focused threat model tests if full-suite runtime constraints require it.
- Validate bounded IOC inventory and hunt result generation with small fixtures.
- Validate scoring and correlation stay resource-conscious.
- Confirm CPU and RAM remain stable for repeated model generation.
- Confirm no logs, runtime outputs, databases, private validation artifacts, credentials, certs, or keys are staged.

## Linux Validation Checklist

- Validate Linux runtime metadata can feed IOC, signature, DNS, scoring, and hunting fixture records.
- Confirm no firewall, service, process, quarantine, or enforcement action is modeled as completed.
- Confirm export dictionaries remain deterministic and sanitized.

## Windows Compatibility Fixture Checklist

- Validate Windows-style process, socket, service, and runtime summaries through sanitized fixtures only.
- Validate IOC, signature, scoring, and hunt result dictionaries from fixtures.
- Confirm no registry, service, firewall, credential, certificate, key, installer, external lookup, or browser action is modeled as completed.

## Safety Notes

- Milestone Y is not an enforcement milestone.
- Milestone Y does not produce final threat verdicts.
- Milestone Y does not call external threat feeds or reputation services.
- Milestone Y does not inspect or store packet payloads.
- Milestone Y does not store raw DNS browsing history.
- Milestone Y prepares metadata-only detection contracts for future supervised security workflows.
