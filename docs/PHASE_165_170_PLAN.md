# Phase 165-170 Compliance And Governance Plan

Milestone AB adds operator accountability, privacy controls, audit readiness, governance profiles, security review models, and legal/privacy safeguards while preserving PortMap-AI's metadata-first, export-safe, operator-controlled architecture.

## Milestone AB: Compliance And Governance

Goal:
Add operator accountability, privacy controls, audit readiness, governance profiles, security review models, and legal/privacy safeguards while preserving PortMap-AI's metadata-first, export-safe, operator-controlled architecture.

All work should remain:

- metadata-only
- export-safe
- privacy-aware
- advisory-first
- operator-controlled
- compatible with current runtime and TUI behavior
- free of destructive deletion, credential storage, legal certification claims, enforcement, firewall/process/service changes, and private identifiers in docs or exports

## Current Starting Point

Implemented foundation available before Phase 165:

- Milestone T provides deployment operator summaries, upgrade readiness, backup/restore planning, and runtime profile records.
- Milestone U provides secure identity, RBAC, tamper detection, secure update, rollback readiness, and redaction-oriented security records.
- Milestone W provides approval gates, rollback gates, safety guardrails, and supervised enforcement-mode previews without action execution.
- Milestone X provides visualization and operator summary models suitable for future compliance dashboards.
- Milestone Y provides metadata-only intelligence, scoring, and hunting records without verdicts or enforcement.
- Milestone AA provides packaging, updater, deployment wizard, rollback, uninstall, and validation readiness records.

Milestone AB should turn existing audit, export, review, and privacy boundaries into governance planning contracts before any compliance workflows make legal, certification, deletion, or enforcement claims.

## Roadmap Notes

- Daily rotating logs should be added under Phase 165.
- Last Export Summary should be added under Phase 165.
- Runtime Export Validation Panel should be added later when the TUI gains tabbed or multi-screen navigation, not forced into the current dashboard.

## Phase 165 - Audit Logging

Status: Complete baseline

Goal:
Model audit logging readiness, daily rotation, audit event summaries, export validation summaries, last export summaries, and log retention previews without destructive log deletion.

Build:

- `core_engine/governance/audit_events.py`
- `core_engine/governance/log_rotation.py`
- `core_engine/governance/export_audit.py`
- `tests/test_audit_logging_governance.py`
- `docs/audit_logging_governance.md`

Features:

- Audit event records for runtime, export, operator action, policy review, remediation preview, configuration, packaging, security review, and unknown categories.
- Daily log rotation readiness records for master, worker, audit, export, runtime, TUI, and unknown log families.
- Last Export Summary records.
- Export validation summaries with expected, observed, and missing file summaries.
- Schema validation, sensitive-data scan, and artifact/private-file check state summaries.
- Retention, compression, and deletion previews that remain advisory only.

Acceptance:

- No destructive log deletion is performed.
- No credential, token, payload, private identifier, or raw secret is stored in audit exports.
- Daily rotating logs are planned as metadata-first readiness records before runtime behavior changes are introduced.
- Last Export Summary is planned as an export-safe record.
- Runtime Export Validation Panel waits for future TUI tabbed or multi-screen navigation instead of crowding the current dashboard.
- No file movement, filesystem write, compression, zip extraction, private export read, remediation execution, firewall/process/service change, credential storage, private identifier export, or runtime behavior change is performed.

## Phase 166 - Compliance Profiles

Status: Complete baseline

Goal:
Model compliance profile records, evidence handling expectations, and audit export readiness without making legal claims or certification statements.

Build:

- `core_engine/governance/compliance_profiles.py`
- `core_engine/governance/evidence_profiles.py`
- `tests/test_compliance_profiles.py`
- `docs/compliance_profiles.md`

Features:

- Compliance profile records for internal audit, privacy review, security review, incident review, enterprise readiness, custom, and unknown modes.
- Evidence expectation records for audit events, runtime logs, export summaries, policy reviews, remediation previews, configuration snapshots, security reviews, and unknown evidence.
- Audit, export, retention, and privacy expectation summaries.
- Operator responsibility summaries.
- Export-safe serialization with `certification_claimed` fixed to false.

Acceptance:

- No legal certification claim is made.
- Compliance profiles remain operator guidance, not compliance guarantees.
- Evidence handling records remain metadata-only and privacy-aware.
- No credential storage, enforcement, destructive deletion, or private identifier export is introduced.
- No file reads, legal analysis, legal claim creation, control enforcement, filesystem writes, or runtime behavior changes are performed.

## Phase 167 - Data Governance Controls

Status: Complete baseline

Goal:
Model data classification, privacy boundaries, retention controls, and export redaction readiness.

Build:

- `core_engine/governance/data_classification.py`
- `core_engine/governance/data_governance.py`
- `tests/test_data_governance_controls.py`
- `docs/data_governance_controls.md`

Complete baseline:

- Data classification records for runtime, audit, export, configuration, operator action, topology, intelligence, and unknown metadata categories.
- Sensitivity and handling state normalization for public, internal, sensitive, restricted, allowed, redaction-required, review-required, restricted, and unknown states.
- Privacy boundary summaries that preserve private identifier export blocks.
- Retention control summaries that preview retention expectations without deletion.
- Redaction readiness summaries that list expected redaction categories without reading private exports.
- Export governance summaries that preserve sensitive-data and artifact-check expectations.
- Compliance profile and audit summary integration from Phases 165-166.
- Export-safe serialization with fixed preview-only and non-destructive safety fields.

Acceptance:

- Redaction readiness remains preview-only until separate runtime/export implementation phases authorize changes.
- No private identifiers are introduced into docs or exports.
- No destructive retention or deletion action is performed.
- No firewall, process, service, collection, or enforcement behavior is changed.
- No governance enforcement, private export reads by default, filesystem reads, filesystem writes, credential storage, or runtime behavior changes are performed.

## Phase 168 - Operator Accountability

Status: Complete baseline

Goal:
Model operator action records, approval summaries, role/action mapping, and review trail readiness.

Build:

- `core_engine/governance/operator_actions.py`
- `core_engine/governance/operator_accountability.py`
- `tests/test_operator_accountability.py`
- `docs/operator_accountability.md`

Complete baseline:

- Metadata-only operator action records for export, policy review, remediation preview, configuration review, packaging review, governance review, security review, compliance review, and unknown action categories.
- Approval state summaries for approved, pending, review-required, rejected, and unknown actions.
- Reviewer chain summaries that count sanitized reviewer references without storing real identities.
- Role mapping summaries that infer advisory review scopes without assigning roles.
- Accountability evidence summaries that combine action evidence, audit references, governance references, compliance profile summaries, and audit summaries.
- Integration with Phase 165 audit summaries, Phase 166 compliance profiles, and Phase 167 data governance summaries.
- Export-safe serialization with fixed preview-only and non-destructive safety fields.

Acceptance:

- Operator accountability records avoid usernames, hostnames, private IPs, and other private identifiers in public docs and exports.
- Role/action summaries remain metadata-only and export-safe.
- No service, process, firewall, credential, enforcement, or runtime behavior change is made.
- Approval records remain advisory until future operator-approved workflow phases explicitly enable action execution.
- No authorization decisions, permissions enforcement, role assignment, identity storage, file reads, file writes, or private export reads are performed.

## Phase 169 - Security Review Framework

Status: Planned

Goal:
Model security checklist records, package/runtime/security review summaries, and deployment review readiness.

Build:

- Security checklist records.
- Package review summaries.
- Runtime review summaries.
- Security review summaries.
- Deployment review readiness records.

Acceptance:

- Reviews summarize readiness and gaps without executing remediation.
- No installer, service, firewall, process, package, update, deletion, or enforcement action is performed.
- Review outputs remain export-safe and free of credentials, payloads, private identifiers, and legal certification claims.

## Phase 170 - Privacy And Legal Safeguards

Status: Planned

Goal:
Model privacy-safe export summaries, consent/operator notice records, and legal safeguard notes without legal advice or certification claims.

Build:

- Privacy-safe export summaries.
- Consent/operator notice records.
- Legal safeguard note records.
- Privacy review readiness summaries.
- Legal boundary summaries.

Acceptance:

- Records do not provide legal advice.
- Records do not claim certification, compliance, authorization, or legal sufficiency.
- Operator notice and consent records remain advisory metadata.
- No private identifiers, credentials, raw payloads, destructive deletion, enforcement, or runtime behavior changes are introduced.

## Safety Boundaries

Milestone AB must not:

- perform destructive deletion
- store credentials, secrets, certs, keys, or tokens
- make legal advice, legal sufficiency, compliance certification, or certification-readiness claims
- execute enforcement
- modify firewall, process, service, routing, worker, installer, package, update, or collection state
- expose private identifiers in docs or exports
- force new panels into the current dashboard when a tabbed or multi-screen TUI is required for clear validation
- break existing `portmap stack`, `portmap tui`, runtime export, dashboard, or packaging behavior

## Validation Checklist

- Audit, compliance, governance, accountability, security review, and privacy safeguard records are metadata-only.
- Daily rotating logs and Last Export Summary remain Phase 165 readiness plans until implemented safely.
- Runtime Export Validation Panel remains deferred to future tabbed or multi-screen TUI navigation.
- Export summaries are redaction-aware and private-identifier safe.
- No deletion, enforcement, credential storage, legal certification claim, firewall/process/service change, or runtime behavior change is introduced.
- Current runtime, TUI, dashboard, CLI entry points, packaging metadata, and docs packaging remain valid.
- Sensitive-data scans and artifact/private-file checks are clean before commit.
