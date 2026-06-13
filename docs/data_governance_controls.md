# Phase 167 - Data Governance Controls

Phase 167 adds metadata-only data governance controls for classifying PortMap-AI records, describing privacy boundaries, previewing retention expectations, and summarizing redaction/export readiness.

The implementation is advisory-first. It does not enforce controls, delete data, read private exports by default, write files, modify runtime behavior, store credentials, or export private identifiers.

## Classification Records

`core_engine/governance/data_classification.py` defines data classification records with category, sensitivity, handling state, redaction, retention, export, source-mode, and governance note fields.

Supported data categories are:

- `runtime_metadata`
- `audit_metadata`
- `export_metadata`
- `configuration_metadata`
- `operator_action_metadata`
- `topology_metadata`
- `intelligence_metadata`
- `unknown`

Supported sensitivity levels are:

- `public`
- `internal`
- `sensitive`
- `restricted`
- `unknown`

Supported handling states are:

- `allowed`
- `redaction_required`
- `review_required`
- `restricted`
- `unknown`

Unknown or malformed category, sensitivity, and handling inputs normalize to `unknown`. Generated records remain export-safe and include fixed `preview_only=True` and `destructive_action=False` fields.

## Governance Summaries

`core_engine/governance/data_governance.py` defines governance control summaries that combine classification rows with optional Phase 165 audit summaries and Phase 166 compliance profile records.

Governance summaries include:

- privacy boundary summaries
- retention control summaries
- redaction readiness summaries
- export governance summaries
- compliance profile summaries
- audit summaries
- governance recommendations

Supported governance states are:

- `ready`
- `review_recommended`
- `restricted`
- `degraded`
- `unavailable`
- `unknown`

## Redaction Readiness

Redaction readiness is a summary of expected redaction categories, not a redaction engine. It records whether categories such as configuration metadata, topology metadata, intelligence metadata, or operator action metadata require review before export.

The summary does not inspect raw payloads, credentials, raw DNS history, local files, databases, private exports, or live runtime data.

## Retention And Export Governance

Retention control summaries preview how many classifications expect retention handling and what retention duration is implied by connected compliance profiles. Deletion remains explicitly disallowed.

Export governance summaries describe whether export review, sensitive-data scanning, and artifact checks are expected. They do not read export bundles or authorize private identifier export.

## Safety Boundary

Phase 167 preserves these boundaries:

- metadata-only records and summaries
- no governance enforcement
- no data deletion
- no private export reads by default
- no filesystem reads or writes
- no credential storage
- no private identifier export
- no firewall, process, service, collection, or runtime behavior changes

## Phase 168 Path

Phase 168 Operator Accountability can consume data governance summaries to link operator actions, approvals, roles, and review trails to the same metadata-only privacy and export boundaries.
