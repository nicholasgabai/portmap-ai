# Compliance Profiles

Phase 166 adds metadata-only compliance profile readiness records and evidence expectation records. These models help operators select advisory governance modes, understand expected evidence, and review audit/export/retention/privacy boundaries without claiming certification, performing legal analysis, enforcing controls, reading private exports by default, or changing runtime behavior.

## Compliance Profile Readiness

`core_engine/governance/compliance_profiles.py` defines compliance profile records for internal audit, privacy review, security review, incident review, enterprise readiness, custom, and unknown profile types.

Each profile includes:

- Evidence expectations.
- Audit requirements.
- Retention expectations.
- Privacy requirements.
- Export requirements.
- Operator responsibilities.
- Advisory notes.

Profile states are ready, advisory, incomplete, degraded, unavailable, and unknown. `certification_claimed` is always false.

## Evidence Expectations

`core_engine/governance/evidence_profiles.py` defines evidence expectation records for audit events, runtime logs, export summaries, policy reviews, remediation previews, configuration snapshots, security reviews, and unknown evidence types.

Each evidence profile describes expected sources, required fields, retention expectation days, whether redaction is required, whether export is required, validation recommendations, and advisory notes. Evidence records do not read files by default and do not perform destructive operations.

## Audit, Export, Retention, And Privacy Boundaries

Compliance profiles consume Phase 165 audit logging governance concepts, including audit events, Last Export Summary records, export validation summaries, daily log rotation readiness, retention previews, and redaction expectations.

These records are planning contracts only. They summarize expectations and operator responsibilities without enforcing controls, deleting records, modifying runtime behavior, or storing private identifiers.

## Certification Boundary

Compliance profiles do not claim legal compliance, certification, authorization, or legal sufficiency. They are advisory readiness models for operator review.

## Phase 167 Path

Phase 167 Data Governance Controls can consume compliance profile and evidence expectation records to build data classification summaries, privacy boundary records, retention control previews, and export redaction readiness without changing runtime behavior.
