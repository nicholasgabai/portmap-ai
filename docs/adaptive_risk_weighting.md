# Adaptive Risk Weighting

Phase 109 adds local, metadata-only adaptive risk weighting for behavioral intelligence summaries. It adjusts advisory scores using existing local evidence from historical baselines, temporal anomaly windows, service behavior fingerprints, and DNS/destination behavior learning.

This feature does not enforce policy, modify traffic, change firewall rules, start services, call external reputation systems, store packet payloads, store credentials, or deanonymize users.

## Scope

Adaptive risk weighting produces deterministic local records for:

- Base and adjusted advisory scores.
- Confidence values.
- Adjustment reasons.
- Baseline context.
- Temporal anomaly context.
- Service fingerprint context.
- DNS and destination context.
- Operator-readable explanations.
- Dashboard, API, operator, and export-ready summaries.

Every record includes safety fields showing that output is advisory-only, dry-run safe, metadata-only, and not eligible for automatic enforcement.

## Local Evidence Inputs

Adaptive risk records can be built from sanitized local summaries:

- Historical flow baseline reports.
- Temporal anomaly reports.
- Service behavior fingerprint reports.
- DNS and destination behavior reports.
- Existing advisory finding or telemetry score inputs.

Inputs should use source references such as `finding:example` or `telemetry:example`. Public documentation and tests must use placeholders only.

## Weighting Behavior

The weighting helpers apply small advisory score changes:

- Known stable behavior can reduce the score.
- Mature stable baselines can reduce the score further.
- Newly observed behavior can increase the score.
- Burst anomalies can increase the score.
- Unusual process, service, protocol, or port combinations can increase the score.
- Unusual resolver or destination behavior can increase the score.
- Low-confidence inputs dampen the adjustment.

Adjusted scores are clamped to the `0.0` to `1.0` range.

## Explanation Records

Each adaptive risk record includes an explanation with:

- What changed in the advisory score.
- Why the score moved.
- Which local evidence contributed.
- Why no enforcement was applied.
- Confidence and limitations.

Explanation records are designed for operator review, export bundles, dashboard panels, and future review queue context.

## Runtime Integration

Adaptive risk reports integrate with:

- Telemetry operator summaries through the `adaptive_risk_report` input.
- Dashboard/API-safe dictionaries.
- Export-ready summary records with deterministic digests.
- Behavioral intelligence summaries in Milestone R.

The integration remains read-only and does not create remediation actions.

## Validation Checklist

- Run deterministic fixture tests for score reductions, score increases, confidence dampening, score clamping, and safe explanation serialization.
- Confirm `enforcement_allowed` remains false by default.
- Confirm no raw packet payloads, credentials, usernames, hostnames, IP addresses, MAC addresses, private paths, logs, screenshots, databases, cache files, or runtime artifacts are required.
- Confirm public examples use sanitized placeholders only.
- Confirm Linux, macOS, and Windows behavior is data-model consistent.

## Safety Guarantees

- `advisory_only: true`
- `dry_run_safe: true`
- `metadata_only: true`
- `automatic_blocking: false`
- `firewall_changes: false`
- `service_changes: false`
- `packet_modification: false`
- `enforcement_allowed: false`
- `external_reputation_calls: false`
