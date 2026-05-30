# Behavioral Intelligence Operator Summary

Phase 110 adds a unified operator-facing behavior summary for Milestone R. It combines local historical flow baselines, temporal anomaly windows, service behavior fingerprints, DNS and destination behavior learning, and adaptive risk weighting into dashboard/API-safe and export-ready records.

This layer is advisory-only. It does not capture payloads, store credentials, call reputation services, apply firewall rules, block traffic, modify packets, install services, or execute remediation.

## Inputs

Behavioral intelligence summaries can combine these local reports:

- Historical flow baseline reports.
- Temporal anomaly reports.
- Service behavior fingerprint reports.
- DNS and destination behavior reports.
- Adaptive risk reports.
- Optional gateway validation state summaries.

All inputs are metadata-only and should use sanitized source references such as `telemetry:example` or `finding:example`.

## Summary Records

`core_engine.telemetry.behavior_summary` builds:

- Component rollups for baselines, anomalies, service fingerprints, DNS/destination behavior, and adaptive risk.
- Supported, degraded, and unavailable state summaries.
- Operator recommendation records.
- Advisory explanation records.
- Privacy and safety field summaries.
- Export-ready behavioral intelligence dictionaries with deterministic digests.
- Dashboard and local API-compatible dictionaries.

`core_engine.telemetry.behavior_operator_views` builds operator views and status panels from the unified summary.

## State Model

Component states are intentionally simple:

- `supported` means the component provided records and does not currently require operator review.
- `degraded` means the component provided records with review hints or provided an empty report.
- `unavailable` means the component summary was not provided.

The overall state is `supported` only when every component is supported. Missing or review-required component summaries make the overall state `degraded`; missing every component makes it `unavailable`.

## Recommendations

Recommendations are advisory records only. They identify whether an operator should:

- Provide missing sanitized component summaries.
- Review advisory behavior changes.
- Continue local behavior monitoring.

Recommendations include `enforcement_allowed: false` and do not create policy approvals or remediation actions.

## Dashboard And API

The unified summary exposes:

- Component state rows.
- Record counts.
- Recommended review counts.
- Average confidence.
- Privacy and safety fields.
- Export digest status.

The existing live telemetry operator summary can include the unified behavioral intelligence panel without replacing the Textual TUI.

## Privacy And Safety

Public docs and test fixtures must not include real IP addresses, MAC addresses, usernames, hostnames, private paths, packet payloads, credentials, runtime logs, screenshots, local databases, cache files, or private validation notes.

The summary records include safety fields confirming:

- `advisory_only: true`
- `dry_run_safe: true`
- `metadata_only: true`
- `automatic_enforcement: false`
- `automatic_blocking: false`
- `firewall_changes: false`
- `external_reputation_calls: false`
- `raw_payload_stored: false`
- `credentials_stored: false`

## Validation Checklist

- Build a complete behavioral intelligence summary from sanitized component reports.
- Build empty and degraded summaries.
- Confirm adaptive risk, anomaly, fingerprint, and destination rollups are displayed.
- Confirm operator recommendations and explanations are advisory-only.
- Confirm export summaries include deterministic digests.
- Confirm dashboard/API dictionaries contain no raw payloads or private identifiers.
- Run the full test suite, diff whitespace check, sensitive-data scan, and artifact/private-file check before committing.
