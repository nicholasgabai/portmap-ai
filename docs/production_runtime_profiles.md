# Production Runtime Profiles

Phase 117 adds deployment runtime profile records for production-safe planning. These profiles describe intended runtime posture and compatibility requirements before an operator installs services, changes host settings, or enables long-running operation.

This feature is metadata-only. It does not install services, create launch agents, create systemd units, modify Windows services, change firewall rules, request elevation, store credentials, collect host identifiers, or enable packet capture.

## Profile Types

The deployment profile catalog includes five profile names:

- `development` - local dry-run profile for developer fixtures and lightweight history.
- `staging` - pre-production profile for validating multi-node readiness with review gates.
- `production` - conservative profile with explicit operator review and stronger resource expectations.
- `edge` - bounded resource profile for Raspberry Pi and Linux edge nodes.
- `lab` - isolated temporary profile for sanitized validation fixtures.

Each profile includes:

- `profile_name`
- `safety_mode`
- `telemetry_level`
- `orchestration_mode`
- `remediation_mode`
- `history_retention_mode`
- `resource_budget`
- `platform_support`
- `deployment_modes`
- `capability_flags`
- `configuration_readiness_flags`
- `advisory_notes`

All records include safety fields such as `metadata_only`, `dry_run`, `automatic_changes: false`, `service_installed: false`, `firewall_rules_changed: false`, `credentials_stored: false`, and `hardware_fingerprint_included: false`.

## Compatibility Validation

`core_engine.deployment.profile_validation` validates a profile against sanitized operator-supplied compatibility inputs:

- operating system family
- available memory
- available disk
- packet capture readiness summary
- firewall provider readiness summary
- deployment mode

Validation returns one of three states:

- `supported` - supplied inputs meet the profile requirements.
- `degraded` - deployment may be possible but requires operator review.
- `unsupported` - supplied inputs do not satisfy profile requirements.

The validator produces operator-readable advisories, dashboard/API dictionaries, and export-safe summaries. It does not inspect unique machine identifiers, collect hardware serials, read MAC addresses, store credentials, or perform host changes.

## Safety Philosophy

Production runtime profiles are advisory-first. They make deployment posture explicit without executing deployment actions. A `production` profile can report readiness, but service lifecycle work remains preview-only until a later operator-approved phase.

Deployment profile validation is designed to answer:

- whether the selected profile fits the platform family
- whether resource budgets are sufficient
- whether packet capture and firewall readiness have been reviewed
- whether the deployment mode matches the profile
- what the operator should review before proceeding

It is not designed to:

- install or start services
- modify firewall providers
- enable packet capture
- store credentials
- collect private identifiers
- perform automatic remediation

## Example Summary

Sanitized example:

```json
{
  "profile_name": "production",
  "state": "degraded",
  "deployment_mode": "master",
  "operator_review_required": true,
  "automatic_changes": false,
  "service_installed": false,
  "firewall_rules_changed": false,
  "credentials_stored": false
}
```

Use deployment profiles as a planning layer before service lifecycle previews, deployment manifests, upgrade planning, backup/restore planning, and final deployment operator summaries.
