# Release Candidate Checklist

## Purpose

This checklist gives maintainers and evaluators a compact local readiness review before a release candidate.

## Checklist

- Full test suite passes with `python -m pytest`.
- Focused tests pass for any changed subsystem.
- `git diff --check` passes.
- Roadmap completion notes match implemented scope.
- Public docs contain no private validation notes, secrets, tokens, or local machine paths.
- Packet intelligence remains metadata-only.
- AI intelligence remains advisory and deterministic.
- Export, governance, deployment, licensing, provisioning, and control-plane models remain local unless a later phase authorizes hosted behavior.
- Unrelated files are excluded from commits.

## Safety Notes

Release candidate review should not start services, publish artifacts, push telemetry, change firewall rules, perform remediation, or run privileged capture unless a separate operator-approved process covers that action.

## Current Limitations

This checklist is a local readiness aid. It does not replace platform signing, package notarization, enterprise acceptance testing, or legal review.

## Related Docs

- [Release Candidate](../release_candidate.md)
- [Developer Guide](developer_guide.md)
- [Governance Guide](governance_guide.md)
- [Deployment Guide](deployment_guide.md)
