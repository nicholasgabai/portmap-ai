# Enterprise Cloud Orchestration Platform

Phase 40 adds local primitives for organization/workspace management, licensing and usage metrics, optional cloud synchronization manifests, and administrator-facing advisory workflows.

This phase is operational infrastructure work. This phase follows the global PortMap-AI safety guarantees. All remediation-related workflow records remain administrator-controlled review objects.

## 40A. Organization and Workspace Management

Implemented modules:

- `saas.tenancy`
- `saas.orgs`

Capabilities:

- Tenant records.
- Organization metadata.
- Team associations.
- User grouping.
- RBAC role inheritance through the existing local RBAC helper.
- Workspace configuration persistence.
- Tenant isolation checks for organizations and teams.

Workspace configuration can remain fully local. No cloud service is required.

## 40B. Licensing and Usage Metrics

Implemented module:

- `saas.licensing`

Capabilities:

- License metadata.
- Subscription tier labels.
- Feature gating.
- Usage counters.
- Quota tracking.
- Usage summaries for local reporting.

Licensing helpers are local accounting utilities. They do not contact billing providers or enforce network behavior.

## 40C. Cloud Synchronization Framework

Implemented module:

- `saas.cloud_sync`

Capabilities:

- Optional encrypted sync manifests.
- Export/import support for configuration and observability metadata.
- Offline-first compatibility flags.
- Conflict detection with `prefer_local`, `prefer_remote`, or `manual_review` policy.

Cloud synchronization remains optional. The manifest helpers do not send network requests. Operators can export/import manifests through local files or future control-plane transports.

## 40E. Advisory Workflow Engine

Implemented module:

- `core_engine.advisory.workflow`

Capabilities:

- Recommendation objects.
- Administrator review states.
- Approval transitions gated by existing RBAC permissions.
- Audit event generation through enterprise audit helpers.
- Explicit `automatic_execution: false` records.

Review workflows do not execute remediation. Approval records are human workflow metadata only.

## CLI Usage

Organization/workspace summary:

```bash
portmap workspace \
  --tenant-json '{"tenant_id":"tenant.local","name":"Local Tenant"}' \
  --org-json '{"organizations":[{"org_id":"org.ops","tenant_id":"tenant.local","name":"Ops"}]}' \
  --team-json '{"teams":[{"team_id":"team.netops","tenant_id":"tenant.local","org_id":"org.ops","name":"NetOps","roles":["analyst"],"members":["alice"]}]}' \
  --user alice
```

License usage summary:

```bash
portmap license \
  --license-json '{"license_id":"lic-1","tenant_id":"tenant.local","tier":"team","features":["cloud_sync"],"quotas":{"workspaces":2}}' \
  --usage-json '{"tenant_id":"tenant.local","counters":{"workspaces":1}}' \
  --feature cloud_sync \
  --quota workspaces
```

Encrypted sync manifest export:

```bash
portmap cloud-sync \
  --tenant-id tenant.local \
  --workspace-id workspace.local \
  --key local-sync-key \
  --payload-json '{"setting":"value"}'
```

Advisory review packet:

```bash
portmap advisory \
  --recommendation-json '{"recommendations":[{"recommendation_id":"rec-1","title":"Review workspace","summary":"Review workspace settings.","category":"configuration_review","target":"workspace.local","actions":["review settings"]}]}'
```

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. Phase 40 remains local/offline infrastructure workflow work: it creates organization, workspace, licensing, sync-manifest, and advisory review metadata without contacting cloud, billing, or identity providers by itself.

## Verification

Focused checks:

```bash
python -m pytest tests/test_enterprise_cloud_orchestration.py tests/test_cli_main.py tests/test_packaging.py
```
