# Resource Optimization

Phase 156 adds metadata-only resource optimization planning records for larger PortMap-AI deployments. The implementation summarizes CPU, memory, storage, telemetry, and worker utilization, then produces adaptive sampling previews, load-shedding previews, deployment budget guidance, and optimization readiness summaries without changing runtime behavior.

## Deployment Budgets

Resource budget records describe advisory deployment capacity. They do not enforce limits or alter runtime settings.

Supported budget types:

- `edge`
- `workstation`
- `server`
- `enterprise`
- `unknown`

Each budget records CPU budget percent, memory budget in MB, storage budget in MB, telemetry budget per minute, worker budget count, source modes, advisory notes, and fixed safety flags. Values are bounded and invalid inputs normalize into export-safe records.

## Optimization Readiness

Optimization summaries can consume:

- Phase 153 telemetry bus summaries.
- Phase 154 storage summaries.
- Phase 155 horizontal scaling summaries.
- Optional CPU, memory, storage, telemetry, and worker usage estimates.

The summary reports CPU, memory, storage, telemetry, and worker utilization ratios along with sanitized upstream summaries and recommendations.

Supported optimization states:

- `optimized`
- `growth_ready`
- `constrained`
- `degraded`
- `unavailable`
- `unknown`

## Adaptive Sampling Preview

Adaptive sampling previews identify resource pressure that could justify later operator-approved sampling changes. Phase 156 does not change sampling, collection logic, telemetry routing, or runtime configuration.

## Load-Shedding Preview

Load-shedding previews identify constrained resources that may need future operator review. Phase 156 does not throttle telemetry, drop telemetry, stop workers, modify worker counts, or execute any runtime action.

## Safety Boundary

Phase 156 remains:

- metadata-only
- source-mode preserving
- bounded by deployment budgets and upstream summaries
- export-safe
- preview-only and advisory-first
- free of telemetry throttling
- free of sampling changes
- free of worker-count changes
- free of runtime behavior changes
- free of collection logic changes
- free of infrastructure changes and cloud resource creation
- free of raw payload storage, credential storage, private identifier export, remediation, enforcement, firewall changes, process changes, and service changes

## Future Consumption

Phase 157 can use optimization summaries to select edge-safe worker modes and offline/degraded behavior. Phase 158 can use the same budget and pressure records to preview cloud relay capacity without starting a live relay, provisioning cloud resources, or introducing a SaaS control plane.
