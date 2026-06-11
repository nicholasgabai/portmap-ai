# Edge Worker Modes

Phase 157 adds metadata-only edge deployment readiness models for PortMap-AI. The implementation describes collector profiles, offline behavior, degraded operation, lightweight modes, gateway collectors, branch collectors, Raspberry Pi readiness, and Linux ARM readiness without deploying workers or changing runtime behavior.

## Edge Profiles

Edge profile records describe advisory deployment shapes for constrained and distributed environments.

Supported profile types:

- `lightweight_collector`
- `workstation_collector`
- `gateway_collector`
- `branch_collector`
- `enterprise_collector`
- `unknown`

Supported device classes:

- `raspberry_pi`
- `linux_arm`
- `linux`
- `macos`
- `windows`
- `unknown`

Each profile records bounded CPU, memory, storage, and telemetry budgets, source modes, offline support, degraded support, advisory notes, and fixed safety flags.

## Raspberry Pi And ARM Readiness

Raspberry Pi and Linux ARM profiles provide lightweight collector readiness summaries with explicit CPU, memory, storage, telemetry, offline, and degraded-mode metadata. These records do not install services, change collection settings, or start worker processes.

## Gateway And Branch Collectors

Gateway and branch collector profiles produce readiness previews for future distributed deployments. Gateway readiness summarizes topic breadth and scaling context. Branch readiness summarizes optimization and scaling state. Both remain advisory and do not change routing, provision infrastructure, create relays, or modify firewall state.

## Offline And Degraded Operation

Offline readiness identifies profiles that can be planned for disconnected operation. Degraded readiness identifies profiles that can be planned for constrained resource conditions. Phase 157 does not change runtime behavior, collection logic, sampling, worker counts, or telemetry routing.

## Safety Boundary

Phase 157 remains:

- metadata-only
- source-mode preserving
- bounded by profile budgets and upstream summaries
- export-safe
- preview-only and advisory-first
- free of worker deployment
- free of runtime behavior changes
- free of telemetry collection changes
- free of worker-count changes
- free of telemetry routing changes
- free of deployment actions
- free of infrastructure provisioning, cloud resources, and relay creation
- free of firewall, process, service, remediation, and enforcement changes

## Phase 158 Consumption

Phase 158 can consume edge worker mode summaries to decide which future relay readiness records are suitable for gateway, branch, Raspberry Pi, Linux ARM, or offline-capable deployments. The relay phase should continue to treat these as metadata-only previews and should not start a live cloud relay or SaaS control plane.
