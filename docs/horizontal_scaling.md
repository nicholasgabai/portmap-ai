# Horizontal Scaling

Phase 155 adds metadata-only horizontal scaling planning records for larger PortMap-AI deployments. The implementation describes worker groups, cluster sizing, shard planning, partition readiness, capacity forecasts, fanout readiness, and scaling recommendations without provisioning infrastructure, creating clusters, changing telemetry routing, or calling cloud APIs.

## Worker Groups

Worker group records summarize planned worker capacity. They are export-safe and do not change runtime worker counts.

Supported group types:

- `collector`
- `analysis`
- `visualization`
- `intelligence`
- `relay_preview`
- `unknown`

Supported health states:

- `healthy`
- `degraded`
- `unavailable`
- `unknown`

Each group records current worker count, maximum worker count, source modes, health state, capacity weight, advisory notes, and fixed safety flags. Counts are bounded and invalid inputs are normalized into safe degraded records.

## Scaling Readiness

Horizontal scaling summaries combine worker groups with Phase 153 telemetry bus summaries and Phase 154 storage summaries. They report current cluster size, recommended cluster size, shard and partition previews, capacity summaries, storage pressure, bus queue pressure, worker distribution, fanout readiness, and advisory recommendations.

Supported scaling states:

- `ready`
- `growth_ready`
- `capacity_pressure`
- `degraded`
- `unavailable`
- `unknown`

Capacity pressure can come from queue utilization, storage utilization, degraded groups, or unavailable capacity. Recommendations remain previews only and never create infrastructure.

## Shard And Partition Previews

Shard counts are derived from cluster size, utilization pressure, and storage tier presence. Partition previews combine shard count, telemetry topic breadth, and storage tier count. These are planning records for future worker coordination and do not modify telemetry routing.

## Safety Boundary

Phase 155 remains:

- metadata-only
- source-mode preserving
- bounded by worker, shard, partition, queue, and storage summaries
- export-safe
- preview-only and advisory-first
- free of infrastructure provisioning
- free of cluster creation
- free of cloud APIs and cloud resource creation
- free of runtime worker-count changes
- free of telemetry routing changes
- free of raw payload storage, credential storage, private identifier export, remediation, enforcement, firewall changes, process changes, and service changes

## Future Consumption

Phase 156 can consume scaling summaries to build resource optimization and load-shedding previews. Phase 157 can use worker group and shard plans for edge worker modes. Phase 158 can use relay-preview groups and fanout readiness for cloud relay infrastructure readiness without starting a live relay or SaaS control plane.
