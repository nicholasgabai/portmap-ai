# Cloud Relay Infrastructure

Phase 158 adds metadata-only cloud relay readiness models for future larger deployments. The implementation describes relay sessions, routing previews, tenant isolation previews, capacity planning, and enterprise relay readiness without creating cloud resources, forwarding telemetry, opening network connections, provisioning infrastructure, or introducing SaaS control-plane behavior.

## Relay Session Records

`core_engine.scaling.relay_sessions` defines export-safe relay session records with bounded node and topic estimates. Supported relay types are `local_preview`, `regional_preview`, `enterprise_preview`, `hybrid_preview`, and `unknown`. Supported relay states are `ready`, `degraded`, `unavailable`, and `unknown`.

Relay sessions preserve source modes and normalize malformed input into bounded advisory records. Tenant and routing scopes are sanitized labels only. Session records do not store tenant-private identifiers, credentials, certs, keys, telemetry payloads, private addresses, hostnames, usernames, or MAC addresses.

## Relay Readiness Summaries

`core_engine.scaling.cloud_relay` combines relay sessions with upstream Milestone Z summaries:

- Phase 153 telemetry bus summaries.
- Phase 154 storage readiness summaries.
- Phase 155 horizontal scaling summaries.
- Phase 156 resource optimization summaries.
- Phase 157 edge worker mode summaries.

The resulting readiness record includes a routing preview, capacity preview, tenant isolation preview, deployment recommendations, source-mode rollups, and safety fields. Readiness states include `ready`, `relay_ready`, `capacity_constrained`, `degraded`, `unavailable`, and `unknown`.

## Routing Previews

Routing previews summarize how many local, regional, enterprise, hybrid, and unknown relay routes are represented by the input sessions. They also report estimated node and topic totals, source modes, and a readiness note. These previews are planning metadata only; they do not modify routing, create relays, or forward telemetry.

## Tenant Isolation Previews

Tenant isolation previews count sanitized tenant scopes, multi-tenant preview records, unknown tenant scopes, and source modes. They are intended to support future SaaS and enterprise design work while keeping current exports safe. No SaaS tenant records, private identifiers, credentials, or tenant-private payloads are stored.

## Capacity Planning

Capacity previews combine relay session estimates with telemetry bus, storage, scaling, optimization, and edge summaries. They report estimated nodes, estimated topics, upstream queue depth, storage utilization, optimization utilization, scaling utilization, edge profile count, an aggregate utilization ratio, and capacity notes.

Capacity planning is advisory only. It does not provision infrastructure, create cloud resources, open sockets, install services, or alter worker counts.

## Safety Boundary

Phase 158 remains metadata-only and advisory-first:

- No cloud services are created.
- No relay infrastructure is created.
- No SaaS control plane is enabled.
- No network connections are opened.
- No telemetry is forwarded.
- No routing, collection, worker, firewall, process, or service state is changed.
- No credentials, certs, keys, raw payloads, raw DNS history, or private identifiers are stored in docs or exports.

## Milestone Z Completion

Phase 158 completes the Milestone Z baseline. Phases 153-158 now provide telemetry bus envelopes, high-volume storage readiness, horizontal scaling previews, resource optimization guidance, edge worker mode readiness, and cloud relay readiness as local metadata models. Milestone Z hands off to Milestone AA packaging and installers without adding live cloud, broker, relay, enforcement, or provisioning behavior.
