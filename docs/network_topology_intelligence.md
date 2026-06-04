# Network Topology Intelligence

Phase 134 adds metadata-only topology intelligence for inferring trust zones, service dependencies, recurring communication chains, node dependencies, and topology adjacency from normalized relationship records.

This feature is advisory-only. It does not inspect packet payloads, store packets, generate PCAP files, require a graph database, actively probe the network, inject traffic, modify firewall rules, or enforce blocking.

## Trust Zones

`core_engine.topology.trust_zones` builds trust-zone records from cross-node relationship metadata.

Supported zone classes are:

- `internal`
- `management`
- `service`
- `external`
- `unknown`

Trust-zone records include:

- `trust_zone_id`
- `zone_class`
- `relationship_count`
- `confidence_score`
- `drift_detected`
- `relationship_references`
- `source_modes`
- `advisory_notes`

Zone inference uses relationship metadata such as node classes, relationship type, shared service state, topology distance, and drift flags. Management relationships usually involve orchestrator or master roles. Service zones are inferred from shared service or dependency relationships. External zones are inferred from external node classes or external adjacency labels.

## Dependency Mapping

`core_engine.topology.dependency_mapping` builds dependency records from normalized relationship records.

Supported dependency types are:

- `service_dependency`
- `communication_chain`
- `node_dependency`
- `topology_adjacency`
- `management_dependency`
- `external_dependency`
- `unknown`

Dependency records include:

- `dependency_id`
- `dependency_type`
- `relationship_reference`
- `relationship_strength`
- `recurrence_score`
- `confidence_score`
- `topology_distance`
- `topology_adjacency`
- `source_mode`
- `advisory_notes`

The dependency mapper uses relationship strength, recurrence, shared service state, topology distance, source and target node classes, and relationship type. Output is suitable for dashboard panels, local API responses, and export bundles.

## Topology Intelligence

Phase 134 connects reconstructed flows, cross-node relationship graphs, behavioral drift hints, and historical topology context into lightweight topology structure records. It can identify:

- likely management relationships
- recurring service dependencies
- direct topology adjacency
- external service dependencies
- internal node dependency relationships
- drifted topology or dependency records that need review

These records are not threat verdicts. They describe structure and confidence so an operator can review how the network appears to be organized.

## Future Enterprise Graphing Path

The records created in this phase are graph-ready, but they do not require a graph database. Future enterprise graphing can use the same export-safe dictionaries to draw trust zones, dependency paths, and topology adjacency while preserving the current local-first, metadata-only safety model.

## Safety Boundaries

Phase 134 preserves the PortMap-AI safety model:

- local-first
- metadata-only
- advisory-only
- source-mode aware
- export-safe
- no payload inspection
- no raw packet storage
- no PCAP generation
- no graph database dependency
- no active probing
- no traffic injection
- no firewall or router changes
- no automatic enforcement

Public examples should use sanitized references such as `relationship-redacted-001`, `flow-redacted-001`, and `session-redacted-001`.
