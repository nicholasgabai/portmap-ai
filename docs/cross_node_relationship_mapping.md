# Cross-Node Relationship Mapping

Phase 131 adds metadata-only cross-node relationship mapping for PortMap-AI.

The goal is to model node-to-node communication patterns, shared services, recurring peer interactions, and topology adjacency without requiring centralized packet capture or packet payload inspection.

Phase 131 does not inspect packet payloads, store packets, generate PCAP files, require a graph database, create threat verdicts, or perform enforcement.

## Relationship Graphs

`core_engine.topology.relationship_graphs` builds normalized relationship records for trusted local node classes:

- `orchestrator`
- `master`
- `worker`
- `edge`
- `external`
- `unknown`

Relationship records include:

- `relationship_id`
- `source_node_class`
- `target_node_class`
- `relationship_type`
- `flow_reference`
- `session_reference`
- `shared_service_state`
- `recurring_interaction_score`
- `topology_distance`
- `relationship_strength`
- `relationship_confidence`
- `drift_detected`
- `source_mode`
- `advisory_notes`

Supported relationship states are:

- `active`
- `recurring`
- `transient`
- `dormant`
- `unknown`

The graph output includes dashboard/API/export-safe dictionaries and summary counts for recurring relationships, shared services, drift, source node classes, target node classes, and source modes.

## Lateral Analysis

`core_engine.topology.lateral_analysis` builds advisory relationship summaries from normalized relationships.

Inputs can include:

- recurring peer communication summaries
- shared service summaries
- reconstructed flow references
- session references
- topology adjacency records

Lateral analysis records include:

- `analysis_id`
- `relationship_reference`
- `lateral_relationship_state`
- `recurrence_score`
- `topology_risk`
- `spread_potential`
- `unusual_peer_detected`
- `drift_detected`
- `confidence_score`
- `operator_summary`

Supported lateral relationship states are:

- `expected`
- `unusual`
- `suspicious`
- `isolated`
- `unknown`

These states are advisory relationship labels, not threat verdicts. Every record sets `threat_verdict` to `not_assessed` and `enforcement_action` to `none`.

## Metadata-Only Safety

Phase 131 records are export-safe and include safety fields showing:

- `metadata_only: true`
- `raw_packet_stored: false`
- `packet_payload_inspected: false`
- `pcap_generated: false`
- `graph_db_dependency: false`
- `credential_material_stored: false`
- `enforcement_enabled: false`
- `automatic_changes: false`

## Operator Use

Operators can use Phase 131 output to review recurring peer relationships, shared service paths, topology adjacency, and unusual node pairings. The output is intended to feed later topology intelligence and behavioral drift work.

No record in this phase modifies traffic, changes firewall state, blocks communication, installs services, opens listeners, or contacts other nodes.

## Validation

Tests use sanitized fixture records only. Public examples must avoid real hostnames, IP addresses, usernames, MAC addresses, payloads, packet captures, runtime logs, screenshots, credentials, certificates, keys, and private validation notes.
