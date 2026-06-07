# Interactive Topology Visualization

Phase 141 adds visualization-model-only topology graph records for PortMap-AI. These records convert sanitized observations and flow summaries into bounded nodes, edges, graph summaries, and export-safe formats for future operator-facing visual experiences.

This phase does not add a GUI, browser UI, packet capture, live network action, enforcement hook, packet storage, raw DNS history, or private identifier export.

## Model Scope

The visualization package is implemented under `core_engine.visualization`:

- `topology_models.py` defines `TopologyNode`, `TopologyEdge`, and `TopologyGraph`.
- `asset_classifier.py` infers coarse asset categories from metadata hints.
- `topology_builder.py` converts observations and flows into graph models.
- `graph_export.py` emits deterministic JSON, Mermaid text, and Cytoscape-safe records.

All records include safety flags showing that they are metadata-only, visualization-model-only, export-safe, advisory, and free of enforcement behavior.

## Asset Categories

Phase 141 supports these asset categories:

- `WORKSTATION`
- `SERVER`
- `ROUTER`
- `SWITCH`
- `NAS`
- `PRINTER`
- `PHONE`
- `IOT`
- `UNKNOWN`

Asset labels are confidence-scored and advisory. Unknown or low-confidence assets remain `UNKNOWN` rather than receiving fake live labels.

## Observation-To-Node Conversion

Observation records are converted into sanitized topology nodes using:

- endpoint class
- role hints
- service hints
- port metadata
- source mode
- first-seen and last-seen timestamps
- observation count

Raw endpoint strings are not required for node construction and are not exported. Node IDs are deterministic digests of sanitized metadata classes rather than private host, address, hardware, or user identifiers.

## Flow-To-Edge Conversion

Flow records are converted into topology edges using:

- source and target endpoint classes
- flow direction
- protocol
- service hint
- observation count
- relationship or session state
- source mode

Edges aggregate repeated identical flow metadata by stable edge ID. Edge weight and confidence remain bounded between `0.0` and `1.0`.

## Bounded Graph Growth

`build_topology_graph` accepts `max_nodes` and `max_edges` limits. Duplicate nodes collapse by stable node ID, duplicate edges aggregate observation counts, and the graph reports whether node or edge output was truncated.

This keeps visualization output safe for Raspberry Pi, edge devices, tests, exports, and future dashboard rendering.

## Export Formats

Phase 141 supports:

- Deterministic JSON via `export_graph_json`.
- Mermaid-safe text via `export_graph_mermaid`.
- Cytoscape-safe dictionaries via `export_graph_cytoscape`.
- Cytoscape-safe JSON via `export_graph_cytoscape_json`.

Exports preserve `source_mode` and include safety summaries. They do not include raw packets, packet payloads, raw DNS browsing history, credentials, private host identifiers, or enforcement actions.

## Safety Boundary

Phase 141 explicitly guarantees:

- No GUI is created.
- No browser UI is started.
- No live network action is performed.
- No packet payload is inspected.
- No raw packet is stored.
- No raw DNS history is stored.
- No firewall, service, process, quarantine, isolation, or remediation hook is executed.
- No private hostnames, IP addresses, usernames, MAC addresses, credentials, certs, keys, logs, screenshots, runtime outputs, or local database artifacts are required or exported.

## Validation

Use sanitized fixtures only:

- Run `python -m pytest tests/test_asset_classifier.py tests/test_topology_builder.py tests/test_graph_export.py`.
- Run the full test suite before committing.
- Run `git diff --check`.
- Run a sensitive-data scan.
- Confirm `docs/real_device_validation.md` and local test files remain unstaged.
