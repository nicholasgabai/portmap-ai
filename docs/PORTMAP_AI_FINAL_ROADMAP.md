# PortMap-AI Final Roadmap To Production Launch

This roadmap describes the remaining strategic path from the completed Phase 122 baseline into a production launch candidate. It is forward-looking documentation only. It does not implement collectors, start services, install components, modify firewalls, open listeners, transmit telemetry, store credentials, or enable enforcement.

PortMap-AI's long-term target is a cross-platform, distributed, AI-assisted behavioral network intelligence and remediation platform. The current baseline provides local runtime operation, distributed coordination records, live telemetry summaries, gateway readiness checks, behavioral intelligence, historical persistence, and deployment planning. The remaining work moves from readiness records into hardened security, richer flow intelligence, supervised response, enterprise visibility, scalability, packaging, governance, and commercial launch readiness.

All future work should remain metadata-first, privacy-aware, operator-controlled, resource-bounded, and safe for macOS, Linux, Raspberry Pi/Linux ARM, and Windows validation.

## Current Foundation

The completed baseline through Milestone T includes:

- Core engine primitives for scanning, telemetry, events, storage, topology, scheduler state, policy review, diagnostics, and runtime workflows.
- CLI and Textual TUI operation for stack launch, runtime status, runtime export, visibility, review, logs, and operator dashboards.
- Runtime sessions, runtime profiles, recovery checkpoints, health summaries, service-readiness previews, and dry-run/local-write workflow modes.
- Local storage, persistent topology state, review queues, export bundles, coordinated multi-node export plans, and deterministic digests.
- Distributed node state, federated topology aggregation, cluster health, distributed reviews, operator visibility, trusted transport models, signed runtime exchange records, synchronization windows, distributed event propagation records, federation diagnostics, and dashboard/API readiness.
- Active federation runtime records, peer lifecycle records, exchange scheduler records, and validation summaries without live network listener behavior.
- Passive interface discovery, bounded packet metadata windows, flow reconstruction, protocol metadata extraction, dynamic topology correlation, real-time telemetry views, source-mode labeling, current-snapshot scan deduplication, the Milestone V live runtime bridge from worker socket snapshots into TUI-visible flow/topology summaries, and macOS socket collection diagnostics with a non-privileged live fallback when psutil is permission-blocked.
- Gateway telemetry enrichment, process/service attribution, DNS visibility, router log parsing, SPAN/mirror-port readiness, and gateway validation records.
- Cross-platform runtime detection, Windows compatibility records, packet capture readiness, firewall provider previews, filesystem/export safety, and unified validation summaries.
- Historical behavioral baselines, temporal anomaly windows, service behavior fingerprints, DNS/destination learning, adaptive risk weighting, behavioral operator summaries, historical snapshots, baseline aging, topology evolution, replay windows, resource-aware retention, and long-term intelligence summaries.
- Production runtime profiles, service lifecycle readiness previews, deployment manifests, upgrade/migration readiness, backup/restore planning, and deployment operator summaries.

## Milestone U - Security Foundation And Trusted Runtime

Goal: transform PortMap-AI into a trusted deployable distributed security platform without enabling destructive automation.

### Phase 123 - Secure Node Identity

Objectives:

- Node identity generation.
- Signed worker enrollment.
- Trust-chain validation.
- Persistent node fingerprint abstraction.
- Hardware-independent identity persistence.

Build:

- `core_engine/security/node_identity.py`
- `core_engine/security/enrollment.py`
- `core_engine/security/trust_chain.py`

Requirements:

- No raw hardware identifiers stored.
- No MAC addresses, serial numbers, usernames, hostnames, or private IPs in public docs.
- Export-safe identity summaries only.
- Cross-platform compatible.

### Phase 124 - Encrypted Orchestration Transport

Objectives:

- Mutual TLS support.
- Encrypted heartbeat channels.
- Session negotiation.
- Secure worker/master communication.
- Graceful downgrade records for unsupported platforms.

Build:

- `core_engine/security/transport_security.py`
- `core_engine/security/session_negotiation.py`

### Phase 125 - Secure Config And Secrets Management

Objectives:

- Encrypted configuration support.
- Runtime secret isolation.
- Secret rotation readiness.
- Environment abstraction.
- Secret redaction in export and dashboard views.

Build:

- `core_engine/security/secure_config.py`
- `core_engine/security/secrets.py`

### Phase 126 - RBAC And Operator Permissions

Objectives:

- Role-based access control.
- Operator separation.
- Admin/operator scope records.
- Enforcement-mode protections.
- Dashboard/API permission summaries.

Build:

- `core_engine/security/rbac.py`
- `core_engine/security/permissions.py`

### Phase 127 - Tamper Detection

Objectives:

- Runtime integrity monitoring.
- Unauthorized modification detection.
- Binary verification support.
- Configuration tamper alerting.
- Export-safe tamper summaries.

Build:

- `core_engine/security/integrity.py`
- `core_engine/security/tamper_detection.py`

### Phase 128 - Secure Update Framework

Objectives:

- Signed update manifests.
- Rollback safety.
- Migration verification.
- Upgrade validation.
- Operator-approved update previews.

Build:

- `core_engine/security/update_verification.py`
- `core_engine/security/rollback_plans.py`

## Milestone V - Deep Network Flow Intelligence

Milestone U is complete as a baseline through Phase 128. Its integration summary is tracked in `docs/MILESTONE_U_INTEGRATION.md` and covers the secure node identity, encrypted transport readiness, secure configuration, RBAC, tamper detection, secure update, rollback, federation trust, and future SaaS control-plane readiness layer.

Milestone V is complete as a baseline through Phase 134. Its integration summary is tracked in `docs/MILESTONE_V_INTEGRATION.md` and covers bidirectional flow reconstruction, packet metadata correlation, cross-node relationship mapping, dynamic application attribution, behavioral drift detection, network topology intelligence, source-mode safety, trust-zone inference, and dependency mapping. The pre-Milestone W runtime bridge is tracked in `docs/milestone_v_live_runtime_integration.md` and wires current socket snapshots into Milestone V counters, flow rows, topology edges, and operator summaries. The macOS collection validation note is tracked in `docs/macos_socket_collection_validation.md`.

Goal: move from socket and metadata visibility into deeper behavior-aware network intelligence without storing payloads or credentials.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 129 | Bidirectional Flow Reconstruction | Complete baseline: session-aware metadata-only flow tracking, direction inference, relationship mapping, source-mode preservation, and reconstruction confidence without payload inspection or PCAP generation. |
| 130 | Packet Metadata Correlation | Complete baseline: correlate packet, socket, session, flow, DNS, protocol, process, service, and topology metadata with source-mode preservation and no payload or PCAP storage. |
| 131 | Cross-Node Relationship Mapping | Complete baseline: model node-to-node relationships, shared services, recurring peer interactions, topology adjacency, and advisory lateral analysis without payload inspection or graph database dependency. |
| 132 | Dynamic Application Attribution | Complete baseline: infer generic probable app/service classes from metadata hints, behavioral signatures, confidence models, and source-mode-aware Unknown/Unattributed fallbacks without payload inspection or hardcoded live identities. |
| 133 | Behavioral Drift Detection | Complete baseline: compare current application, service, destination, flow, topology, and protocol behavior against historical baselines with bounded drift and confidence scores, recurrence state, environment aggregation, source-mode preservation, no threat verdicts, and no enforcement. |
| 134 | Network Topology Intelligence | Complete baseline: infer trust zones, service dependencies, communication chains, node dependency relationships, topology adjacency, bounded relationship and confidence scores, source-mode preservation, and dashboard/API/export-safe topology intelligence without active probing, graph database dependency, or enforcement. |

Primary deliverable areas:

- `core_engine/flows/`
- `core_engine/attribution/`
- `core_engine/behavior/`
- `core_engine/topology/`

Dynamic attribution should eventually identify likely browsers, SSH clients, database systems, cloud sync tools, remote access tools, update agents, and suspicious unknown behaviors using metadata-only evidence and confidence scoring.

## Milestone W - Autonomous Response And Policy Engine

Goal: transition from passive monitoring and advisory records into supervised response orchestration with explicit operator controls.

Detailed implementation planning for this milestone is tracked in `docs/PHASE_135_140_PLAN.md`, and integration is summarized in `docs/MILESTONE_W_INTEGRATION.md`. The completed baseline remains dry-run safe, advisory-first, operator-approved, rollback-aware, and does not enable firewall changes, quarantine execution, service disablement, destructive rollback, packet payload inspection, credential handling, threat verdicts, or automatic enforcement.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 135 | Policy Runtime Engine | Complete baseline: dry-run policy records, fixture-safe loading, validation, advisory evaluation, safe enforcement-mode rejection, export-safe summaries, and no live enforcement. |
| 136 | Adaptive Remediation Logic | Complete baseline: confidence-weighted preview recommendations, escalation-aware decisions, approval gates, rollback summaries, export-safe records, and no action execution. |
| 137 | Quarantine And Isolation Providers | Complete baseline: dry-run provider readiness for Windows Defender Firewall, Linux nftables/ufw/iptables, macOS pf, Raspberry Pi edge, manual review, sanitized command previews, approval/rollback summaries, and no execution. |
| 138 | Risk Escalation Pipelines | Complete baseline: multi-signal advisory escalation, incident candidates, safety blockers, operator actions, export-safe records, no final threat verdicts, and no enforcement. |
| 139 | Safety Guardrails | Complete baseline: approval gates, rollback gates, blast-radius gates, provider readiness gates, confidence/runtime/policy/emergency-stop gates, rollback simulations, and no execution. |
| 140 | Autonomous Enforcement Modes | Complete baseline: monitor, supervised, autonomous-preview, hardened-preview mode records, autonomy controls, approval/audit/emergency-stop requirements, containment disabled, and no enforcement. |

All enforcement work must remain explicit, reviewable, reversible, and disabled by default until separate production validation authorizes it.

## Milestone X - Visual Intelligence Layer

Goal: turn PortMap-AI's working telemetry, flow reconstruction, topology intelligence, policy evaluation, and advisory remediation layers into operator-facing visual intelligence models that can support a future GUI/dashboard experience without adding live enforcement or browser UI yet.

Detailed implementation planning for this milestone is tracked in `docs/PHASE_141_146_PLAN.md`, and integration is summarized in `docs/MILESTONE_X_INTEGRATION.md`. The completed baseline remains visualization-model only, source-mode preserving, bounded, export-safe, and does not add browser UI, remote control, live enforcement, firewall/process/service changes, remediation execution, packet payload storage, raw DNS history, private identifier export, cloud sync, or runtime database writes.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 141 | Interactive Network Topology Visualization | Complete baseline: topology graph records, nodes, edges, asset classification, flow-to-graph conversion, bounded graph growth, and JSON/Mermaid/Cytoscape-safe export models. |
| 142 | Historical Network Timeline | Complete baseline: timeline events, topology/flow/service change history, replay-safe visual summaries, bounded event windows, category/severity counts, and export-safe serialization. |
| 143 | Asset Inventory Intelligence | Complete baseline: bounded asset inventory records, role inference, first-seen and last-seen summaries, service/flow/timeline counts, source-mode preservation, and confidence-scored export-safe labels. |
| 144 | Risk Dashboard Models | Complete baseline: risk cards, dashboard panels, severity/category counts, recommendation and blocked-action counts, high-risk sorting, bounded cards, and export-safe visual risk summaries. |
| 145 | Multi-Node Fleet Visibility | Complete baseline: fleet node records, site/group summaries, collector health, version compatibility, last check-ins, telemetry freshness, max-node bounding, and export-safe fleet panels. |
| 146 | Visualization Operator Summary | Complete baseline: unified visualization summaries, readiness checks, topology/timeline/asset/risk/fleet/runtime rollups, degraded/empty component detection, recommendation summaries, and export-safe outputs. |

The Textual TUI remains supported. Browser dashboards should extend these visual models later without replacing terminal-first operations prematurely.

## Milestone Y - Threat Intelligence And Detection Expansion

Goal: expand detection primitives while preserving privacy and avoiding external lookups unless explicitly configured.

Detailed implementation planning for this milestone is tracked in `docs/PHASE_147_152_PLAN.md`, and integration is summarized in `docs/MILESTONE_Y_INTEGRATION.md`. Phases 147-152 are complete as baselines for metadata-only IOC records, bounded inventories, local matching, hash-only exports, redacted previews, DNS domain pattern records, resolver behavior summaries, IOC match integration, DNS analytics state rollups, local signature records, deterministic signature matching, unsafe-condition rejection, composite signal support, deterministic AI correlation evidence chains, advisory threat scoring expansion, and local threat hunting query records. The completed Milestone Y baseline remains metadata-only, advisory-first, source-mode preserving, bounded, export-safe, and does not add final threat verdicts, malicious labels, blocking, enforcement, firewall/process/service changes, external threat-feed lookups, external AI calls, credential storage, packet payload storage, raw DNS history, or private identifier export.

Phases:

| Phase | Name |
| --- | --- |
| 147 | IOC Intelligence Framework | Complete baseline: metadata-only IOC records, deterministic normalization, hash-only value export, redacted previews, bounded inventories, local matching, JSON/CSV-safe summaries, and no external lookups, malicious flags, threat verdict fields, or enforcement. |
| 148 | DNS Threat Analytics | Complete baseline: metadata-only domain pattern records, deterministic domain normalization and hashing, redacted domain previews, resolver behavior summaries, local IOC match integration, DNS analytics state rollups, source-mode preservation, and no DNS lookups, external threat feeds, raw DNS history, domain blocking, malicious flags, final threat verdicts, or enforcement. |
| 149 | Threat Signature Framework | Complete baseline: local metadata-only signature records, required-field validation, unsafe enforcement-condition rejection, deterministic matching across IOC, DNS, flow, protocol, attribution, topology, runtime, and composite contexts, source-mode preservation, bounded severity/confidence summaries, and no external feeds, payload inspection, malicious flags, final threat verdicts, blocking, or enforcement. |
| 150 | AI Correlation Layer | Complete baseline: metadata-only evidence chain records, deterministic local AI correlation summaries, IOC/DNS/signature correlation, flow/attribution/drift correlation, topology/policy/risk correlation, remediation/guardrail correlation, composite chain behavior, source-mode preservation, bounded confidence and severity aggregation, explanation points, and no external AI calls, network requests, payload inspection, final threat verdicts, or enforcement. |
| 151 | Threat Scoring Expansion | Complete baseline: advisory scoring weight profiles, bounded advisory score records, IOC/DNS/signature/correlation/flow/attribution/drift/topology/runtime/remediation/guardrail score breakdowns, confidence aggregation, source-mode preservation, explanation points, and no malicious labels, final threat verdicts, external feeds, external AI calls, blocking, or enforcement. |
| 152 | Threat Hunting Query Engine | Complete baseline: local metadata-only query records, equality/contains/confidence/severity/source-mode filters, bounded result limits, deterministic hunt result summaries, source-scope rollups, export-safe matched-record summaries, and no external queries, payload inspection, malicious labels, final threat verdicts, blocking, or enforcement. |

## Milestone Z - Scalability And Distributed Infrastructure

Goal: scale federation and telemetry processing for larger local and enterprise deployments.

Phases:

| Phase | Name |
| --- | --- |
| 153 | Distributed Telemetry Bus |
| 154 | High-Volume Storage Engine |
| 155 | Horizontal Scaling |
| 156 | Resource Optimization |
| 157 | Edge Worker Modes |
| 158 | Cloud Relay Infrastructure |

## Milestone AA - Packaging And Installers

Goal: make PortMap-AI installable, updateable, and maintainable across supported operating systems.

Phases:

| Phase | Name |
| --- | --- |
| 159 | Windows Installer |
| 160 | macOS Packaging |
| 161 | Linux Packaging |
| 162 | Container Deployment |
| 163 | Secure Auto-Updater |
| 164 | Deployment Wizard |

## Milestone AB - Compliance And Governance

Goal: add operator accountability, privacy controls, and compliance-ready evidence handling.

Phases:

| Phase | Name |
| --- | --- |
| 165 | Audit Logging |
| 166 | Compliance Profiles |
| 167 | Data Governance Controls |
| 168 | Operator Accountability |
| 169 | Security Review Framework |
| 170 | Privacy And Legal Safeguards |

## Milestone AC - AI Intelligence Evolution

Goal: evolve behavioral intelligence into advanced graph-based, federated, and predictive analysis while keeping operator control and privacy boundaries explicit.

Phases:

| Phase | Name |
| --- | --- |
| 171 | Probabilistic Application Models |
| 172 | Continuous Learning Profiles |
| 173 | Graph-Based Behavioral AI |
| 174 | Threat Prediction Models |
| 175 | Federated Intelligence |
| 176 | Autonomous Investigation Chains |

## Milestone AD - Commercial Launch Readiness

Goal: prepare a business and enterprise launch path after the local-first product is technically hardened.

Phases:

| Phase | Name |
| --- | --- |
| 177 | Licensing System |
| 178 | SaaS Control Plane |
| 179 | Customer Provisioning |
| 180 | Billing Integration |
| 181 | Documentation Portal |
| 182 | Launch Candidate Stabilization |

## Strategic Priority

The primary long-term differentiator is:

```text
Behavioral attribution + adaptive network intelligence
```

The core advantage should come from adaptive learning, probabilistic attribution, behavioral modeling, and autonomous intelligence, not only from port scanning, dashboards, or socket visibility.

## Current Strategic Position

| Capability | Comparable Platform Category |
| --- | --- |
| Port visibility | Port scanning tools |
| Traffic observation | Packet analysis tools |
| DNS behavior | DNS visibility tools |
| Behavioral analytics | Network detection and response tools |
| Endpoint awareness | Endpoint detection concepts |
| Threat scoring | Endpoint and SIEM scoring concepts |
| Topology awareness | Security monitoring platforms |
| Distributed orchestration | Search and telemetry platforms |

## Development Priorities

Immediate priorities:

1. Secure runtime foundation.
2. Dynamic attribution.
3. Real flow intelligence.
4. Autonomous remediation in supervised mode.
5. Enterprise dashboard.

Long-term priorities:

1. Federated learning.
2. Predictive intelligence.
3. Distributed autonomous response.
4. Enterprise-scale deployment.
5. AI-native detection ecosystem.

## Deployment Philosophy

PortMap-AI should remain:

- Cross-platform.
- Lightweight.
- Metadata-first.
- Privacy-aware.
- Distributed.
- Modular.
- Resource-bounded.

It should operate on Windows, macOS, Linux, Raspberry Pi/Linux ARM, edge devices, and enterprise environments without requiring payload inspection, invasive drivers, or initial kernel hooks.

## Final Launch Objective

```text
PortMap-AI v1.0 =
Cross-platform distributed AI-assisted behavioral network intelligence and remediation platform.
```
