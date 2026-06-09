# PortMap-AI Completion Roadmap

This roadmap defines the remaining end-to-end work required to turn PortMap-AI from its current local and trusted-federation baseline into a fully functioning live network intelligence platform. The target platform should support live telemetry, gateway/router-adjacent visibility, production security, installable services, release packaging, advanced AI security intelligence, and a clear commercial path.

This is a planning document. It does not implement collectors, start services, open network listeners, change host networking, enable gateway behavior, transmit data externally, or perform automatic enforcement.

The extended production-launch roadmap after the Phase 122 baseline is tracked in `docs/PORTMAP_AI_FINAL_ROADMAP.md`. That document starts with Milestone U security foundation and continues through deep flow intelligence, supervised response, enterprise visibility, scalability, packaging, governance, AI evolution, and commercial launch readiness.

## Current Completed Foundation

PortMap-AI has completed baseline implementation through Phase 151, covering Phases 0-151, plus a pre-Milestone W Milestone V live runtime bridge that wires current worker socket snapshots into flow, correlation, attribution, drift, topology, TUI, dashboard/API, and export-safe summaries.

Implemented foundation includes:

- Core engine primitives for scanning, event modeling, storage records, runtime state, scheduling, topology, policy review, diagnostics, and controlled local workflows.
- CLI and Textual TUI foundations for local operation, stack launch, runtime commands, visibility inputs, review workflows, and dashboard-oriented status.
- Runtime session records, runtime profiles, recovery checkpoints, health summaries, service-readiness previews, and explicit dry-run/local-write workflow modes.
- Local SQLite storage repositories for events, snapshots, assets, services, topology edges, and findings.
- Persistent topology state, topology snapshots, snapshot diffing, drift detection, topology timeline records, and correlation-ready outputs.
- Policy review queues, persistent review records, review history, finding status records, and advisory review-state transitions.
- Operational export bundles, coordinated multi-node export plans, redaction helpers, placeholder validation, deterministic digests, and optional local archive plans.
- Distributed node state normalization for trusted master and worker summaries.
- Federated topology aggregation, cluster runtime health, distributed review aggregation, coordinated export planning, and read-only operator visibility models.
- Federation transport models for trusted nodes, local trust profiles, approved peers, transport session metadata, handshake summaries, expiration windows, trust scopes, and replay-window metadata.
- Signed runtime summary exchange records with canonical JSON, deterministic digests, signature metadata, signing status, verification status, trusted peer validation hooks, and replay-window validation hooks.
- Live cluster synchronization records with accepted, rejected, stale, replayed, malformed, and untrusted update classifications.
- Distributed event propagation records with source attribution, sequence numbers, event digests, replay-window integration, signed exchange verification, and event batch summaries.
- Federation diagnostics with readiness scoring, trusted peer health, transport health, signed exchange health, synchronization counters, event propagation counters, replay-window checks, recommendations, and local health events.
- Federation dashboard/API readiness with read-only panels and local API-compatible dictionaries for trusted peers, transports, signed exchanges, sync windows, distributed events, diagnostics, readiness scores, and counters.
- Active federation runtime manager records with trusted peer enrollment summaries, active/inactive/paused/error runtime states, signed exchange loop plans, synchronization loop plans, event propagation loop plans, per-peer counters, and dashboard/API-ready runtime state.
- Trusted peer lifecycle records with enrollment, approval, pause, resume, revoke, expire, trust scope update, transport session linkage, stale/expired/revoked peer summaries, and dashboard/API-ready registry dictionaries.
- Runtime exchange scheduler records with signed-summary exchange jobs, cluster-state synchronization jobs, event propagation jobs, per-peer schedule records, interval/backoff metadata, failure counters, and dashboard/API-ready scheduler summaries.
- Active federation validation records with trusted peer, signed exchange, synchronization window, event propagation, replay-window, runtime scheduler, and federation runtime readiness checks, scores, recommendations, and dashboard/API-ready dictionaries.
- Passive interface discovery records with local interface summaries, normalized address-family metadata, loopback/broadcast/multicast capability fields, dry-run capture session plans, resource budgets, deterministic serialization, and dashboard/API-ready dictionaries.
- Live packet ingestion records with bounded metadata windows, interface and node attribution, IPv4/IPv6 classification, TCP/UDP/ICMP summaries, packet size and rate summaries, replay-safe counters, malformed/unsupported packet classification, and dashboard/API-ready dictionaries.
- Flow reconstruction records with bidirectional flow keys, timeout-aware session tracking, complete/partial/malformed classification, ephemeral/persistent labels, service association, deterministic flow digests, topology edge generation, and dashboard/API-ready dictionaries.
- Protocol metadata extraction records with HTTP/TLS/DNS summaries, protocol fingerprints, service fingerprint summaries, encrypted-session metadata handling, confidence scoring, application hints, safe truncation, governance fields, protocol anomalies, and dashboard/API-ready dictionaries.
- Dynamic topology correlation records with live node relationship inference, flow-to-topology edge correlation, protocol-aware summaries, drift correlation, temporal topology summaries, node role inference, bounded graph growth controls, replay-safe topology update records, cluster/federation-aware summaries, operator health summaries, and dashboard/API-ready dictionaries.
- Real-time telemetry dashboard records with interface, packet rate, flow rate, live topology, protocol distribution, resource usage, federation rollup, telemetry health, bounded update interval, empty-state, stale-state, and local API dictionaries.
- Flow telemetry enrichment records with rolling packet and byte statistics, first-seen and last-seen timestamps, direction inference, local/remote endpoint classification, service-port hint correlation, state transition summaries, confidence scoring, telemetry quality flags, and dashboard/API-ready dictionaries.
- Process and service attribution records with process-to-port attribution summaries, service-name correlation, listening socket ownership summaries, confidence levels, unsupported-platform fallbacks, permission-denied degraded states, minimized process metadata, sanitized operator display records, and dashboard/API-ready dictionaries.
- DNS visibility records with metadata-only query and response summaries, domain-to-flow correlation, resolver classification, timing summaries, NXDOMAIN/error summaries, encrypted DNS limitations, anomaly hints, safe domain truncation/redaction options, and dashboard/API-ready dictionaries.
- Gateway and router log ingestion records with sanitized router/firewall log models, syslog-style parser helpers, NAT and allow/deny summaries, source/destination normalization, timestamp normalization, severity summaries, malformed log handling, runtime event hooks, topology hooks, export-ready summaries, and dashboard/API-ready dictionaries.
- SPAN and mirror-port readiness records with dry-run profiles, passive capture requirements, interface capability summaries, expected traffic volume warnings, resource budget checks, privilege requirement summaries, packet-loss risk summaries, operator readiness checklists, telemetry scaling summaries, Raspberry Pi resource-awareness summaries, and dashboard/API-ready dictionaries.
- Gateway mode validation records with telemetry enrichment, DNS visibility, router log, SPAN readiness, topology correlation, runtime health, and operator visibility validation summaries, safety checklists, export summaries, supported/degraded/unavailable/unsafe state models, and dashboard/API-ready dictionaries.
- Cross-platform runtime detection records for macOS, Linux, Raspberry Pi/Linux ARM, Windows, and unknown platforms, including architecture, Python version, permission state, capability placeholders, and dashboard/API-ready compatibility dictionaries.
- Windows runtime compatibility records with Windows-safe path normalization, log/export/cache summaries, process/socket visibility capability summaries, permission/elevation records, service-mode readiness previews, runtime profile defaults, degraded fallbacks, and dashboard/API-ready dictionaries.
- Cross-platform packet capture readiness records for macOS BPF/libpcap, Linux libpcap/AF_PACKET/scapy, Raspberry Pi, and Windows Npcap/WinPcap backends, including permission requirements, passive safety warnings, payload prohibition fields, and dashboard/API-ready dictionaries.
- Cross-platform firewall provider readiness records for Windows Defender Firewall, macOS pf, Linux nftables/ufw/iptables, and Raspberry Pi, including dry-run rule preview records, permission requirements, provider states, safety warnings, operator review flags, and dashboard/API-ready dictionaries.
- Cross-platform filesystem and export safety records with safe log, cache, and export path summaries, OS-specific path normalization, artifact exclusion validation, private-file warnings, runtime artifact classification, public-doc safety checks, and dashboard/API-ready dictionaries.
- Unified cross-platform validation records for macOS, Linux, Raspberry Pi/Linux ARM, and Windows with capture readiness, firewall readiness, filesystem/export safety, aggregate states, operator recommendations, and CLI/table/JSON/dashboard/API-ready output.
- Historical flow baseline records for ports, protocols, services, process/service fingerprints, flow tuple digests, and DNS/domain observations with first-seen and last-seen windows, frequency counters, rolling average scores, stable/new/recurring/decaying behavior classification, advisory confidence scoring, bounded window retention, dashboard/API summaries, and export-ready digests.
- Temporal anomaly window records with short, medium, and long summaries, burst detection, rare service timing, volume drift hints, port/protocol/service novelty labels, baseline-aware anomaly confidence scoring, operator-readable explanations, dashboard/API dictionaries, and export-ready digests.
- Service behavior fingerprint records for recurring metadata-only process, service, protocol, port, transport, flow role, redacted DNS-summary, runtime platform, interface class, and direction combinations with expected profile summaries, unusual combination labels, dormant service return tracking, advisory confidence scoring, dashboard/API dictionaries, and export-ready digests.
- DNS and destination behavior records for redacted or hashed domain summaries, resolver hashes, destination classification placeholders, recurrence timing, novelty, stable/new/recurring/unusual/dormant/drift labels, advisory confidence scoring, dashboard/API summaries, and export-ready digests.
- Adaptive risk weighting records with base and adjusted advisory scores, baseline context, temporal anomaly context, service fingerprint context, DNS/destination context, confidence-aware adjustments, no-enforcement explanation records, dashboard/API summaries, and export-ready digests.
- Behavioral intelligence operator summary records with baseline, anomaly, service fingerprint, DNS/destination, and adaptive risk rollups, supported/degraded/unavailable states, advisory recommendation records, explanation records, dashboard/API views, privacy/safety summaries, and export-ready digests.
- Historical snapshot persistence records with metadata-only behavioral intelligence snapshots, bounded rotation, export-safe summaries, malformed input isolation, and dashboard/API-safe dictionaries.
- Baseline aging and decay records with inactive, stale, dormant, and maturity summaries for baselines, service fingerprints, and destination behavior.
- Long-term topology evolution records with recurring relationship tracking, stable/transient classification, topology drift, dormant relationship returns, and export/dashboard/API-safe rollups.
- Historical replay windows with bounded timeline reconstruction for snapshots, anomalies, topology changes, baseline decay, service fingerprints, DNS/destination behavior, adaptive risk, and offline review helpers.
- Resource-aware historical retention records with storage and memory budgets, Raspberry Pi and edge profiles, adaptive retention windows, preview-only recommendations, and no automatic deletion.
- Long-term intelligence operator summary records with historical snapshot, baseline aging/decay, topology evolution, replay, and retention rollups, supported/degraded/unavailable states, recommendations, privacy/safety summaries, and dashboard/API/export-ready dictionaries.
- Production runtime profile records for development, staging, production, edge, and lab deployment modes with safety, telemetry, orchestration, remediation, retention, resource, platform, capability, and compatibility summaries.
- Service lifecycle readiness previews for systemd, launchd, Windows Service Control Manager, foreground process mode, and Raspberry Pi edge mode with sanitized command previews and no service installation.
- Deployment manifest records for standalone, orchestrator, worker, edge, lab, and production-preview modes with node profile summaries, readiness states, export path placeholders, and backup recommendations.
- Upgrade and migration readiness records with version compatibility, migration preview plans, rollback notes, required backups, validation steps, operator steps, and no destructive migration behavior.
- Backup and restore planning records for configuration, manifests, runtime exports, historical intelligence, and operator evidence bundles with restore previews, conflict warnings, encryption recommendations, and no automatic restore/delete behavior.
- Deployment operator summary records with readiness scores, release-readiness checklists, operator actions, safety warnings, ready/degraded/blocked/unknown states, dashboard/API-safe views, and export-safe dictionaries.
- Secure logical node identity records with deterministic installation-scoped UUIDs, worker enrollment previews, trust-chain summaries, identity regeneration and rotation previews, advisory-only safety fields, and no raw hardware identifiers, hostnames, usernames, MAC addresses, serial numbers, plaintext secrets, certificates, listeners, or privileged enrollment actions.
- Encrypted orchestration transport readiness records with plaintext development, TLS-ready, mTLS-ready, pinned-certificate-ready, and production-required profiles, downgrade warnings, session negotiation previews, mutual-auth requirement summaries, and no certificate generation, private key material, listener changes, live auth exchange, or mTLS handshakes.
- Secure configuration and secrets-management readiness records with development, staging, production, edge, and ephemeral runtime profiles, secret-management previews for orchestration/runtime classes, plaintext persistence rejection, rotation readiness, external provider readiness, and no credential storage, key generation, OS keychain integration, live encryption, or secret exchange.
- RBAC and operator permission readiness records with admin, security-operator, analyst, auditor, read-only, and service-account roles, permission evaluation previews, remediation/enrollment/export/config/audit boundaries, and no user account creation, password or token storage, live authentication enforcement, or API behavior changes.
- Tamper detection readiness records with integrity targets for runtime configs, deployment manifests, node identities, trust chains, transport profiles, package manifests, binary artifacts, and history stores plus preview-only tamper detections for config changes, manifest changes, identity rotation mismatches, trust-chain drift, transport downgrades, package digest mismatches, and history-store drift without file watching, private-file hashing, blocking, quarantine, deletion, rollback, or configuration modification.
- Secure update framework readiness records with release manifest, package digest, signature status, migration manifest, compatibility manifest, and rollback manifest verification previews plus config, package, migration, identity, trust-chain, and history-store rollback previews without downloads, installer execution, file modification, restore, delete, overwrite, private key creation, live signature trust, or migration execution.
- Bidirectional flow reconstruction records with normalized session tracking, inbound/outbound/loopback direction inference, source-mode preservation, flow pairs, flow relationships, inferred/transient/recurring session summaries, relationship strength scoring, recurrence scoring, drift hints, reconstruction confidence, and metadata-only dashboard/API/export-safe dictionaries.
- Packet metadata correlation records connecting packet metadata, socket observations, reconstructed sessions, flow pairs, redacted DNS/destination behavior, protocol hints, process/service attribution, and topology relationships with source-mode preservation, Unknown/Unattributed live fallbacks, fixture/simulated-only demo labels, confidence scoring, and dashboard/API/export-safe dictionaries.
- Cross-node relationship mapping records with normalized node relationship graphs, orchestrator/master/worker/edge/external node classes, shared service states, recurring interaction scores, topology distance, relationship strength and confidence, drift hints, metadata-only lateral analysis, advisory operator summaries, and dashboard/API/export-safe dictionaries.
- Dynamic application attribution records with generic probable application and service candidates, process/service/protocol/destination/flow hints, metadata-only behavioral signatures, recurrence and stability scores, deterministic confidence scoring, conflict penalties, source-mode-aware Unknown/Unattributed live fallbacks, and dashboard/API/export-safe dictionaries.
- Behavioral drift detection records for application, service, destination, flow, topology, and protocol behavior with baseline/current references, bounded drift and confidence scoring, recurrence state, source-mode preservation, environment drift aggregation, operator summaries, dashboard/API/export-safe dictionaries, no threat verdicts, and no enforcement.
- Network topology intelligence records with internal, management, service, external, and unknown trust zones, service dependencies, communication chains, node dependencies, topology adjacency, relationship strength, recurrence scoring, confidence scoring, topology distance, source-mode preservation, and dashboard/API/export-safe dictionaries.
- Milestone V live runtime bridge summaries that convert bounded current socket snapshots into reconstructed sessions, flow rows, metadata correlations, process/service correlations, relationship edges, attribution candidates, drift records, topology records, runtime counters, and TUI-visible Traffic Flows and Topology Edges without payload inspection or PCAP generation.
- Policy runtime engine records that load, validate, and evaluate dry-run advisory policies against metadata-only telemetry, flow, attribution, drift, topology, and runtime context with safe enforcement-mode rejection, preview-only evaluation records, and no live enforcement.
- Adaptive remediation recommendation records that consume policy evaluations, risk scores, flow intelligence, attribution confidence, drift signals, topology context, and runtime health to produce confidence-weighted preview recommendations, escalation decisions, approval gates, rollback-required summaries, and export-safe advisory records without executing actions.
- Quarantine and isolation provider readiness records for Windows Defender Firewall, Linux nftables, Linux ufw, Linux iptables, macOS pf, Raspberry Pi edge, and manual operator review with platform-specific states, sanitized command previews, containment preview records, approval requirements, rollback requirements, blast-radius summaries, safety blockers, and no live containment.
- Risk escalation pipeline records with multi-signal risk aggregation across policies, remediation previews, flow intelligence, attribution, drift, topology, runtime health, and provider readiness plus incident-candidate summaries, safety blockers, operator actions, and no final threat verdicts or enforcement.
- Safety guardrail records with approval, rollback, blast-radius, provider readiness, confidence, runtime health, policy scope, and emergency-stop gates plus rollback simulation previews, operator actions, recommended safe modes, safety blockers, and no rollback, backup, file, firewall, service, process, or enforcement side effects.
- Autonomous enforcement mode records for monitor, supervised, autonomous-preview, and hardened-preview operation with allowed/blocked action classes, approval, guardrail, rollback, provider, runtime health, audit, emergency-stop, and autonomy control summaries while keeping containment disabled and enforcement inactive.
- macOS socket collection diagnostics and non-privileged live fallback behavior so psutil permission-blocked socket inventory can still produce current metadata observations when visible to the operating system.
- Pre-Milestone U source labeling for TUI, dashboard, API, and export-safe telemetry records so live/default runtime views show unresolved attribution as Unattributed or Unknown and reserve dummy labels for explicit simulated or fixture data.
- Pre-Milestone U live scan snapshot deduplication so worker payloads represent bounded current observations, duplicate socket rows collapse by stable metadata key, transient live socket states are pruned from current snapshots, and TUI latest-scan views do not accumulate stale rows.

Current posture remains local-first, operator-controlled, advisory by default, read-only unless explicitly run in local-write mode, and suitable for sanitized test fixtures.

Milestone O integration is summarized in `docs/MILESTONE_O_INTEGRATION.md`, covering how passive interface discovery, packet metadata windows, flow reconstruction, protocol metadata, dynamic topology, and telemetry dashboard/API summaries connect to runtime, events, storage, topology, drift, federation, and operator visibility.

Milestone P integration is summarized in `docs/MILESTONE_P_INTEGRATION.md`, covering how flow enrichment, process/service attribution, DNS visibility, gateway/router logs, SPAN readiness, and gateway validation connect to live telemetry ingestion, flow reconstruction, protocol metadata, topology correlation, runtime health, gateway readiness, export bundles, and dashboard/API views.

Milestone Q integration is summarized in `docs/MILESTONE_Q_INTEGRATION.md`, covering how cross-platform runtime detection, Windows compatibility, packet capture readiness, firewall provider readiness, filesystem/export safety, and unified validation summaries connect to runtime health, telemetry readiness, gateway readiness, service-mode readiness, export safety, and Windows/macOS/Linux/Raspberry Pi compatibility.

Milestone R integration is summarized in `docs/MILESTONE_R_INTEGRATION.md`, covering how historical flow baselines, temporal anomaly windows, service fingerprints, DNS/destination learning, adaptive risk weighting, and behavioral operator summaries connect to live telemetry, flow enrichment, process/service attribution, DNS visibility, exports, dashboard/API views, gateway readiness, and cross-platform compatibility.

Milestone S integration is summarized in `docs/MILESTONE_S_INTEGRATION.md`, covering how historical snapshot persistence, baseline aging and decay, long-term topology evolution, replay windows, resource-aware retention, and long-term intelligence operator summaries connect to behavioral intelligence, telemetry enrichment, topology correlation, exports, dashboard/API views, cross-platform resource awareness, and Raspberry Pi/edge readiness.

Milestone T integration is summarized in `docs/MILESTONE_T_INTEGRATION.md`, covering how production runtime profiles, service lifecycle readiness, deployment manifests, upgrade and migration readiness, backup/restore planning, and deployment operator summaries connect to runtime health, cross-platform readiness, historical intelligence, service-mode readiness, deployment safety, export safety, Raspberry Pi/edge readiness, and future installer/executable packaging.

Milestone U integration is summarized in `docs/MILESTONE_U_INTEGRATION.md`, covering how secure node identity, encrypted transport readiness, secure config and secrets management, RBAC, tamper detection, and secure update previews connect to distributed federation, trust boundaries, future mTLS, signed enrollment, secure secret storage, dashboard/API RBAC, tamper enforcement, signed updates, rollback-safe upgrades, and future SaaS control-plane readiness.

Milestone V integration is summarized in `docs/MILESTONE_V_INTEGRATION.md`, covering how bidirectional flow reconstruction, packet metadata correlation, cross-node relationship mapping, dynamic application attribution, behavioral drift detection, and network topology intelligence connect socket observations, reconstructed sessions, DNS/destination behavior, process/service attribution, source-mode-safe operator views, trust zones, and service dependency mapping. The live runtime bridge is documented in `docs/milestone_v_live_runtime_integration.md`, including socket-only visibility limits for ICMP and short-lived TCP/UDP activity. macOS socket collection validation is documented in `docs/macos_socket_collection_validation.md`.

Milestone W integration is summarized in `docs/MILESTONE_W_INTEGRATION.md` and planned in `docs/PHASE_135_140_PLAN.md`. It is complete as a baseline through Phase 140. Phases 135-140 provide policy runtime records, fixture-safe loading, validation, advisory evaluation, confidence-weighted remediation recommendations, escalation previews, quarantine/isolation provider readiness, risk escalation pipelines, incident candidates, safety guardrails, rollback simulation, and autonomous enforcement mode modeling. Milestone W remains dry-run, advisory-first, operator-approved, rollback-aware, containment-disabled, and free of automatic enforcement.

Milestone X integration is summarized in `docs/MILESTONE_X_INTEGRATION.md` and planned in `docs/PHASE_141_146_PLAN.md`. It is complete as a baseline through Phase 146. Phases 141-146 provide visualization-model-only topology graphs, historical network timelines, asset inventory intelligence, risk dashboard models, multi-node fleet visibility, visualization operator summaries, and readiness checks. Milestone X preserves source mode, keeps graph and timeline growth bounded, avoids browser UI, and avoids live enforcement, firewall changes, payload inspection, raw packet storage, raw DNS history, private identifiers, remote control, runtime databases, and remediation execution.

Phase 141 is complete as a baseline and documented in `docs/interactive_topology_visualization.md`. It adds pure visualization topology models, observation-to-node conversion, flow-to-edge conversion, node deduplication, edge aggregation, confidence scoring, bounded graph limits, and JSON/Mermaid/Cytoscape-safe exports without GUI, browser UI, live network action, packet storage, raw DNS history, or enforcement hooks.

Phase 142 is complete as a baseline and documented in `docs/historical_network_timeline.md`. It adds replay-safe timeline event records, bounded timeline windows, chronological sorting, event deduplication, category and severity counts, source-mode preservation, and export-safe serialization for flow, topology, service, asset, drift, policy, remediation-preview, incident-candidate, and runtime-health records without timeline databases, raw payloads, raw DNS history, private identifiers, or live actions.

Phase 143 is complete as a baseline and documented in `docs/asset_inventory_intelligence.md`. It adds visualization-ready asset role inference, bounded inventory records, first-seen and last-seen summaries, service/flow/timeline relationship counts, confidence scoring, source-mode preservation, and export-safe inventory summaries without inventory databases, raw payloads, raw DNS history, private identifiers, or live actions.

Phase 144 is complete as a baseline and documented in `docs/risk_dashboard_models.md`. It adds visualization-ready risk cards and dashboard panels for asset inventory, topology, flows, policy matches, remediation previews, incident candidates, guardrail blockers, runtime health, drift, and attribution records with severity/category counts, recommendation and blocked-action counts, high-risk sorting, max-card bounding, source-mode preservation, and export-safe serialization without browser UI, runtime databases, raw payloads, raw DNS history, private identifiers, or live actions.

Phase 145 is complete as a baseline and documented in `docs/multi_node_fleet_visibility.md`. It adds visualization-ready fleet node records, site/group summaries, collector health, version compatibility, last check-in metadata, telemetry freshness, observed asset/flow counts, risk rollups, deduplication, max-node bounding, empty/degraded states, source-mode preservation, and export-safe fleet panels without cloud sync, remote control, browser UI, runtime databases, raw payloads, private identifiers, or live actions.

Phase 146 is complete as a baseline and documented in `docs/visualization_operator_summary.md`. It adds unified visualization operator summaries, readiness checks, topology/timeline/asset/risk/fleet/runtime rollups, degraded and empty component detection, recommendation summaries, source-mode preservation, dashboard/API/export-safe dictionaries, and readiness safety fields without browser UI, remote control, runtime databases, raw payloads, raw DNS history, private identifiers, or live actions.

Milestone Y planning is tracked in `docs/PHASE_147_152_PLAN.md`. Phases 147-151 extend visual intelligence into metadata-only threat intelligence and detection readiness with IOC models, DNS threat analytics, local signature matching, deterministic AI correlation evidence chains, and advisory threat scoring expansion. Remaining Phase 152 work covers local threat-hunting query models. Milestone Y must remain advisory-first, source-mode preserving, bounded, export-safe, and free of final threat verdicts, malicious labels, blocking, enforcement, firewall/process/service changes, external threat-feed lookups, external AI calls, credential storage, packet payload storage, raw DNS history, and private identifiers.

Phase 147 is complete as a baseline and documented in `docs/ioc_intelligence_framework.md`. It adds metadata-only IOC records, deterministic normalization, hash-only value export, redacted value previews, source-category and source-mode preservation, bounded IOC inventories, local exact/normalized/pattern matching, JSON-safe and CSV-row-safe export summaries, and safety fields without external lookups, malicious flags, threat verdict fields, blocking, enforcement, raw payload storage, raw DNS history, credentials, or private identifier export.

Phase 148 is complete as a baseline and documented in `docs/dns_threat_analytics.md`. It adds metadata-only DNS pattern records, deterministic domain normalization and hashing, redacted domain previews, resolver behavior summaries, local IOC match integration, DNS analytics state rollups, source-mode preservation, and export-safe safety fields without DNS lookups, external threat feeds, raw DNS history, domain blocking, malicious flags, final threat verdicts, packet payload storage, or enforcement.

Phase 149 is complete as a baseline and documented in `docs/threat_signature_framework.md`. It adds local metadata-only signature records, required-field validation, unsafe enforcement-condition rejection, deterministic matching across IOC, DNS, flow, protocol, attribution, topology, runtime, and composite contexts, source-mode preservation, bounded severity/confidence summaries, and export-safe match records without external feeds, payload inspection, malicious flags, final threat verdicts, blocking, or enforcement.

Phase 150 is complete as a baseline and documented in `docs/ai_correlation_layer.md`. It adds metadata-only evidence chain records, deterministic local AI correlation summaries, IOC/DNS/signature correlation, flow/attribution/drift correlation, topology/policy/risk correlation, remediation/guardrail correlation, composite chain behavior, source-mode preservation, bounded confidence and severity aggregation, explanation points, and export-safe summaries without external AI calls, network requests, payload inspection, malicious labels, final threat verdicts, or enforcement.

Phase 151 is complete as a baseline and documented in `docs/threat_scoring_expansion.md`. It adds advisory scoring weight profiles, bounded threat scoring records, IOC/DNS/signature/correlation/flow/attribution/drift/topology/runtime/remediation/guardrail score breakdowns, confidence aggregation, source-mode preservation, explanation points, recommended next steps, and export-safe summaries without malicious labels, final threat verdicts, external feeds, external AI calls, blocking, or enforcement.

Sanitized real-device validation after Milestone O confirmed that the local runtime stack can operate for an extended period with orchestrator, master, worker, TUI, runtime status, runtime export, remote administration, node heartbeats, scoring, advisory remediation, and live dashboard updates functioning together. It also confirmed dry-run safety, duplicate stack-start protection, multi-node dashboard status, live score changes, service observations, heuristic labels, and no automatic enforcement. Private validation artifacts remain out of public documentation.

## Completion Milestone Roadmap

### Milestone N - Active Federation Runtime (Complete Baseline)

Goal:
Turn trusted federation models into active runtime exchange loops between approved nodes.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 83 | Federation Runtime Manager | Complete baseline: coordinate active federation session records, runtime lifecycle state, component state, and operator-approved exchange window plans without live execution. |
| 84 | Trusted Peer Lifecycle | Complete baseline: manage peer enrollment, approval, pause, resume, revoke, expiration, trust scope updates, session linkage, stale/expired/revoked summaries, and local registry dictionaries. |
| 85 | Runtime Exchange Scheduler | Complete baseline: schedule signed summary exchange, synchronization, event propagation, retry windows, bounded backoff, per-peer job state, and dashboard/API-ready summaries without execution. |
| 86 | Active Federation Validation | Complete baseline: validate trusted peers, signed exchanges, synchronization windows, event propagation, replay windows, scheduler state, and runtime manager readiness without execution. |
| 87 | Federation CLI Commands | Add operator commands for federation status, peers, exchange, sync, diagnostics, export, and dry-run previews. |
| 88 | Active Federation Validation | Validate active exchange loops with sanitized local-node fixtures, failure isolation, replay protection, and no untrusted discovery. |

### Milestone O - Live Network Telemetry (Complete Baseline)

Goal:
Transition PortMap-AI from coordinated runtime/federation intelligence into real live network telemetry ingestion, passive flow reconstruction, protocol metadata extraction, and dynamic topology correlation.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 87 | Passive Interface Discovery | Complete baseline: plan passive interface targeting, metadata summaries, dry-run capture sessions, passive-mode enforcement, and resource budgets without packet capture. |
| 88 | Live Packet Ingestion | Complete baseline: build bounded packet metadata windows, transport summaries, packet rates, IPv4/IPv6 support, replay-safe counters, malformed/unsupported classification, and dry-run dashboard/API summaries. |
| 89 | Flow Reconstruction | Complete baseline: reconstruct bidirectional flows, timeout-aware sessions, service associations, flow digests, topology edges, complete/partial/malformed classifications, and local-only dashboard/API summaries. |
| 90 | Protocol Metadata Extraction | Complete baseline: extract HTTP, TLS, and DNS metadata summaries, service fingerprints, confidence scores, safe truncation, governance fields, and protocol anomaly summaries without credential or content persistence. |
| 91 | Dynamic Topology Correlation | Complete baseline: correlate live node relationships, flow edges, protocol-aware topology summaries, topology drift, node roles, temporal summaries, bounded graph controls, replay-safe updates, cluster rollups, and federation-aware dashboard/API summaries. |
| 92 | Real-Time Telemetry Dashboard Integration | Complete baseline: build live telemetry, packet/flow rate, topology, interface, protocol, resource, operator visibility, federation-aware, health, bounded update, empty-state, and stale-state dashboard/API models. |

### Milestone P - Gateway and Telemetry Enrichment (Complete Baseline)

Goal:
Strengthen PortMap-AI's live telemetry intelligence before full gateway/router-adjacent deployment by adding richer flow telemetry, process/service attribution, DNS visibility, gateway/router log ingestion, SPAN/mirror-port readiness, and gateway validation workflows.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 93 | Real Flow Telemetry Enrichment | Complete baseline: add enriched flow observations, rolling statistics, direction inference, local/remote endpoint classification, service-port hints, state transitions, confidence scoring, quality flags, and dashboard/API dictionaries. |
| 94 | Process and Service Attribution | Complete baseline: add process-to-port and service attribution summaries from available OS data with permission-safe degraded states, metadata minimization, confidence levels, and dashboard/API dictionaries. |
| 95 | DNS Visibility Mode | Complete baseline: add metadata-only DNS query/response records, domain-to-flow correlation, resolver classification, timing summaries, error summaries, anomaly hints, redaction/truncation options, and dashboard/API dictionaries. |
| 96 | Gateway and Router Log Ingestion | Complete baseline: add sanitized router/firewall log models, syslog-style parser helpers, NAT and allow/deny summaries, timestamp normalization, severity summaries, and runtime/topology/export hooks. |
| 97 | SPAN / Mirror-Port Readiness | Complete baseline: add dry-run readiness profiles, passive capture requirements, interface capability summaries, resource warnings, packet-loss risk summaries, operator checklists, telemetry scaling summaries, and dashboard/API dictionaries. |
| 98 | Gateway Mode Validation | Complete baseline: add sanitized gateway validation records spanning telemetry enrichment, DNS visibility, router logs, SPAN readiness, topology correlation, safety checklist, exports, supported/degraded/unavailable/unsafe states, and dashboard/API dictionaries. |

### Milestone Q - Cross-Platform Runtime Hardening (Complete Baseline)

Goal:
Make PortMap-AI reliably testable and operable across macOS, Linux/Raspberry Pi, and Windows before deeper behavioral intelligence and commercial packaging.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 99 | Cross-Platform Runtime Detection | Complete baseline: platform detection helpers, platform family records, architecture and Python summaries, permission detection, capability placeholders, and dashboard/API-ready compatibility dictionaries. |
| 100 | Windows Runtime Compatibility | Complete baseline: Windows-safe path handling, process/socket visibility fallbacks, permission/elevation summaries, runtime profile defaults, service-mode previews, degraded states, and dashboard/API-ready dictionaries. |
| 101 | Cross-Platform Packet Capture Readiness | Complete baseline: macOS/Linux/Raspberry Pi/Windows capture capability summaries, Npcap/WinPcap readiness, BPF/libpcap/scapy readiness, backend states, passive warnings, and no automatic capture mode changes. |
| 102 | Cross-Platform Firewall Provider Readiness | Complete baseline: Windows Defender Firewall, macOS pf, Linux nftables/ufw/iptables, and Raspberry Pi dry-run preview providers with rule safety warnings and no rule changes. |
| 103 | Cross-Platform Filesystem and Export Safety | Complete baseline: safe log/export/cache path summaries, artifact exclusion validation, private-file warnings, runtime artifact classification, public-doc checks, and OS-specific path normalization. |
| 104 | Cross-Platform Validation Summary | Complete baseline: unified macOS/Linux/Raspberry Pi/Windows validation reports with capture/firewall/filesystem/export rollups, CLI table/JSON output, recommendations, and dashboard/API-ready compatibility summaries. |

### Milestone R - Behavioral Intelligence Foundation (Complete Baseline)

Goal:
Add the first historical behavioral intelligence layer for PortMap-AI so the platform can begin learning normal network behavior over time instead of only showing current telemetry snapshots.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 105 | Historical Flow Baselines | Complete baseline: rolling metadata-only baseline records for flows, services, ports, protocols, process/service fingerprints, and DNS/domain observations with first-seen and last-seen windows, frequency counters, stable versus new classification, bounded windows, confidence scoring, dashboard/API summaries, and export-ready digests. |
| 106 | Temporal Anomaly Windows | Complete baseline: time-window anomaly records with short, medium, and long summaries, burst detection, rare service timing detection, volume drift hints, novelty labels, advisory confidence scoring, operator explanations, dashboard/API dictionaries, and export-ready digests. |
| 107 | Service Behavior Fingerprints | Complete baseline: recurring metadata-only service fingerprint records for process, service, protocol, port, transport, flow role, redacted DNS-summary, runtime platform, interface class, and direction combinations with expected service behavior profiles, unusual combination labels, dormant service return tracking, confidence summaries, dashboard/API dictionaries, and export-ready digests. |
| 108 | DNS and Destination Behavior Learning | Complete baseline: recurring redacted or hashed DNS/domain summaries, resolver hashes, destination classification placeholders, domain frequency and novelty scoring, stable/unusual/new/dormant/drift labels, confidence summaries, dashboard/API dictionaries, and export-ready digests with no external reputation calls. |
| 109 | Adaptive Risk Weighting | Complete baseline: local adaptive scoring helpers with stable behavior reductions, novelty and anomaly increases, unusual service and destination weighting, low-confidence dampening, no-enforcement explanations, dashboard/API dictionaries, and export-ready digests. |
| 110 | Behavioral Intelligence Operator Summary | Complete baseline: unified operator summaries across baselines, anomalies, service fingerprints, DNS/destination learning, and adaptive risk with supported/degraded/unavailable states, recommendations, explanations, dashboard/API views, and export-ready digests. |

### Milestone S - Historical Persistence and Long-Term Intelligence (Complete Baseline)

Goal:
Add lightweight, resource-conscious historical persistence and long-term behavioral memory so PortMap-AI can retain, age, summarize, and replay behavioral intelligence over time without storing raw packet payloads.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 111 | Historical Snapshot Persistence | Complete baseline: rolling metadata snapshot persistence, lightweight storage records, snapshot rotation, bounded retention windows, and export-safe persistence summaries. |
| 112 | Baseline Aging and Decay | Complete baseline: aging and decay helpers, inactive behavior fading, stale fingerprint handling, confidence decay, and long-term baseline maturity tracking. |
| 113 | Long-Term Topology Evolution | Complete baseline: topology evolution summaries, recurring node relationship tracking, topology drift history, and stable versus transient relationship modeling. |
| 114 | Historical Replay Windows | Complete baseline: replay-safe behavioral summaries, historical timeline reconstruction, anomaly replay summaries, and bounded offline review helpers. |
| 115 | Resource-Aware Historical Retention | Complete baseline: Raspberry Pi resource-aware retention controls, adaptive retention windows, storage safety summaries, and low-resource degradation states. |
| 116 | Long-Term Intelligence Operator Summary | Complete baseline: unified historical intelligence summaries, export-ready persistence rollups, dashboard/API historical views, recommendations, and supported/degraded/unavailable states. |

### Future Production Security and Access Control Themes

Goal:
Harden the platform for real operator and enterprise usage after cross-platform runtime behavior is stable.

Candidate future work:

- Local users, roles, permissions, API authorization, and CLI/TUI access controls.
- TLS and local certificate management for local API bindings.
- Secure node enrollment with revocation and trust scope review.
- Audit chain hardening with tamper-evident digests and exportable chains.
- Data retention and redaction policy enforcement.
- Security hardening validation under local and distributed scenarios.

### Future Installer, Service, and Release Packaging Themes

Goal:
Make PortMap-AI installable and maintainable across operating systems.

Candidate future work:

- Operator-approved Linux service installation, preflight checks, rollback records, and systemd integration.
- macOS launch agent templates, install checks, local paths, and operator-controlled startup.
- Windows service templates, install previews, local configuration paths, and validation workflows.
- Repeatable release artifacts, checksums, dependency manifests, and provenance records.
- Versioned upgrades, database migrations, backups, rollback plans, and operator confirmation records.
- Install, service, upgrade, rollback, and uninstall validation across supported platforms.

### Future AI Security Intelligence Layer

Goal:
Add advanced behavior intelligence on top of real telemetry.

Candidate future work:

- Telemetry-backed baselines for hosts, services, flows, protocols, and time windows beyond the current metadata-only behavioral baseline layer.
- Deviation scoring for service drift, topology drift, protocol anomalies, and federation anomalies.
- Attack-path reconstruction from topology, flow, finding, event, and review evidence.
- Explainable review summaries with evidence references, confidence, severity, and recommended review actions.
- Adaptive trust scoring for trusted nodes, services, and topology confidence using signed summaries, health, drift, and anomaly signals.
- AI intelligence validation for determinism, explainability, false-positive controls, and safety boundaries with sanitized fixtures.

### Milestone T - Operationalization and Deployment Foundation

Goal:
Prepare PortMap-AI for reliable real-world deployment by adding production-safe runtime profiles, service lifecycle modeling, deployment manifests, upgrade readiness, backup/restore planning, and operator deployment validation without enabling destructive automation.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 117 | Production Runtime Profiles | Complete baseline: production, staging, development, edge, and lab runtime profile records with safe defaults, compatibility validation, deployment mode summaries, and configuration readiness flags. |
| 118 | Service Lifecycle Readiness | Complete baseline: service provider readiness for systemd, launchd, Windows Service Control Manager, foreground mode, and Raspberry Pi edge mode with dry-run lifecycle previews and sanitized command summaries. |
| 119 | Deployment Manifest Generation | Complete baseline: sanitized standalone, orchestrator, worker, edge, lab, and production-preview manifests with node profiles, readiness summaries, export paths, and backup recommendations. |
| 120 | Upgrade and Migration Readiness | Complete baseline: upgrade readiness reports, version compatibility summaries, migration preview plans, rollback notes, backup requirements, and no-destructive-migration records. |
| 121 | Backup and Restore Planning | Complete baseline: backup plans, restore previews, historical intelligence and evidence bundle safety records, encryption recommendations, conflict warnings, and no automatic restore/delete behavior. |
| 122 | Deployment Operator Summary | Complete baseline: unified deployment readiness summaries, dashboard/API-safe views, recommendations, ready/degraded/blocked/unknown states, and release-readiness checklists. |

### Future Commercial SaaS and Fleet Management

Goal:
Prepare the future business and enterprise deployment model after local operationalization and deployment readiness are stable.

Candidate future work:

- Fleet management architecture for node groups, enrollment, policy assignment, and fleet-level summaries.
- Organization and tenant model with users, roles, workspaces, quotas, audit boundaries, and data isolation.
- Licensing and subscription hooks with local license state, entitlement checks, plan metadata, and commercial feature flags.
- Cloud control plane blueprint with sync contracts, privacy controls, and operational ownership.
- Enterprise API blueprint with auth scopes, pagination, filtering, audit, and export semantics.
- Commercial readiness review covering packaging, security, docs, support workflows, compliance posture, and go-to-market constraints.

## Completion Definition

PortMap-AI is fully functioning when:

- Live data ingestion works from approved network and system telemetry sources.
- Topology reflects real network activity with current assets, services, flows, findings, and drift.
- Multi-node federation works between approved nodes with signed summaries, replay protection, synchronization, diagnostics, and operator visibility.
- Router-adjacent modes are supported through explicit router log, SPAN/mirror-port, Raspberry Pi edge, DNS/flow, gateway profile, and transparent bridge readiness paths.
- Dashboard, TUI, and local API surfaces show live state, health, topology, reviews, exports, and federation status.
- Operator review and export flows work across local, distributed, and federation records.
- Install and service mode works across supported operating systems with upgrade, rollback, and validation workflows.
- Security hardening is complete for local auth, RBAC, TLS, node enrollment, audit chains, retention, and redaction.
- The commercial roadmap is clear for fleet management, tenant modeling, licensing, control-plane design, enterprise APIs, and readiness review.

## Deployment Mode Definitions

Endpoint agent mode:
A local node collects approved host, socket, process, interface, service, and telemetry summaries for its own system and reports them to the local runtime pipeline.

Master/worker distributed mode:
A master coordinates trusted worker summaries, distributed runtime state, federated topology, cluster health, reviews, exports, and signed federation records.

Raspberry Pi edge node mode:
A resource-conscious Linux/ARM profile runs selected runtime, telemetry, federation, dashboard, and export workflows with bounded storage and CPU use.

Router log integration mode:
PortMap-AI imports sanitized router, firewall, DNS, or gateway logs from explicit operator-approved sources and converts metadata into events, findings, topology updates, and review-ready records.

SPAN/mirror-port collector mode:
PortMap-AI prepares passive metadata ingestion from a mirror-port interface under explicit opt-in, with redaction, bounds, readiness checks, and no payload storage by default.

Gateway profile mode:
PortMap-AI runs adjacent to a gateway or router to summarize network flows, DNS activity, service exposure, topology, router logs, readiness, and policy review evidence without automatic enforcement.

Transparent bridge readiness mode:
PortMap-AI prepares and validates bridge-mode requirements through dry-run checks, warnings, and operator review before any future bridge configuration is applied.

Future SaaS fleet mode:
A future enterprise control plane coordinates fleet inventory, tenant boundaries, licensing, policies, fleet summaries, and optional sync contracts with explicit privacy and security controls.

## Safety and Control Model

The completion roadmap keeps the existing control model:

- Nodes must be operator-approved before federation or fleet workflows accept their records.
- Local-first defaults remain the baseline for telemetry, storage, review, dashboard, and export behavior.
- Signed summaries and replay-window metadata protect trusted federation records from stale or duplicate updates.
- Review workflows stay advisory and preserve explicit operator decisions.
- Dry-run defaults remain standard for setup, service mode, gateway mode, installer, and remediation-adjacent workflows.
- Explicit local-write modes are required for storage, runtime history, service setup, retention, and export writes.
- Audit and export records preserve evidence references, safety fields, digests, redaction state, and operator action history.

## Validation Strategy

Unit tests:
Cover deterministic record builders, validators, parsers, scoring helpers, serializers, state transitions, CLI formatting, and safety fields.

Integration tests:
Exercise runtime pipelines across telemetry, storage, topology, policy review, federation, diagnostics, dashboard providers, and export bundles.

macOS live validation:
Validate endpoint-agent workflows, runtime state, CLI/TUI operation, local API dictionaries, telemetry permissions, and packaging behavior on a development host.

Raspberry Pi live validation:
Validate edge-device profiles, resource budgets, telemetry rates, storage limits, federation summaries, dashboard/TUI usability, and service readiness on Linux/ARM.

Long-running runtime validation:
Run extended sessions for scheduler behavior, queue depth, telemetry storage, checkpoint recovery, federation exchange windows, health events, and export rotation.

Network-lab validation:
Use a controlled lab with placeholder nodes, router logs, mirror-port telemetry, DNS/flow records, signed federation summaries, and gateway-adjacent profiles.

Release packaging validation:
Validate Linux, macOS, and Windows packaging, install, service setup, upgrade, rollback, dependency manifests, checksums, and release documentation.

## Documentation Requirements

Each future milestone should add focused implementation plans, operator docs, packaging references, and validation checklists. Public docs and tests must use sanitized placeholders only and must not include real IP addresses, MAC addresses, hostnames, usernames, tokens, logs, screenshots, packet payloads, local paths, database files, cache files, environment files, archives, runtime artifacts, or private validation notes.
