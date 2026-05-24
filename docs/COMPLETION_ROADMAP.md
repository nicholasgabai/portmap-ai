# PortMap-AI Completion Roadmap

This roadmap defines the remaining end-to-end work required to turn PortMap-AI from its current local and trusted-federation baseline into a fully functioning live network intelligence platform. The target platform should support live telemetry, gateway/router-adjacent visibility, production security, installable services, release packaging, advanced AI security intelligence, and a clear commercial path.

This is a planning document. It does not implement collectors, start services, open network listeners, change host networking, enable gateway behavior, transmit data externally, or perform automatic enforcement.

## Current Completed Foundation

PortMap-AI has completed baseline implementation through Milestone O and Phase 89, covering Phases 0-89.

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

Current posture remains local-first, operator-controlled, advisory by default, read-only unless explicitly run in local-write mode, and suitable for sanitized test fixtures.

## Remaining Milestone Roadmap

### Milestone N - Active Federation Runtime

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

### Milestone O - Live Network Telemetry

Goal:
Transition PortMap-AI from coordinated runtime/federation intelligence into real live network telemetry ingestion, passive flow reconstruction, protocol metadata extraction, and dynamic topology correlation.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 87 | Passive Interface Discovery | Complete baseline: plan passive interface targeting, metadata summaries, dry-run capture sessions, passive-mode enforcement, and resource budgets without packet capture. |
| 88 | Live Packet Ingestion | Complete baseline: build bounded packet metadata windows, transport summaries, packet rates, IPv4/IPv6 support, replay-safe counters, malformed/unsupported classification, and dry-run dashboard/API summaries. |
| 89 | Flow Reconstruction | Complete baseline: reconstruct bidirectional flows, timeout-aware sessions, service associations, flow digests, topology edges, complete/partial/malformed classifications, and local-only dashboard/API summaries. |
| 90 | Protocol Metadata Extraction | Extract HTTP, TLS, and DNS metadata, service fingerprints, confidence scores, safe truncation, and protocol anomaly summaries without credential or content persistence. |
| 91 | Dynamic Topology Correlation | Correlate live node relationships, flow edges, topology drift, node roles, temporal summaries, cluster rollups, and federation-aware topology summaries. |
| 92 | Real-Time Telemetry Dashboard Integration | Build live telemetry, packet/flow rate, topology, interface, protocol, resource, operator visibility, and federation-aware dashboard/API models. |

### Milestone P - Gateway and Router-Adjacent Modes

Goal:
Support router-adjacent deployment options for broader network visibility.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 95 | Router Log Integration | Import router, firewall, and DNS log records from explicit local files or approved local sources. |
| 96 | SPAN/Mirror-Port Ingestion | Support passive metadata ingestion from mirror-port interfaces with strict bounds and redaction. |
| 97 | Raspberry Pi Gateway Profile | Define edge-device runtime settings, resource budgets, storage limits, and dashboard profiles for Pi deployments. |
| 98 | Transparent Bridge Readiness | Prepare bridge-mode preflight checks, operator warnings, interface validation, and dry-run configuration previews. |
| 99 | DNS/Flow Visibility Mode | Build DNS and flow visibility summaries, topology links, findings, and review records from approved inputs. |
| 100 | Gateway Mode Validation | Validate router-adjacent modes in a network lab with sanitized evidence, explicit opt-in, and no automatic enforcement. |

### Milestone Q - Production Security and Access Control

Goal:
Harden the platform for real operator and enterprise usage.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 101 | Local Auth and RBAC | Add local users, roles, permissions, API authorization, and CLI/TUI access controls. |
| 102 | TLS and Local Certificate Management | Manage local certificates, trust stores, rotation records, and secure local API bindings. |
| 103 | Secure Node Enrollment | Enroll trusted nodes with signed enrollment records, revocation, trust scope review, and audit history. |
| 104 | Audit Chain Hardening | Strengthen audit event ordering, tamper-evident digests, exportable chains, and retention metadata. |
| 105 | Data Retention and Redaction Policies | Define retention windows, redaction policies, private data handling, and operator-controlled purge workflows. |
| 106 | Security Hardening Validation | Validate auth, TLS, enrollment, audit, retention, and redaction controls under local and distributed scenarios. |

### Milestone R - Installer, Service, and Release Packaging

Goal:
Make PortMap-AI installable and maintainable across operating systems.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 107 | Linux Service Installer | Add operator-approved Linux service installation, preflight checks, rollback records, and systemd integration. |
| 108 | macOS Launch Agent Support | Add macOS launch agent templates, install checks, local paths, and operator-controlled startup. |
| 109 | Windows Service Support | Add Windows service templates, install previews, local configuration paths, and validation workflows. |
| 110 | Release Build Pipeline | Build repeatable release artifacts, checksums, dependency manifests, and provenance records. |
| 111 | Upgrade/Rollback Workflow | Provide versioned upgrades, database migrations, backups, rollback plans, and operator confirmation records. |
| 112 | Installer Validation | Validate install, service, upgrade, rollback, and uninstall paths across supported platforms. |

### Milestone S - AI Security Intelligence Layer

Goal:
Add advanced behavior intelligence on top of real telemetry.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 113 | Behavioral Baseline Models | Build telemetry-backed baselines for hosts, services, flows, protocols, and time windows. |
| 114 | Anomaly and Drift Scoring | Score deviations, service drift, topology drift, protocol anomalies, and federation anomalies. |
| 115 | Attack Path Reconstruction | Reconstruct likely attack paths from topology, flow, finding, event, and review evidence. |
| 116 | Explainable AI Review Summaries | Produce operator-readable explanations, evidence references, confidence, severity, and recommended review actions. |
| 117 | Adaptive Trust Scoring | Adjust trusted-node, service, and topology confidence using signed summaries, health, drift, and anomaly signals. |
| 118 | AI Intelligence Validation | Validate scoring determinism, explainability, false-positive controls, and safety boundaries with sanitized fixtures. |

### Milestone T - Commercial SaaS and Fleet Management

Goal:
Prepare the future business and enterprise deployment model.

Phases:

| Phase | Name | Focus |
| --- | --- | --- |
| 119 | Fleet Management Architecture | Define fleet inventory, node groups, enrollment, policy assignment, and fleet-level summaries. |
| 120 | Organization and Tenant Model | Model organizations, tenants, users, roles, workspaces, quotas, audit boundaries, and data isolation. |
| 121 | Licensing and Subscription Hooks | Add local license state records, entitlement checks, plan metadata, and commercial feature flags. |
| 122 | Cloud Control Plane Blueprint | Document future cloud control plane boundaries, sync contracts, privacy controls, and operational ownership. |
| 123 | Enterprise API Blueprint | Define enterprise API resources, auth scopes, pagination, filtering, audit, and export semantics. |
| 124 | Commercial Readiness Review | Review packaging, security, docs, support workflows, compliance posture, and go-to-market constraints. |

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
PortMap-AI imports router, firewall, DNS, or gateway logs from explicit operator-approved sources and converts them into events, flows, findings, topology updates, and review records.

SPAN/mirror-port collector mode:
PortMap-AI passively ingests metadata from a mirror-port interface under explicit opt-in, with redaction, bounds, and no payload storage by default.

Gateway profile mode:
PortMap-AI runs adjacent to a gateway or router to summarize network flows, DNS activity, service exposure, topology, and policy review evidence without automatic enforcement.

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
