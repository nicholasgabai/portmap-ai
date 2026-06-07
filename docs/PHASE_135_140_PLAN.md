# Phase 135-140 Autonomous Response and Policy Engine Plan

Milestone W begins the transition from advisory intelligence into controlled, policy-driven response planning. The focus is policy runtime records, confidence-weighted remediation recommendations, quarantine/isolation provider readiness, risk escalation pipelines, safety guardrails, and enforcement-mode modeling.

This is a planning document only. It does not enable live enforcement, modify firewall rules, quarantine hosts, disable services, execute rollback actions, inspect packet payloads, store credentials, contact external services, or perform destructive automation.

## Milestone W: Autonomous Response and Policy Engine

Goal:
Begin transitioning PortMap-AI from advisory intelligence into controlled, policy-driven response planning while preserving dry-run safety, operator approval, rollback awareness, and no automatic destructive enforcement.

All work should remain:

- advisory-first
- dry-run safe
- operator-controlled
- policy-aware
- source-attributed
- rollback-aware
- metadata-only
- local-first
- resource-conscious
- Raspberry Pi/Linux ARM compatible
- macOS/Linux/Windows aware
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 135:

- Live worker socket snapshots wired into Milestone V runtime bridge summaries.
- Metadata-only reconstructed sessions, flow summaries, metadata correlations, process/service correlations, relationship edges, attribution candidates, drift summaries, trust-zone inference, and dependency mapping.
- Runtime sessions, runtime health, export bundles, policy review queues, dashboard/API-ready summaries, and advisory remediation safety primitives.
- Cross-platform runtime, packet capture readiness, firewall provider readiness, filesystem/export safety, and validation summaries.
- Secure node identity, transport readiness, secure config and secrets readiness, RBAC previews, tamper detection previews, and secure update previews.
- Deployment readiness, backup/restore planning, historical intelligence, and rollback preview primitives.

Milestone W should connect those records into response planning models. It should not activate enforcement or change host/network state.

## Phase 135 - Policy Runtime Engine

Status: Complete Baseline

Goal:
Create policy runtime records and advisory evaluation helpers that can evaluate local metadata-only evidence against operator-reviewed policies without live enforcement.

Build:

- `core_engine/policy/runtime_engine.py`
- `core_engine/policy/policy_loader.py`
- `tests/test_policy_runtime_engine.py`
- `docs/policy_runtime_engine.md`

Features:

- Policy records.
- Policy loader for sanitized local definitions.
- Policy validation records.
- Advisory policy evaluation summaries.
- Policy scope labels for telemetry, flow, attribution, drift, topology, gateway, federation, and deployment evidence.
- Policy severity and confidence thresholds.
- Source-mode and source-node attribution.
- Operator approval requirement fields.
- Dashboard/API/export-safe policy dictionaries.
- No live enforcement fields defaulting to disabled.

Acceptance:

- Sanitized policy fixtures load deterministically.
- Malformed policies produce validation records, not exceptions that stop processing.
- Advisory evaluation reports matched, unmatched, degraded, and unsupported policies.
- Output preserves source attribution and safety fields.
- No firewall, quarantine, service, rollback, or remediation action is executed.

## Phase 136 - Adaptive Remediation Logic

Status: Complete Baseline

Goal:
Generate confidence-weighted, escalation-aware remediation recommendations that remain supervised and advisory by default.

Build:

- `core_engine/remediation/adaptive_actions.py`
- `core_engine/remediation/escalation.py`
- `tests/test_adaptive_remediation_logic.py`
- `docs/adaptive_remediation_logic.md`

Features:

- Confidence-weighted remediation recommendation records.
- Escalation-aware action planning.
- Supervised response plan records.
- Recommended operator review records.
- Evidence references for flow, attribution, drift, topology, gateway, and health inputs.
- Dry-run remediation command summaries.
- Confidence and uncertainty explanations.
- Rollback preview references.
- Dashboard/API/export-safe recommendation dictionaries.
- Enforcement allowed flag always false by default.

Acceptance:

- Recommendations are deterministic from sanitized fixtures.
- Low-confidence evidence reduces action strength.
- Repeated or higher-confidence signals raise review urgency without enabling blocking.
- Operator approval remains required for all response plans.
- No automatic blocking, service disablement, firewall changes, or destructive rollback occurs.

## Phase 137 - Quarantine and Isolation Provider Readiness

Goal:
Model quarantine and isolation provider readiness across platforms as dry-run previews only.

Build:

- `core_engine/response/isolation_providers.py`
- `core_engine/response/quarantine_readiness.py`
- `tests/test_quarantine_isolation_provider_readiness.py`
- `docs/quarantine_isolation_provider_readiness.md`

Features:

- Windows Defender Firewall readiness summaries.
- Linux nftables, ufw, and iptables readiness summaries.
- macOS pf readiness summaries.
- Raspberry Pi/Linux ARM provider warnings.
- Dry-run provider preview records.
- Isolation scope labels: host, port, service, process, node, and unknown.
- Permission and elevation requirement summaries.
- Operator review requirement flags.
- Provider limitations and unsupported-state records.
- Dashboard/API/export-safe provider dictionaries.

Acceptance:

- Provider readiness is deterministic for macOS, Linux, Raspberry Pi/Linux ARM, and Windows fixtures.
- Unsupported providers degrade safely.
- Command previews are sanitized and dry-run only.
- No firewall rule, quarantine, interface, route, service, or process state is modified.

## Phase 138 - Risk Escalation Pipelines

Goal:
Build multi-signal escalation chains that roll up flow, attribution, drift, topology, health, and gateway signals into incident candidate summaries without threat verdicts.

Build:

- `core_engine/response/escalation_pipeline.py`
- `core_engine/response/incident_candidates.py`
- `tests/test_risk_escalation_pipelines.py`
- `docs/risk_escalation_pipelines.md`

Features:

- Multi-signal escalation chain records.
- Flow, attribution, drift, topology, gateway, federation, and health risk rollups.
- Incident candidate summaries.
- Escalation stage records.
- Evidence contribution summaries.
- Confidence and uncertainty scoring.
- Recurrence and persistence hints.
- Operator-readable incident candidate explanations.
- Dashboard/API/export-safe escalation dictionaries.
- No threat verdicts yet.

Acceptance:

- Escalation pipelines are deterministic with sanitized fixtures.
- Missing inputs create degraded records rather than false certainty.
- Incident candidates remain candidates and do not become threat verdicts.
- Repeated identical inputs do not create unbounded escalation records.
- No enforcement, quarantine, blocking, or service action is executed.

## Phase 139 - Safety Guardrails

Goal:
Create safety guardrail records that preview rollback, blast radius, response simulation, and operator approval gates before any future enforcement mode can be considered.

Build:

- `core_engine/response/safety_guardrails.py`
- `core_engine/response/response_simulation.py`
- `tests/test_safety_guardrails.py`
- `docs/safety_guardrails.md`

Features:

- Rollback preview records.
- Blast-radius summaries.
- Remediation simulation records.
- Operator approval gate records.
- Response preflight checks.
- Policy exception and suppressor preview records.
- Resource and availability impact summaries.
- Audit/export-ready safety summaries.
- Dashboard/API-safe guardrail dictionaries.
- Destructive action flag always false.

Acceptance:

- Guardrails identify missing rollback, missing approval, high blast radius, and unsafe state.
- Simulations are deterministic and preview-only.
- Approval gates are explicit and export-safe.
- No rollback, firewall, quarantine, service, route, file, or process action is executed.

## Phase 140 - Autonomous Enforcement Mode Modeling

Goal:
Define enforcement mode models for monitor, supervised, autonomous-preview, and hardened-preview operation without activating real enforcement.

Build:

- `core_engine/response/enforcement_modes.py`
- `core_engine/response/operator_views.py`
- `tests/test_autonomous_enforcement_mode_modeling.py`
- `docs/autonomous_enforcement_mode_modeling.md`

Features:

- Monitor mode records.
- Supervised mode records.
- Autonomous-preview mode records.
- Hardened-preview mode records.
- Mode transition validation.
- Required policy, RBAC, rollback, audit, provider, and safety guardrail prerequisites.
- Operator-readable mode summaries.
- Dashboard/API/export-safe enforcement mode dictionaries.
- Enforcement active flag false for every mode in this milestone.

Acceptance:

- Mode records serialize deterministically.
- Unsafe or incomplete prerequisites block preview readiness.
- Supervised and autonomous-preview records remain dry-run only.
- Hardened-preview describes future requirements without enabling enforcement.
- No firewall changes, quarantine execution, service disablement, rollback, or automatic enforcement is activated.

## Milestone W Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Run `python -m pytest`.
- Run `git diff --check`.
- Review staged diffs.
- Run a sensitive-data scan.
- Run an artifact/private-file check.
- Confirm `docs/real_device_validation.md` remains unstaged.
- Confirm `testfile.txt` remains unstaged if present.
- Confirm no logs, artifacts, screenshots, caches, runtime outputs, or databases are staged.
- Confirm docs contain no real hostnames, IP addresses, usernames, MAC addresses, SSH details, tokens, credentials, certificates, keys, or private paths.
- Confirm all response behavior remains dry-run and advisory-first.
- Confirm no automatic enforcement, quarantine, firewall changes, service disablement, payload inspection, or destructive rollback is introduced.

## macOS Validation Checklist

- Load sanitized policy fixtures.
- Evaluate advisory policies against sanitized flow, drift, topology, and attribution summaries.
- Generate remediation recommendation previews.
- Generate macOS pf isolation readiness previews.
- Generate escalation candidates without threat verdicts.
- Generate guardrail and simulation summaries.
- Generate enforcement mode previews.
- Confirm no privilege elevation, firewall change, service change, packet capture, or blocking occurs.

## Raspberry Pi / Linux ARM Validation Checklist

- Run focused response planning tests on the target device.
- Evaluate a small sanitized policy set.
- Generate Linux provider readiness previews with Raspberry Pi resource warnings.
- Generate bounded escalation and incident candidate summaries.
- Generate guardrail summaries with low-resource constraints.
- Confirm CPU and memory use remain modest.
- Confirm no nftables, ufw, iptables, service, route, or process state is changed.

## Linux Validation Checklist

- Validate Linux provider readiness fixtures.
- Validate dry-run command previews are sanitized.
- Validate policy evaluation and remediation recommendations with local metadata-only fixtures.
- Confirm no firewall rules are added, removed, or modified.
- Confirm no service disablement, quarantine, rollback, or enforcement occurs.

## Windows Compatibility Fixture Checklist

- Validate Windows Defender Firewall readiness fixtures.
- Validate Windows permission/elevation summaries.
- Validate supervised and preview-mode records.
- Confirm no Windows service control, registry write, firewall change, credential handling, or local account change is modeled as executed.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/policy_runtime_engine.md`
- `docs/adaptive_remediation_logic.md`
- `docs/quarantine_isolation_provider_readiness.md`
- `docs/risk_escalation_pipelines.md`
- `docs/safety_guardrails.md`
- `docs/autonomous_enforcement_mode_modeling.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Automatic firewall blocking.
- Quarantine execution.
- Service disablement.
- Process termination.
- Router modification.
- Packet injection.
- Packet payload inspection.
- PCAP generation.
- Credential handling.
- Destructive rollback.
- External response orchestration.
- Unapproved remote commands.
- Threat verdict engine.
- Autonomous enforcement activation.
- Replacement of the Textual terminal dashboard.
