# Milestone W Integration

Milestone W adds the autonomous response and policy engine foundation for PortMap-AI. It connects policy evaluation, adaptive remediation recommendations, quarantine and isolation previews, risk escalation pipelines, incident candidates, safety guardrails, rollback simulation, and autonomous enforcement mode modeling into one advisory response-planning path.

This milestone remains local-first, dry-run safe, preview-only, advisory-first, operator-approved, rollback-aware, source-mode aware, and export-safe. It does not change firewall rules, terminate processes, disable services, isolate nodes, execute quarantine, run rollbacks, create backups or restores, issue final threat verdicts, or activate autonomous enforcement.

## Phase Summary

### Phase 135 - Policy Runtime Engine

The policy runtime engine adds dry-run policy records, in-memory and fixture-safe JSON loading, validation summaries, disabled-policy normalization, and advisory evaluation against telemetry, flow, attribution, drift, topology, and runtime health context.

Policy evaluations return preview-only records with match state, confidence, recommendation, approval requirements, enforcement mode, and destructive-action safety fields. Unsafe enforcement modes and destructive actions are rejected during validation.

### Phase 136 - Adaptive Remediation Logic

Adaptive remediation logic consumes policy evaluations, risk scores, Milestone V flow intelligence, attribution confidence, drift signals, topology context, and runtime health summaries. It produces confidence-weighted remediation recommendations for monitor, review, rate-limit preview, quarantine preview, block preview, and isolate-node preview actions.

All recommendations remain advisory. High-risk recommendations still require approval, rollback awareness, and safety review, and no firewall, service, process, or host action is executed.

### Phase 137 - Quarantine and Isolation Provider Readiness

Quarantine and isolation readiness models Windows Defender Firewall, Linux nftables, Linux ufw, Linux iptables, macOS pf, Raspberry Pi edge, and generic manual operator providers as dry-run readiness records.

Provider records include platform family, supported and unavailable preview actions, readiness state, permission and elevation requirements, sanitized command previews, safety warnings, and advisory notes. No subprocess calls, firewall APIs, process actions, service changes, or containment actions are performed.

### Phase 138 - Risk Escalation Pipelines

Risk escalation pipelines aggregate policy matches, adaptive remediation recommendations, flow intelligence, attribution uncertainty, drift signals, topology relationships, runtime health, and provider readiness into advisory escalation records.

Incident candidate summaries identify exposed-service review, unusual-flow review, attribution-conflict review, drift review, topology-risk review, runtime-health review, and containment-readiness review cases. These records are not final threat verdicts and do not execute any response.

### Phase 139 - Safety Guardrails

Safety guardrails add approval gates, rollback gates, blast-radius gates, provider readiness gates, confidence gates, runtime health gates, policy scope gates, and emergency-stop gates. Rollback simulations preview rollback availability, confidence, validation steps, failure modes, required backups, and operator actions.

Guardrails are preview-only and do not create backups, restore files, modify configs, modify firewall rules, stop services, kill processes, or run rollback steps.

### Phase 140 - Autonomous Enforcement Mode Modeling

Autonomous enforcement mode modeling defines monitor, supervised, autonomous-preview, and hardened-preview modes plus autonomy control summaries. Mode records describe allowed and blocked action classes, approval requirements, guardrail requirements, rollback requirements, provider requirements, runtime health requirements, audit requirements, emergency-stop expectations, and safer-mode recommendations.

Containment remains disabled, enforcement remains inactive, `preview_only` remains true, and `destructive_action` remains false.

## Integration Points

### Milestone V Flow Intelligence

Milestone W consumes Milestone V metadata-only flow, session, attribution, drift, topology, trust-zone, and dependency summaries as evidence for policy evaluation and response planning. It does not inspect payloads, generate PCAPs, or turn drift into a threat verdict.

### Policy Evaluation

Policy runtime records provide the first structured bridge from observed metadata to operator-reviewable response intent. Policies can match port exposure, service behavior, flow behavior, application attribution, drift behavior, topology relationships, and runtime health while remaining preview-only.

### Adaptive Remediation Recommendations

Adaptive recommendations translate policy and intelligence context into confidence-weighted next steps. Low confidence stays monitor or review, while higher-risk scenarios can request operator approval for preview-only containment plans.

### Quarantine And Isolation Previews

Provider readiness records explain whether platform-specific containment providers are ready, degraded, unavailable, or unknown. They produce sanitized command previews for operator understanding, but do not call subprocesses, firewall APIs, service managers, or system tools.

### Risk Escalation Pipelines

Risk escalation pipelines combine policy matches, recommendations, attribution, drift, topology, runtime health, and provider readiness into bounded escalation summaries. Safety blockers can override risk and produce blocked-by-safety states.

### Incident Candidates

Incident candidates organize escalation outputs into review categories for future SOC-style operator workflows. They are evidence summaries and review prompts, not threat verdicts.

### Safety Guardrails

Safety guardrails evaluate whether a future response should require approval, rollback readiness, provider readiness, confidence thresholds, runtime health, policy scope checks, blast-radius review, or emergency-stop availability before any real enforcement could be considered.

### Rollback Simulation

Rollback simulation records preview rollback feasibility, validation steps, failure modes, required backups, and operator actions. They do not execute rollback, create backups, restore files, delete files, or change host state.

### Enforcement Mode Modeling

Enforcement mode records define the future operating-mode ladder from monitor to supervised and autonomous preview modes. They keep containment disabled and make approval, audit, guardrail, rollback, runtime health, and emergency-stop requirements explicit.

### Future Supervised And Autonomous Response

Milestone W prepares the data contracts for later supervised and autonomous response work. Future enforcement still requires separate production validation, explicit operator approval paths, audit trails, rollback readiness, provider-specific safety controls, and a separate decision to enable any real action.

## Safety Guarantees

Milestone W explicitly guarantees:

- No firewall changes.
- No process termination.
- No service disablement.
- No node isolation.
- No quarantine execution.
- No rollback execution.
- No backups or restores.
- No final threat verdicts.
- No autonomous enforcement activation.
- No subprocess calls for provider previews.
- No credential storage.
- No packet payload inspection.
- No raw packet storage or PCAP generation.
- No private host, IP, MAC, username, credential, cert, key, log, screenshot, cache, database, or runtime artifact in public docs.
- Preview-only and advisory-first behavior.

## Data Flow

```text
Milestone V metadata intelligence
  -> policy runtime evaluation
  -> adaptive remediation recommendations
  -> quarantine/isolation provider readiness
  -> risk escalation pipeline
  -> incident candidate summaries
  -> safety guardrail and rollback simulation checks
  -> autonomous enforcement mode and autonomy-control summaries
  -> dashboard/API/export-safe response planning
```

## macOS Source-Of-Truth Checklist

Use the Mac repository as the source of truth.

- Run `python -m pytest`.
- Run `git diff --check`.
- Confirm sensitive-data scans pass for staged files.
- Confirm artifact/private-file checks pass.
- Confirm `docs/real_device_validation.md` and local test files remain unstaged.
- Confirm Milestone W docs use sanitized placeholders only.
- Confirm no firewall, process, service, rollback, backup, restore, quarantine, or enforcement command is executed.

## Raspberry Pi/Linux ARM Runtime Checklist

Pull only after the Mac push succeeds.

- Validate policy evaluation with bounded live-like or sanitized fixture metadata.
- Confirm remediation recommendations remain preview-only.
- Confirm provider readiness handles Raspberry Pi edge constraints without executing provider commands.
- Confirm risk escalation and incident candidates remain bounded during repeated runtime cycles.
- Confirm guardrails and autonomy controls keep containment disabled.
- Confirm CPU and memory remain stable for repeated summary generation.

## Linux Compatibility Checklist

- Validate Linux nftables, ufw, and iptables provider records as dry-run previews.
- Confirm permission and elevation requirements are advisory summaries only.
- Confirm no firewall rules, services, processes, configs, backups, restores, or rollback steps are modified.
- Confirm export dictionaries remain deterministic and sanitized.

## Windows Compatibility Fixtures Checklist

Use fixture records only.

- Validate Windows Defender Firewall provider readiness records.
- Confirm command previews are sanitized and never executed.
- Confirm service, process, registry, firewall, credential, certificate, and key actions remain unmodeled as completed.
- Confirm policy, remediation, escalation, guardrail, rollback, and enforcement-mode dictionaries serialize safely.

## Policy Evaluation Safety Checklist

- Confirm unsafe enforcement modes are rejected.
- Confirm disabled policies normalize without matching.
- Confirm malformed policies produce invalid or degraded records instead of exceptions.
- Confirm `preview_only` remains true and `destructive_action` remains false.

## Remediation Preview Safety Checklist

- Confirm low confidence produces monitor or review recommendations.
- Confirm high risk still requires approval.
- Confirm rollback-required summaries are advisory only.
- Confirm no firewall, service, process, or host action is executed.

## Provider Preview Safety Checklist

- Confirm provider command previews are sanitized.
- Confirm no subprocess calls or firewall APIs are used.
- Confirm unavailable providers produce blocked or degraded advisory states.
- Confirm platform-specific limitations are documented in operator notes.

## Escalation Candidate Safety Checklist

- Confirm incident candidates do not contain final threat verdict fields.
- Confirm safety blockers can override risk escalation.
- Confirm evidence summaries use metadata-only references.
- Confirm candidate lists remain bounded.

## Guardrail And Rollback Safety Checklist

- Confirm approval, rollback, blast-radius, provider, confidence, runtime, policy-scope, and emergency-stop gates serialize safely.
- Confirm rollback simulations do not create backups, restore files, delete files, overwrite configs, or execute rollback steps.
- Confirm blocked/degraded states include operator-safe reasons.

## Enforcement Mode Safety Checklist

- Confirm monitor, supervised, autonomous-preview, and hardened-preview modes all keep `preview_only` true.
- Confirm `destructive_action` is always false.
- Confirm containment remains disabled.
- Confirm emergency-stop, audit, approval, rollback, provider, and runtime health requirements are explicit.

## Sensitive-Data Scan Checklist

- Scan staged docs, tests, and package metadata for private hostnames, IP addresses, usernames, MAC addresses, credentials, certs, keys, private paths, logs, screenshots, archives, runtime outputs, and databases.
- Confirm docs use sanitized examples and no private validation notes.

## Artifact And Private-File Check

- Confirm `docs/real_device_validation.md` is not staged.
- Confirm `testfile.txt` is not staged.
- Confirm no `logs/`, `artifacts/`, screenshots, archives, cache files, temp files, local runtime outputs, local databases, private credentials, certificates, or keys are staged.
