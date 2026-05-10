# PortMap-AI CLI Reference

The installed command is `portmap`. This reference lists the primary command families; run `portmap <command> --help` for exact options.

## Setup and Runtime

- `portmap setup` initializes `~/.portmap-ai` runtime directories and default settings.
- `portmap doctor` reports platform, package, config, command, and runtime diagnostics.
- `portmap stack` launches the local orchestrator/master/worker stack.
- `portmap tui` starts the Textual terminal dashboard.

## Local API Checks

- `portmap health` checks orchestrator health.
- `portmap nodes` lists orchestrator nodes.
- `portmap metrics` prints orchestrator metrics.
- `portmap logs` filters or exports local audit/log data.

## Observability and Analysis

- `portmap scan` runs local socket inventory or explicit target/port checks.
- `portmap discover` builds authorized asset inventory observations.
- `portmap services` performs service/version detection.
- `portmap os` analyzes OS-family evidence.
- `portmap fast-scan` plans and runs bounded async TCP connect checks.
- `portmap capture` collects packet metadata where supported.
- `portmap dpi` analyzes packet/payload metadata.
- `portmap tls` analyzes TLS posture.
- `portmap flows` reconstructs passive flow summaries.

## Intelligence and Advisory Workflows

- `portmap behavior` analyzes local behavior baselines.
- `portmap payload` classifies payload observations.
- `portmap correlate` correlates events into advisory incidents.
- `portmap recommend` creates administrator-facing recommendations.
- `portmap cve` matches service evidence against CVE records.
- `portmap vuln` correlates service/CVE exposure findings.

## Enterprise and Integration Helpers

- `portmap rbac` inspects local roles and permissions.
- `portmap alert` formats alert/SIEM payloads and supports explicit dry-run or send flows.
- `portmap cluster plan` creates dry-run distributed job plans.
- `portmap workspace` summarizes tenant, organization, team, and workspace records.
- `portmap license` summarizes local license, quota, and usage metadata.
- `portmap cloud-sync` creates or imports encrypted sync manifests.
- `portmap advisory` builds recommendation review packets.

## Safety

CLI commands follow the global PortMap-AI safety guarantees in `PORTMAP_AI_HANDOFF.md` and `docs/SECURITY_MODEL.md`.
