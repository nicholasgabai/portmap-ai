# PortMap-AI Beginner Guide

## What is a firewall?
A firewall inspects network traffic and enforces policy rules (allow, block, review). PortMap-AI pairs traditional rule logic with AI scoring to flag unusual connections.

## Ports and protocols
- **Port**: a logical endpoint for network services (e.g., 22 SSH, 443 HTTPS).
- **Protocol**: defines how data is exchanged (TCP, UDP, etc.).

PortMap-AI scans open ports, labels protocols, and assigns risk scores.

## Master/Worker flow
1. Worker scans local ports (`basic_scan` placeholder) and sends findings to the master.
2. Master aggregates results, runs risk scoring, and triggers remediation decisions.
3. Orchestrator records heartbeats, metrics, and commands workers.

## Remediation actions
- **Monitor**: no firewall change, just log.
- **Review**: flag for operator attention.
- **Block**: invoke firewall plugin (noop by default, can enable `linux_iptables`).

## Getting started
1. `scripts/run_stack.py` launches orchestrator, master, worker, dashboard, TLS optional.
2. Use the dashboard buttons (`Scan Now`, `Toggle Autolearn`, `Detect Orchestrator`, `Export Logs`).
3. Observe remediation history and metrics (counts of monitor/review/block).
4. Generate certs via `scripts/generate_certs.py` and enable TLS in your profiles.
5. Enable real firewall enforcement by switching the plugin from `noop` to `linux_iptables` (dry-run first!).

See `docs/tutorials/` for lab-style walkthroughs as they become available.
