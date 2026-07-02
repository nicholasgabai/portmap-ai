# PortMap-AI Documentation Portal

## Purpose

This portal is the local documentation index for PortMap-AI operators, developers, and enterprise evaluators. It organizes the project into stable guide areas without requiring a hosted service, web server, SaaS portal, telemetry, or external documentation generator.

## How To Use

Start with the guide that matches your role:

- Operators: [Operator Guide](operator_guide.md), [Packet Intelligence Guide](packet_intelligence_guide.md), and [Troubleshooting Guide](troubleshooting_guide.md).
- Developers: [Developer Guide](developer_guide.md) and [Architecture Guide](architecture_guide.md).
- Enterprise evaluators: [Deployment Guide](deployment_guide.md), [Governance Guide](governance_guide.md), and [Open Source / Enterprise Model Guide](open_source_enterprise_model.md).

The machine-readable index is [manifest.json](manifest.json). It uses deterministic ordering so future UI, export, and API surfaces can consume the same section list.

## Safety Notes

The portal is documentation only. It does not start services, open sockets, run packet capture, contact external systems, execute remediation, change firewall rules, authenticate users, or manage billing.

## Current Limitations

The portal is a local file structure, not a hosted site. Future phases may add rendering or publishing workflows, but this foundation intentionally stays static and offline.

## Related Docs

- [Final Roadmap](../PORTMAP_AI_FINAL_ROADMAP.md)
- [Quick Start](../quick_start.md)
- [Security Model](../SECURITY_MODEL.md)
