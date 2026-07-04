# Architecture Guide

## Purpose

This guide describes the main local architecture areas that make up PortMap-AI.

## What Readers Should Know

PortMap-AI is organized as a local-first platform. The core engine contains capture metadata models, protocol intelligence, timeline building, visualization models, hunting, packet intelligence integration, attribution, learning profiles, behavior graph summaries, federation records, governance helpers, deployment models, and export support.

## Key Concepts

- Capture and packet layers produce metadata-only records.
- Protocol, timeline, visualization, hunting, and packet intelligence layers compose those records into summaries.
- Attribution and AI intelligence layers produce deterministic operator-readable reasoning.
- Cross-engine observation identity is preserved with stable observation, flow, node, protocol, port, state, and service-candidate context so Risk and AI summaries can be correlated without implying a single global conclusion.
- Governance and export layers focus on reviewability, redaction, and accountability.
- Deployment and commercial-readiness models describe future operational structure without creating hosted services.

## Safety Notes

Architecture boundaries should preserve read-only defaults. Packet payloads, credentials, secrets, private validation data, and raw capture contents should not enter summary models or public docs.

## Current Limitations

The documentation portal does not include generated diagrams. Existing graph and visualization modules provide data structures that future renderers can consume.

## Related Docs

- [Packet Intelligence Guide](packet_intelligence_guide.md)
- [AI Intelligence Guide](ai_intelligence_guide.md)
- [Architecture](../architecture.md)
- [Security Model](../SECURITY_MODEL.md)
