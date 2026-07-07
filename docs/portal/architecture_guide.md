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
- Listener-derived evidence and conversation-derived evidence are intentionally distinct. A listener such as `TCP/22 LISTEN` may have an observation ID and listener provenance without a flow key, while an established conversation can carry observation, flow, and session references when endpoint metadata is available.
- Operator-facing timestamps preserve UTC internally and label UTC detail values explicitly so local evening activity that crosses a UTC date boundary is not silently presented as an unexplained next-day event.
- Governance and export layers focus on reviewability, redaction, and accountability.
- Deployment and commercial-readiness models describe future operational structure without creating hosted services.

## Safety Notes

Architecture boundaries should preserve read-only defaults. Packet payloads, credentials, secrets, private validation data, and raw capture contents should not enter summary models or public docs.

## UTC Timestamp Contract

PortMap-AI uses UTC as the canonical timestamp standard for new runtime records. Newly created canonical timestamps should be timezone-aware UTC and serialize as unambiguous ISO-8601 values ending in `Z`, such as `2026-07-05T04:34:11Z`.

Aware source timestamps from workers or imported metadata are converted to UTC once with timezone-aware conversion. Naive timestamps are not assumed to be local time and are not labeled as UTC by replacing timezone metadata. When legacy records contain ambiguous timestamp strings, PortMap-AI preserves the original value and surfaces the ambiguity instead of rewriting history.

The worker, master/orchestrator, storage, risk, AI, packet/flow, API, export, and TUI paths should preserve the same instant. TUI detail rows display UTC explicitly, including packet and flow activity, so activity generated in a local evening timezone can correctly appear on the next UTC date without looking like unexplained future activity.

## Current Limitations

The documentation portal does not include generated diagrams. Existing graph and visualization modules provide data structures that future renderers can consume.

## Validation Note

Physical validation with a sanitized SSH-style scenario showed that socket-state telemetry can observe both a listener and an established connection while packet activity remains limited to flow-shaped metadata. The architecture now carries canonical observation, flow, and session references through reconstruction, correlation, risk, learning, behavior graph, investigation, AI evidence, API serialization, and TUI details where those references are semantically available. Listener-only evidence continues to show flow identity as not applicable rather than synthesizing a fake flow key.

## Related Docs

- [Packet Intelligence Guide](packet_intelligence_guide.md)
- [AI Intelligence Guide](ai_intelligence_guide.md)
- [Architecture](../architecture.md)
- [Security Model](../SECURITY_MODEL.md)
