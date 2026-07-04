# Packet Intelligence Guide

## Purpose

This guide explains the metadata-only packet intelligence stack completed through Phase 185.

## What Operators Should Know

The packet stack describes observed network metadata without storing packet payloads. It includes capture metadata models, protocol classification, timeline events, visualization data models, hunting/search, and packet intelligence integration summaries.

## Key Concepts

- Packet capture framework: normalized packet metadata and session records.
- Protocol intelligence: deterministic protocol classification from metadata such as ports, protocol fields, tags, and flow keys.
- Flow direction is preserved from the observed metadata; outbound TCP flows keep the original local-to-remote orientation.
- Service candidates such as DNS, SSH, HTTP, and HTTPS are evidence derived from metadata such as protocol and port. They are not proof of application identity by themselves.
- Packet timeline: chronological event records and lifecycle summaries.
- Visualization models: reusable data structures that describe what can be visualized.
- Hunting and search: reusable query objects and deterministic result summaries.
- Packet intelligence integration: compact summaries for attribution, risk, behavior graph, AI details, and future API/TUI surfaces.
- Historical flow aggregation summarizes short-lived bursts with observation counts, unique flow counts, first and last seen times, service candidates, and active-vs-historical status without retaining raw packet payloads.

## Safety Notes

The packet stack does not store payload contents, display raw packet bytes, perform DPI, craft packets, inject traffic, block traffic, enforce policies, or execute remediation.

## Current Limitations

The current portal does not render packet charts or packet tables. Future UI work can consume the existing visualization and intelligence models.

## Related Docs

- [Packet Capture](../packet_capture.md)
- [Protocol Metadata Extraction](../protocol_metadata_extraction.md)
- [Live Packet Ingestion](../live_packet_ingestion.md)
- [Operator Guide](operator_guide.md)
