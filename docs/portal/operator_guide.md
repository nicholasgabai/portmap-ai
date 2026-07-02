# Operator Guide

## Purpose

This guide explains how an operator should approach PortMap-AI as a local visibility and intelligence tool. The operator workflow is centered on read-only observation, review, export, and validation.

## What Operators Should Know

PortMap-AI summarizes ports, services, runtime status, attribution, risk context, behavior graph intelligence, and packet metadata. The system is designed to keep operators in control: advisory intelligence does not automatically block, remediate, change policies, or modify services.

## Key Commands And Concepts

- Run focused validation with `python -m pytest tests/test_gui_app.py`.
- Run full validation with `python -m pytest`.
- Review the Textual TUI for Dashboard, Risk, AI, Packet, Governance, Deployment, and Export workspaces.
- Treat risk, AI, and packet outputs as evidence summaries that require operator review.

## Safety Notes

Operator workflows should remain metadata-first. Do not paste credentials, secrets, payload contents, or private validation notes into public documentation.

## Current Limitations

The portal does not replace runtime help inside the TUI. It provides a stable local reference for the current product architecture and operating model.

## Related Docs

- [Packet Intelligence Guide](packet_intelligence_guide.md)
- [AI Intelligence Guide](ai_intelligence_guide.md)
- [Troubleshooting Guide](troubleshooting_guide.md)
- [TUI Dashboard](../tui_dashboard.md)
