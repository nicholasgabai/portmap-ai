# Troubleshooting Guide

## Purpose

This guide provides a safe local troubleshooting flow for PortMap-AI.

## What Operators Should Know

Start with deterministic validation. Prefer focused tests for the area being changed, then run the full suite before review. Use logs and status summaries before making environment changes.

## Key Commands And Concepts

- Run a focused test such as `python -m pytest tests/test_packet_intelligence_integration.py`.
- Run full validation with `python -m pytest`.
- Check formatting with `git diff --check`.
- Review `git status --short` before staging files.
- Keep unrelated validation notes and scratch files out of commits.

## Safety Notes

Avoid destructive commands during troubleshooting. Do not reset, delete, or overwrite user changes unless the operator explicitly requests that action.

## Current Limitations

This guide is a general workflow. Individual runtime, packaging, capture, and deployment issues may require their specific docs.

## Related Docs

- [Runtime Health Monitor](../runtime_health_monitor.md)
- [Runtime CLI](../runtime_cli.md)
- [Gateway Mode Validation](../gateway_mode_validation.md)
- [Operator Guide](operator_guide.md)
