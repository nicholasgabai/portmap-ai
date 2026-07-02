# Developer Guide

## Purpose

This guide gives developers a compact map for working inside the PortMap-AI repository.

## What Developers Should Know

The codebase is organized around local core-engine modules, CLI and TUI surfaces, tests, and documentation. New phases should follow existing module boundaries, preserve deterministic outputs, and avoid broad refactors when a focused change is enough.

## Key Commands And Concepts

- Use `python -m pytest tests/<target>.py` for focused validation.
- Use `python -m pytest` before review commits.
- Use `git diff --check` to catch whitespace issues.
- Prefer structured data models and deterministic sorting for new summaries.
- Keep unrelated dirty files out of commits.

## Safety Notes

Do not introduce network calls, live privileged capture, packet payload handling, enforcement, remediation execution, or cloud dependencies unless a future roadmap phase explicitly authorizes them.

## Current Limitations

The project includes some historical modules that predate the newer metadata-only packet and AI intelligence layers. Prefer current local patterns when extending recent phases.

## Related Docs

- [Architecture Guide](architecture_guide.md)
- [Release Candidate Checklist](release_candidate_checklist.md)
- [Configuration](../configuration.md)
- [API Reference](../api_reference.md)
