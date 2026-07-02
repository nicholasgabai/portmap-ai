# Installation Guide

## Purpose

This guide summarizes local setup and validation expectations for PortMap-AI.

## What Operators Should Know

PortMap-AI should be validated locally before operational use. Installation and packaging details vary by platform, but the baseline expectation is that tests and local commands run without requiring cloud services.

## Key Commands And Concepts

- Create and activate the project Python environment according to local setup instructions.
- Install project dependencies from repository-managed requirement files.
- Run `python -m pytest` after changes.
- Use platform-specific packaging docs before installing services.

## Safety Notes

Do not run privileged capture, install services, or change firewall settings unless a documented workflow explicitly calls for it and an operator approves the action.

## Current Limitations

This guide is a portal overview. Platform-specific packaging docs remain the detailed source for macOS, Linux, Windows, container, and Raspberry Pi workflows.

## Related Docs

- [Quick Start](../quick_start.md)
- [Deployment](../DEPLOYMENT.md)
- [Packaging](../packaging.md)
- [Linux Packaging Readiness](../linux_packaging_readiness.md)
