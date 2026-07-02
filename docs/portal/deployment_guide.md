# Deployment Guide

## Purpose

This guide summarizes deployment planning for local and enterprise evaluation.

## What Evaluators Should Know

PortMap-AI includes deterministic deployment models for runtime profiles, service lifecycle readiness, manifests, backup and restore planning, migration readiness, local licensing, local control-plane metadata, and customer provisioning records.

## Key Concepts

- Runtime profiles describe expected operating modes.
- Service lifecycle readiness records preview service behavior without starting hosted systems.
- Control-plane and provisioning models are local representations for later SaaS phases.
- Packet and AI intelligence remain local-first and operator-controlled.

## Safety Notes

Deployment models do not create hosted APIs, cloud infrastructure, authentication providers, billing, sockets, databases, background services, remote execution, packet forwarding, or enforcement actions.

## Current Limitations

This guide describes readiness models. Production service installation still depends on platform-specific review and operator approval.

## Related Docs

- [Deployment](../DEPLOYMENT.md)
- [Production Runtime Profiles](../production_runtime_profiles.md)
- [Service Lifecycle Readiness](../service_lifecycle_readiness.md)
- [Open Source / Enterprise Model Guide](open_source_enterprise_model.md)
