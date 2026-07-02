# Export Guide

## Purpose

This guide summarizes safe export handling for local evidence and review bundles.

## What Operators Should Know

PortMap-AI export models support local bundles, redaction, deterministic summaries, and coordinated multi-node plans. Exports should be treated as operator-reviewed artifacts, not automatic telemetry.

## Key Concepts

- Export bundles should avoid secrets, credentials, payloads, and private validation details.
- Redaction should be applied before sharing artifacts outside the local environment.
- Deterministic digests help compare local outputs.
- Coordinated export plans describe metadata movement without creating hosted collection.

## Safety Notes

Do not transmit exports automatically. Review contents before moving files to another system.

## Current Limitations

The portal does not generate export bundles. It links to existing export documentation and describes safe handling expectations.

## Related Docs

- [Operational Export Bundle](../operational_export_bundle.md)
- [Coordinated Export Bundles](../coordinated_export_bundles.md)
- [Cross Platform Filesystem Export Safety](../cross_platform_filesystem_export_safety.md)
- [Governance Guide](governance_guide.md)
