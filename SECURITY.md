# Security Policy

PortMap-AI is a local-first network security tool. Treat it like privileged infrastructure software when deploying beyond a single developer machine.

## Supported Baseline

The current release-candidate baseline is `0.1.0`.

## Safe Deployment Defaults

- The default local stack binds orchestrator and master services to loopback addresses.
- Docker Compose requires an explicit `PORTMAP_ORCHESTRATOR_TOKEN`; it does not use the local development token by default.
- Destructive remediation is dry-run by default and requires explicit active-enforcement policy plus confirmation.
- Router/network-control features are advisory-only.
- Runtime logs, state, exports, build artifacts, and local virtual environments should not be committed.

## Required For Shared Or Remote Deployments

- Use a long random orchestrator token through `PORTMAP_ORCHESTRATOR_TOKEN` or `${secret:PORTMAP_ORCHESTRATOR_TOKEN}`.
- Do not expose the master socket or orchestrator API to untrusted networks.
- Place services behind host firewall rules when binding to LAN interfaces.
- Keep firewall plugins in dry-run until policy, confirmation, and audit review are complete.
- Rotate tokens after demos, tests, screenshots, or log exports that may have exposed them.

## Reporting Vulnerabilities

Do not publish exploit details in public issues. Report security concerns privately to the project maintainer or repository owner, including:

- affected version or commit;
- reproduction steps;
- expected and actual behavior;
- whether credentials, logs, or runtime state were exposed.

## Not Yet Implemented

- Multi-user SaaS authentication and authorization.
- Token rotation protocol.
- mTLS enrollment.
- OS-native secret storage.
- Windows service hardening.
