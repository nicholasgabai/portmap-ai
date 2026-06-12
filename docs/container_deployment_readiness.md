# Container Deployment Readiness

Phase 162 adds container deployment readiness models for future Docker, Compose, Podman, and containerd-preview deployment paths. The implementation defines container profile previews, runtime readiness summaries, image build readiness, Compose readiness, volume/network/environment layout previews, resource limit recommendations, uninstall previews, rollback previews, and validation summaries without building images, publishing registries, starting containers, stopping containers, calling Docker or Podman APIs, writing Compose files, writing files, storing credentials, or changing runtime behavior.

## Container Profile Records

`core_engine.packaging.container_profiles` defines export-safe container profile preview records. Supported profile types are `single_node_preview`, `multi_service_preview`, `worker_only_preview`, `orchestrator_preview`, `edge_preview`, and `unknown`.

Supported container runtimes are `docker`, `podman`, `compose`, `containerd_preview`, and `unknown`.

Each profile includes sanitized image references, Compose service previews, volume layout previews, network layout previews, environment previews, resource limit previews, rollback/uninstall availability, validation steps, advisory notes, and fixed safety flags. Environment keys that look like secrets, tokens, passwords, keys, or credentials are redacted.

## Deployment Readiness Records

`core_engine.packaging.container_deployment` defines container deployment readiness summaries with:

- container profiles
- runtime readiness
- image build readiness
- Compose readiness
- volume readiness
- network readiness
- environment readiness
- rollback preview
- uninstall preview
- validation summary
- required permission summaries

Supported deployment states are `ready`, `degraded`, `blocked`, `unavailable`, and `unknown`. Supported deployment methods are `docker_preview`, `compose_preview`, `podman_preview`, `containerd_preview`, and `unknown`.

## Preview Paths

The Docker preview path models local image/runtime readiness only. The Compose preview path models multi-service Compose layout readiness only. The Podman preview path models rootless-compatible runtime readiness only. The containerd preview path models future orchestrator-facing runtime metadata only.

None of these paths builds images, pulls images, pushes images, publishes registries, starts containers, stops containers, creates volumes, creates networks, writes Compose files, or calls container runtime APIs.

## Volume, Network, Environment, And Resource Limits

Volume and network previews describe names, intended layout, and whether host networking or runtime database mounts would be needed in a future deployment. They do not create volumes or networks.

Environment previews are export-safe and redact sensitive-looking keys. They do not write `.env` files or store credentials.

Resource limit previews describe advisory CPU, memory, and storage recommendations. They do not apply cgroups, change runtime limits, or alter collection behavior.

## Uninstall And Rollback

Uninstall and rollback previews are required before future container deployment actions can be considered. They describe review steps and command shape only. No containers, images, volumes, networks, registries, Compose files, or local files are changed.

## Safety Boundary

Phase 162 remains readiness-only:

- No image builds.
- No image pulls or pushes.
- No registry publishing.
- No Docker, Podman, or containerd API calls.
- No container start or stop.
- No Compose file writes.
- No volume or network creation.
- No filesystem writes.
- No administrator escalation.
- No credential storage.
- No runtime behavior changes.

## Future Phases

Phase 163 secure auto-updater and Phase 164 deployment wizard can reuse container deployment previews for runtime checks, resource recommendations, rollback/uninstall previews, and safety summaries while keeping all host-changing behavior disabled until an explicit operator-approved deployment path is added.
