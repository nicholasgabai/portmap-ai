# Federation Dashboard/API Readiness

Phase 82 adds read-only federation dashboard and local API view models for trusted runtime federation records. The helpers convert already-built trusted peer, transport, signed exchange, synchronization, distributed event propagation, and federation diagnostic summaries into deterministic dictionaries for local dashboards and future local API providers.

This phase does not create live network listeners, expose public services, replace the Textual terminal dashboard, execute remote commands, or persist a parallel schema.

## Build Targets

- `core_engine/federation/operator_views.py`
- `gui/web/federation_views.py`
- `tests/test_federation_dashboard_api_readiness.py`

## View Model Inputs

The core view builder accepts existing local records:

- Local node trust profile and approved peer summaries.
- Trusted transport session records.
- Signed runtime summary exchange envelopes or exchange summaries.
- Live cluster synchronization results.
- Distributed event propagation batches.
- Federation diagnostics records.
- Optional cluster health and distributed node-state records.

All inputs are operator-provided local dictionaries. The view helpers do not contact peers, start services, bind sockets, or collect new records.

## Dashboard Panels

`build_federation_operator_view()` returns these stable panels:

- `trusted_peers`
- `transport_sessions`
- `signed_exchanges`
- `synchronization`
- `event_propagation`
- `diagnostics`
- `readiness`
- `counters`

Each panel contains:

- `panel`
- `status`
- `generated_at`
- `metrics`
- `detail`
- `recommended_review`
- safety fields such as `local_only`, `read_only`, `network_listener_enabled: false`, and `remote_control_enabled: false`

The counter panel rolls up stale, rejected, replayed, and duplicate records so operators can see replay-window and propagation risk without opening detailed records first.

## Local API Shape

The operator view includes an `api` dictionary with:

- `status`
- `generated_at`
- `count`
- `items`
- `panels`
- `summary`
- `empty_state`

The shape is compatible with existing local dashboard provider responses. It is a dictionary only; this phase does not start a local API server.

## Web Adapter

`gui/web/federation_views.py` adds a small rendering adapter:

- `build_federation_dashboard_view()`
- `build_federation_dashboard_sections()`
- `render_federation_dashboard_sections()`
- `federation_dashboard_api_response()`
- `build_empty_federation_dashboard_view()`

These helpers mirror existing dashboard section patterns and keep the Textual TUI unchanged.

## Empty State

When no federation records are provided, the view status is `empty`, the API count is `0`, and every panel renders as an empty panel. Empty states remain explicit so local dashboards can show a clean trusted-federation placeholder without implying that federation transport is active.

## Safety Boundaries

Phase 82 output remains:

- local-only
- read-only
- advisory by default
- operator-controlled
- API-compatible dictionary output only
- `raw_payload_stored: false`
- `automatic_changes: false`
- `network_listener_enabled: false`
- `remote_control_enabled: false`
- `public_exposure_enabled: false`

No raw payload bytes, private signing material, host configuration, real node identifiers, local paths, logs, screenshots, database files, or runtime artifacts are required for public examples or tests.

## Sanitized Example

```json
{
  "record_type": "federation_operator_view",
  "status": "ok",
  "panels": {
    "trusted_peers": {
      "panel": "trusted_peers",
      "status": "ok",
      "metrics": {
        "approved_peer_count": 1,
        "expired_peer_count": 0
      },
      "remote_control_enabled": false
    }
  },
  "public_exposure_enabled": false
}
```

## Validation

- Run `python -m pytest`.
- Run `git diff --check`.
- Confirm staged public files contain sanitized placeholders only.
- Confirm no private identifiers, keys, logs, screenshots, archives, database files, cache files, or runtime artifacts are staged.
- Keep `docs/real_device_validation.md` unstaged unless it is separately scrubbed and explicitly approved.
