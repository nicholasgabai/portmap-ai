# Dashboard Data Providers

Phase 63 connects the reusable local web dashboard foundation to provider-backed data from the local API shape, local storage repositories, runtime state, topology summaries, review queues, and diagnostic summaries.

The provider layer is read-only. It does not replace the Textual TUI, start services, contact external systems, run scans, execute plugins, install services, write configuration, or transmit data.

## Modules

- `gui.web.providers`
- `gui.web.views`

## Provider Types

`StaticDashboardProvider` accepts API-compatible dictionaries for tests, examples, or local previews.

`StorageDashboardProvider` reads from existing local repository helpers and optional runtime/review/diagnostic inputs:

- `LocalStorageRepository`
- `RuntimeState`
- `PersistentReviewStore` or `ReviewQueue`
- topology snapshots and topology edge records
- diagnostic summary records

No parallel schema or separate persistence system is introduced.

## Basic Example

```python
from gui.web.providers import StaticDashboardProvider
from gui.web.views import build_dashboard_view, render_dashboard_view

provider = StaticDashboardProvider(
    {
        "health": {"status": "ok"},
        "assets": {"status": "ok", "count": 1, "items": [{"asset_id": "asset-sample"}]},
        "events": {"status": "ok", "count": 0, "items": []},
    }
)

model = build_dashboard_view(provider)
html = render_dashboard_view(provider)
```

Use placeholders only in docs and tests.

## Storage-Backed Provider

```python
from gui.web.providers import StorageDashboardProvider

provider = StorageDashboardProvider(
    repository,
    runtime_state=runtime_state,
    review_store=review_store,
    diagnostics=[{"diagnostic_id": "diagnostic-sample", "status": "ok"}],
)
model = build_dashboard_view(provider)
```

The provider returns local API-compatible payloads for:

- `/health`
- `/events`
- `/assets`
- `/snapshots`
- `/nodes`
- `/topology`
- `/operator_reviews`
- `/diagnostics`

## Summary Helpers

The module also exposes focused helpers:

- `runtime_state_response()`
- `snapshot_summary_response()`
- `topology_summary_response()`
- `review_summary_response()`
- `diagnostic_summary_response()`

These helpers return JSON-compatible dictionaries with explicit safety fields.

## Empty State

`build_dashboard_view()` marks `empty_state: true` when all major counters are zero. Empty-state rendering remains local and read-only.

## Safety Properties

Provider outputs include:

```json
{
  "local_only": true,
  "read_only": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Phase 63 is a dashboard data-provider integration layer only. It does not expose public internet endpoints or modify runtime behavior.
