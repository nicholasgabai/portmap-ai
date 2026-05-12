# Dashboard Foundation

Phase 49 adds a lightweight local dashboard foundation for PortMap-AI. It renders operator-friendly status panels from local API-compatible dictionaries or provider objects.

This phase does not replace the existing Textual TUI. It does not introduce a frontend build system.

## Panels

The dashboard model includes:

- Health status.
- Asset count.
- Event count.
- Snapshot count.
- Node count.
- Topology node and edge count.
- Operator review count.

## Python Example

```python
from gui.web import build_dashboard_model, render_dashboard_html
from gui.web.sample_data import sample_dashboard_api_data

model = build_dashboard_model(sample_dashboard_api_data())
html = render_dashboard_html(model)
```

To write a local static preview:

```python
from gui.web import write_dashboard_html

write_dashboard_html("<LOCAL_PREVIEW_FILE>", model)
```

The preview file path is explicitly supplied by the operator.

## Safety Boundaries

- Local-first and read-only.
- No external network transport.
- No cloud sync.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No write endpoints.
- No frontend build system.

## Sanitized Sample Data

`gui.web.sample_data.sample_dashboard_api_data()` returns placeholder-only sample API responses. The examples use generic IDs such as `asset-sample-001`, `event-sample-001`, and `worker-sample`.

Use placeholders in public examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
