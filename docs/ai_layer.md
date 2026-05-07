# AI Layer

Phase 9 makes the analysis layer optional and replaceable without changing the default scanner behavior.

## Default Provider

`ai_agent.scoring.get_score()` delegates to the active AI provider. The default provider is `LocalAIProvider`, which keeps the current behavior:

- Use the local ML scorer only when `use_ml` is enabled and a model is loaded.
- Fall back to deterministic heuristic scoring when ML is disabled, unavailable, or fails.
- Add `score`, `score_factors`, `risk_explanation`, and `ai_provider` to the connection payload.
- Add `ml_flag` only when a provider returns a label.

This means PortMap-AI remains stable without any external AI service.

## Provider Contract

Providers implement `AIProvider` from `ai_agent.interface`:

```python
from ai_agent.interface import AIAnalysisResult


class CustomProvider:
    name = "custom"

    def analyze(self, connection, context=None):
        return AIAnalysisResult(
            score=0.5,
            factors=["custom_signal"],
            explanation="Risk score 0.500: custom signal.",
            provider=self.name,
        )
```

Register a provider with:

```python
from ai_agent.scoring import set_ai_provider

set_ai_provider(CustomProvider())
```

Call `reset_ai_provider()` to restore the local provider.

A built-in local stub is also available for integration tests or future UI development:

```python
from ai_agent.interface import StubAIProvider
from ai_agent.scoring import set_ai_provider

set_ai_provider(StubAIProvider(score=0.25))
```

## Validation

Provider outputs are validated by `validate_analysis_result()` before they are written to scan payloads:

- Scores are coerced to floats and clamped to `0.0` through `1.0`.
- Factors are coerced to strings.
- Missing explanations are replaced with a safe default.
- Provider metadata is preserved when present.

Connection payload validation is available through `validate_connection_payload()` for future API-backed providers.

## Failure Handling

If the active provider raises an exception, `get_score()` catches it and falls back to heuristic scoring. The connection payload records:

- `ai_provider: "heuristic_fallback"`
- `score_factors` with `ai_provider_failed`
- `ai_metadata.failed_provider`
- `ai_metadata.fallback_reason`

This preserves scan continuity even when a future remote AI service is offline or returns invalid data.
