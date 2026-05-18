# Operator Review Queue Integration

Phase 62 persists advisory operator review drafts, review state transitions, finding status records, and review history through the existing local storage repository.

The integration is local-first and state-only. Approving, deferring, dismissing, or resolving a review changes local review state only. It does not execute actions, change configuration, install services, contact external systems, modify routers, or transmit data.

## Modules

- `core_engine.policy.review_store`
- `core_engine.policy.history`

## Persistence Model

Phase 62 reuses `LocalStorageRepository` and stores review records as typed entries in the existing findings repository. It does not add a parallel database, separate schema, or external persistence system.

Stored record types:

- `operator_review_record`
- `operator_review_transition`
- `operator_finding_status`

## Review Drafts

```python
from core_engine.policy import PersistentReviewStore, build_review_record, create_policy
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore

repository = LocalStorageRepository(SQLiteStore("operator-provided.db"))
store = PersistentReviewStore(repository)

policy = create_policy(
    policy_id="policy-sample",
    name="Sample Review Policy",
    description="Review medium and higher advisory findings.",
    severity_threshold="medium",
)

review = build_review_record(
    policy=policy,
    source_ref="finding:finding-sample",
    category="policy_review_required",
    severity="high",
    title="Sample Review",
    summary="Review this advisory finding.",
)

store.add_review(review)
```

Use operator-provided local paths only in real deployments. Public examples should use placeholders.

## Review Transitions

Supported review states remain:

- `open`
- `approved`
- `deferred`
- `dismissed`
- `resolved`

```python
store.update_status(
    review.review_id,
    "approved",
    reviewed_by="operator-sample",
    review_note="Sample approval note.",
)
```

The transition is recorded as local history. No action is executed.

## Filters

Persistent reviews can be filtered by:

- status
- severity
- category
- source reference

```python
open_reviews = store.list_reviews(status="open")
source_reviews = store.list_reviews(source_ref="finding:finding-sample")
```

## Finding Status Tracking

Finding status records let operators track advisory finding handling without changing the original finding payload:

```python
store.set_finding_status(
    "finding:finding-sample",
    "resolved",
    reviewed_by="operator-sample",
)
```

## JSON Import And Export

Review records can be exported and imported as local JSON-compatible payloads:

```python
payload = store.export_reviews()
store.import_reviews(payload)
```

Exports include only review metadata and safety flags. They do not include raw payload bytes.

## Safety Properties

Persistent review records, transition records, and finding status records include:

```json
{
  "local_only": true,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

Phase 62 is persistence and review-state wiring only. It does not add write endpoints, background collection, automatic enforcement, service installation, router changes, cloud sync, or external transport.
