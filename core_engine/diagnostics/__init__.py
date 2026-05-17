"""Local diagnostic helpers for bounded fixture validation."""

from core_engine.diagnostics.fixture_mutation import mutate_fixture
from core_engine.diagnostics.schema_validation import (
    SchemaValidationError,
    classify_exception,
    validate_fixture,
    validate_schema_definition,
)

__all__ = [
    "SchemaValidationError",
    "classify_exception",
    "mutate_fixture",
    "validate_fixture",
    "validate_schema_definition",
]
