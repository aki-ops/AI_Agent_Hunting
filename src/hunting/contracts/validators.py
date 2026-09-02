"""Contract validation rules.

Enforces:
  - Malformed contracts fail validation with informative ValueError
  - Unknown semantic type does NOT fail validation (preservation rule)
  - TESTIMONY cannot become OBSERVED (epistemic integrity)
  - M2 / LLM cannot write attribution or observation status directly
"""
from __future__ import annotations

from hunting.contracts.cells import Cell, ProviderScope
from hunting.contracts.entities import AnyEntity
from hunting.contracts.expectations import Expectation
from hunting.contracts.observations import EpistemicType, Observation


def validate_provider_scope(scope: ProviderScope) -> None:
    if not isinstance(scope, ProviderScope):
        raise TypeError(f"Expected ProviderScope, got {type(scope).__name__}")
    if not scope.provider_id.strip():
        raise ValueError("ProviderScope.provider_id must not be empty")
    if not scope.native_partition:
        raise ValueError("ProviderScope.native_partition must not be empty")


def validate_cell(cell: Cell) -> None:
    if not isinstance(cell, Cell):
        raise TypeError(f"Expected Cell, got {type(cell).__name__}")
    validate_provider_scope(cell.provider_scope)
    if not cell.time_bucket.strip():
        raise ValueError("Cell.time_bucket must not be empty")


def validate_observation(obs: Observation) -> None:
    if not isinstance(obs, Observation):
        raise TypeError(f"Expected Observation, got {type(obs).__name__}")
    if not obs.id.strip():
        raise ValueError("Observation.id must not be empty")
    if not obs.timestamp.strip():
        raise ValueError("Observation.timestamp must not be empty")
    validate_provider_scope(obs.provider_scope)

    # Inviolable rule: ANY entity must never enter Observation.entities
    for entity in obs.entities:
        if isinstance(entity, AnyEntity):
            raise ValueError("Observation.entities cannot contain ANY (wildcard)")

    # Preservation rule: unknown or None semantic_type is always valid!
    # No exception is raised for semantic_type="unknown_vendor_type" or None.


def validate_expectation(exp: Expectation) -> None:
    if not isinstance(exp, Expectation):
        raise TypeError(f"Expected Expectation, got {type(exp).__name__}")
    if not exp.id.strip():
        raise ValueError("Expectation.id must not be empty")
    if not exp.time_window.strip():
        raise ValueError("Expectation.time_window must not be empty")
    if isinstance(exp.entity_ref, AnyEntity):
        raise ValueError("Expectation.entity_ref cannot be ANY (wildcard)")


def assert_epistemic_transition(from_type: EpistemicType, to_type: EpistemicType) -> None:
    """TESTIMONY can never become OBSERVED."""
    if from_type == EpistemicType.TESTIMONY and to_type == EpistemicType.OBSERVED:
        raise ValueError("Inviolable constraint: TESTIMONY cannot become OBSERVED")


def assert_m2_cannot_mutate_attribution(actor: str) -> None:
    """M2 (abduction engine) cannot write attribution or status."""
    normalized_actor = actor.strip().lower()
    if normalized_actor in {"m2", "abduction"} or "llm" in normalized_actor:
        raise PermissionError("Security guard: M2/LLM cannot write attribution or mutate observation status")


__all__ = [
    "validate_provider_scope",
    "validate_cell",
    "validate_observation",
    "validate_expectation",
    "assert_epistemic_transition",
    "assert_m2_cannot_mutate_attribution",
]
