"""Negative evidence controls (C7).

Controls do not emit observations and cannot satisfy expectations.
They exist solely to license a VALID_NEGATIVE result:
  1. ScopeHealthControl(scope, window): provider reachable and ingestion lag acceptable.
  2. AnyRecordInScope(scope, entity, window): broad scan possible and trustworthy.
  3. PredicateObservabilityControl(scope, requirement, predicate): fields/values observable.

A negative result (absence of evidence) requires all three controls to pass.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hunting.contracts.cells import ProviderScope
from hunting.contracts.expectations import EvidenceRequirement, FieldPredicate
from hunting.contracts.queries import (
    ControlResult,
    Diagnostic,
    QueryIntent,
    QueryResult,
)
from hunting.m5_adapter.allowlist import validate_time_window_format


def execute_scope_health_control(
    scope: ProviderScope,
    window: str,
    as_of: datetime | None = None,
    min_ingest_lag_seconds: int = 900,
    is_reachable: bool = True,
) -> ControlResult:
    """Evaluate ScopeHealthControl: provider reachable and lag bounds respected.

    Per EXP-04: If query window ends too close to now (within min_ingest_lag),
    telemetry may still be in-flight; negative evidence cannot be licensed.
    """
    if not is_reachable:
        return ControlResult(
            query_id=f"ctrl-health-{scope.scope_id}",
            operation=QueryIntent.SCOPE_HEALTH_CONTROL,
            executed_ok=False,
            diagnostic=Diagnostic.SOURCE_UNAVAILABLE,
        )

    _, end_dt = validate_time_window_format(window)
    ref_time = as_of or datetime.now(timezone.utc)
    lag_cutoff = ref_time - timedelta(seconds=min_ingest_lag_seconds)

    if end_dt > lag_cutoff:
        # Window reaches into the unsettled ingestion lag period
        return ControlResult(
            query_id=f"ctrl-health-{scope.scope_id}",
            operation=QueryIntent.SCOPE_HEALTH_CONTROL,
            executed_ok=False,
            diagnostic=Diagnostic.SOURCE_UNHEALTHY,
        )

    return ControlResult(
        query_id=f"ctrl-health-{scope.scope_id}",
        operation=QueryIntent.SCOPE_HEALTH_CONTROL,
        executed_ok=True,
    )


def execute_any_record_in_scope(
    scope: ProviderScope,
    record_count: int,
    executed_ok: bool = True,
) -> ControlResult:
    """Evaluate AnyRecordInScope: verifies that broad telemetry is flowing in scope."""
    if not executed_ok:
        return ControlResult(
            query_id=f"ctrl-anyrec-{scope.scope_id}",
            operation=QueryIntent.ANY_RECORD_IN_SCOPE,
            executed_ok=False,
            diagnostic=Diagnostic.QUERY_FAILED,
        )

    return ControlResult(
        query_id=f"ctrl-anyrec-{scope.scope_id}",
        operation=QueryIntent.ANY_RECORD_IN_SCOPE,
        executed_ok=True,
        count=record_count,
    )


def execute_predicate_observability_control(
    scope: ProviderScope,
    requirement: EvidenceRequirement,
    predicate: FieldPredicate | None,
    observed_fields: set[str],
) -> ControlResult:
    """Evaluate PredicateObservabilityControl.

    Verifies that the native fields/values needed by the predicate are observable
    or guaranteed by the adapter in this scope.
    """
    if not predicate:
        # No predicate -> unconditional observability
        return ControlResult(
            query_id=f"ctrl-predobs-{scope.scope_id}",
            operation=QueryIntent.PREDICATE_OBSERVABILITY_CONTROL,
            executed_ok=True,
            predicate_observable=True,
        )

    # Check if predicate's target field is in the observed fields of this scope
    target_field = predicate.field.strip().lower()
    lower_observed = {f.strip().lower() for f in observed_fields}
    is_observable = target_field in lower_observed

    return ControlResult(
        query_id=f"ctrl-predobs-{scope.scope_id}",
        operation=QueryIntent.PREDICATE_OBSERVABILITY_CONTROL,
        executed_ok=True,
        predicate_observable=is_observable,
        field_present={target_field: is_observable},
        diagnostic=None if is_observable else Diagnostic.UNSUPPORTED_REQUIREMENT,
    )


def license_valid_negative(
    target_result: QueryResult,
    health_control: ControlResult,
    any_record_control: ControlResult,
    predicate_control: ControlResult,
) -> bool:
    """Determine whether an empty query outcome licenses a VALID_NEGATIVE.

    Contract:
      - Target query executed_ok is True
      - Target query complete is True
      - Target query rows is empty (len == 0)
      - ScopeHealthControl passed
      - AnyRecordInScope passed (with count > 0)
      - PredicateObservabilityControl passed (predicate_observable == True)
    """
    if not target_result.executed_ok or not target_result.complete:
        return False

    rows = target_result.rows or []
    if len(rows) > 0:
        # Non-empty rows cannot be a negative
        return False

    if not health_control.executed_ok:
        return False

    if not any_record_control.executed_ok or (any_record_control.count or 0) <= 0:
        return False

    if not predicate_control.executed_ok or predicate_control.predicate_observable is not True:
        return False

    return True


__all__ = [
    "execute_scope_health_control",
    "execute_any_record_in_scope",
    "execute_predicate_observability_control",
    "license_valid_negative",
]
