"""Compile generic logical steps into the existing executable QueryPlan contract."""
from __future__ import annotations

from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import QueryPlan
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.query_intent import QueryIntentSpec, QueryPredicateSpec
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep, SemanticConstraint


def _predicate_specs(
    step: PlanStep,
    operation: ProviderOperation | None,
    removed_retrieval_keys: set[str] | None = None,
) -> tuple[QueryPredicateSpec, ...]:
    supported = {
        str(key).strip().casefold() for key in getattr(operation, "supported_constraints", ())
    }
    searchable = {
        str(key).strip().casefold() for key in getattr(operation, "searchable_constraints", ())
    }
    metadata_by_key = {
        str(item.get("key", "")).strip().casefold(): dict(item)
        for item in step.constraint_metadata
    }
    removed_retrieval_keys = {
        str(key).strip().casefold()
        for key in (removed_retrieval_keys or set())
        if str(key).strip()
    }
    predicates: list[QueryPredicateSpec] = []
    for index, raw in enumerate(step.constraints):
        constraint = SemanticConstraint.from_raw(raw, path=f"{step.id}.constraints[{index}]")
        metadata = metadata_by_key.get(constraint.key, {})
        # A provider may use a searchable-only constraint to retrieve rows, but
        # the original semantic restriction remains a proof obligation.  The
        # role here describes this query predicate, not claim satisfaction.
        role = "proof" if constraint.key in supported else "retrieval" if constraint.key in searchable else "proof"
        if role == "retrieval" and constraint.key in removed_retrieval_keys:
            continue
        predicates.append(QueryPredicateSpec(
            key=constraint.key,
            operator=constraint.operator,
            value=constraint.value,
            role=role,
            provenance=str(metadata.get("provenance", "semantic_graph")),
            trust_class=str(metadata.get("trust_class", "request_grounded")),
        ))
    return tuple(predicates)


def query_plan_from_step(
    plan: LogicalPlan,
    step: PlanStep,
    scope: ProviderScope,
    time_window: str,
    *,
    query_id: str | None = None,
    limit: int = 100,
    operation: ProviderOperation | None = None,
    retrieval_stage: str = "narrow",
    removed_retrieval_keys: set[str] | None = None,
) -> QueryPlan:
    """Create an executable provider operation envelope without native syntax."""
    parameters: dict[str, Any] = {
        "window": time_window,
        "input_bindings": dict(step.input_bindings),
        "output_bindings": dict(step.output_bindings),
        "advances_goal_ids": list(step.advances_goal_ids),
        "depends_on": list(step.depends_on),
        "logical_plan_id": plan.id,
        "relation": step.relation,
        "constraints": list(step.constraints),
        "constraint_metadata": [dict(item) for item in step.constraint_metadata],
        "constraint_retrieval_terms": [
            {"key": key, "term": term}
            for key, term in step.constraint_retrieval_terms
        ],
        "constraint_contract": "provider-declared",
        "retrieval_stage": retrieval_stage,
        "removed_retrieval_keys": sorted(removed_retrieval_keys or set()),
    }
    source_id = (
        operation.runtime_source_id
        if operation is not None and operation.runtime_source_id
        else scope.scope_id
    )
    intent = QueryIntentSpec(
        goal_id=step.advances_goal_ids[0] if step.advances_goal_ids else step.id,
        operation_id=step.operation_id,
        source_id=source_id,
        relation=step.relation,
        bindings=dict(step.input_bindings),
        binding_metadata={
            role: {
                "variable_id": variable_id,
                "provenance": "logical_plan",
                "trust_class": "runtime_binding_required",
            }
            for role, variable_id in step.input_bindings.items()
        },
        predicates=_predicate_specs(step, operation, removed_retrieval_keys),
        time_window=time_window,
        projection_roles=tuple(step.output_bindings),
        expected_output=tuple(step.output_bindings.values()),
        max_rows=limit,
        expected_cost=step.expected_cost,
        retrieval_stage=retrieval_stage,
    )
    if operation is not None and operation.query_builder == "runtime.source_profile.v1":
        parameters["runtime_capability"] = {
            "source_id": operation.runtime_source_id,
            "schema_fingerprint": operation.schema_fingerprint,
            "proof_mode": operation.proof_mode,
            "native_field_bindings": {
                key: list(values)
                for key, values in operation.native_field_bindings.items()
            },
            "output_value_bindings": {
                key: list(values)
                for key, values in operation.output_value_bindings.items()
            },
        }
    parameters["query_intent"] = intent.to_dict()
    return QueryPlan(
        id=query_id or f"{plan.id}-{step.id}",
        requirement_id=step.advances_goal_ids[0] if step.advances_goal_ids else step.id,
        provider_id=plan.provider_id,
        scope_id=scope.scope_id,
        operation_id=step.operation_id,
        parameters=parameters,
        estimated_cost=step.expected_cost,
        completeness_contract="provider-declared",
        is_targeted=bool(step.input_bindings),
    )


__all__ = ["query_plan_from_step"]
