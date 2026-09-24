"""Compile generic logical steps into the existing executable QueryPlan contract."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import LogicalQueryPlan, NativeQueryPlan, QueryPlan
from hunting.contracts.ontology import native_field_compatible_with_kind
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.query_intent import QueryIntentSpec, QueryPredicateSpec
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep, SemanticConstraint
from hunting.m5_adapter.allowlist import validate_time_window_format
from hunting.query_safety.c3_admission import should_invoke_c3


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


def adjacency_plan_from_operation(operation: ProviderOperation | None) -> list[dict[str, Any]]:
    """Record declared correlation/join keys. Heuristic field names are not joins."""
    if operation is None:
        return []
    plan: list[dict[str, Any]] = []
    for role, fields in dict(getattr(operation, "correlation_roles", {}) or {}).items():
        declared = tuple(dict.fromkeys(str(item).strip() for item in fields if str(item).strip()))
        if not role or not declared:
            continue
        plan.append({
            "kind": "declared_correlation",
            "role": str(role),
            "fields": list(declared),
            "proof_status": "NOT_PROOF",
        })
    return plan


def split_time_window(time_window: str, *, min_bucket_seconds: int = 300) -> tuple[str, str] | None:
    """Split one incomplete window in half. Irreducible windows return None."""
    try:
        start_dt, end_dt = validate_time_window_format(str(time_window or "").strip())
    except ValueError:
        return None
    duration = (end_dt - start_dt).total_seconds()
    if duration <= min_bucket_seconds:
        return None
    from datetime import timedelta, timezone

    mid_dt = start_dt + timedelta(seconds=duration / 2)

    def _fmt(value: Any) -> str:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"{_fmt(start_dt)}/{_fmt(mid_dt)}", f"{_fmt(mid_dt)}/{_fmt(end_dt)}"


def logical_plan_from_intent(
    intent: QueryIntentSpec,
    *,
    provider_id: str,
    scope_id: str,
    plan_id: str,
    native_partition: dict[str, Any] | None = None,
    retention_days: int | None = None,
    cursor: str = "",
    adjacency: list[dict[str, Any]] | None = None,
    pagination: str = "none",
) -> LogicalQueryPlan:
    """Project a typed QueryIntent onto a provider-neutral logical plan."""
    partition = dict(native_partition or {})
    filters = [
        {
            "field": predicate.key,
            "op": predicate.operator,
            "value": predicate.value,
            "role": predicate.role,
        }
        for predicate in intent.predicates
    ]
    # The default semantic path has no backend cost estimator.  A planner
    # placeholder must not be reported as an estimated provider cost.
    cost_status = "unknown"
    return LogicalQueryPlan(
        id=plan_id,
        requirement_id=intent.goal_id,
        provider=provider_id,
        scope=scope_id,
        data_sources=[{"source_id": intent.source_id, **partition}],
        filters=filters,
        fields=list(intent.projection_roles) or list(intent.expected_output),
        time_window=intent.time_window,
        constraints={
            "bindings": dict(intent.bindings),
            "relation": intent.relation,
            "mode": intent.mode,
        },
        limit=intent.max_rows,
        is_targeted=bool(intent.bindings),
        evidence_type=intent.relation,
        goal_id=intent.goal_id,
        mode=intent.mode,
        operation_id=intent.operation_id,
        cursor=cursor,
        cost_status=cost_status,
        partition=partition,
        retention_days=retention_days,
        cancellation_cap=intent.max_rows,
        adjacency=list(adjacency or []),
        pagination=str(pagination or "none"),
    )


def compile_operation_envelope(
    logical_plan: LogicalQueryPlan,
    *,
    operation_id: str,
    source_id: str,
    bindings: dict[str, Any] | None = None,
) -> NativeQueryPlan:
    """Compile a logical plan to a provider-operation envelope, not invented SPL."""
    start, end = ("", "")
    if "/" in str(logical_plan.time_window):
        start, end = str(logical_plan.time_window).split("/", 1)
    native_query = json.dumps(
        {
            "kind": "provider_operation",
            "operation_id": operation_id,
            "source_id": source_id,
            "bindings": dict(bindings or {}),
            "time_window": logical_plan.time_window,
            "limit": logical_plan.limit,
            "cursor": logical_plan.cursor,
        },
        sort_keys=True,
        default=str,
    )
    return NativeQueryPlan(
        id=f"nqp-{logical_plan.id}",
        logical_plan_id=logical_plan.id,
        provider=logical_plan.provider,
        native_query=native_query,
        time_range=(start, end),
        limit=logical_plan.limit,
        diagnostics={"compiler": "operation_envelope", "cost_status": logical_plan.cost_status},
    )


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
    cursor: str = "",
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
    typed_projection = _typed_projection_fields(operation, step)
    if operation is None:
        projection_roles = tuple(step.output_bindings)
        expected_output = tuple(step.output_bindings.values())
    else:
        projection_roles = typed_projection
        expected_output = typed_projection
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
        projection_roles=projection_roles,
        expected_output=expected_output,
        max_rows=limit,
        expected_cost=step.expected_cost,
        retrieval_stage=retrieval_stage,
        mode=step.mode,
        differentiating_fields=tuple(getattr(operation, "discriminator_fields", ()) or ()) if operation else (),
    )
    if operation is not None and operation.query_builder == "runtime.source_profile.v1":
        parameters["runtime_capability"] = {
            "source_id": operation.runtime_source_id,
            "schema_fingerprint": operation.schema_fingerprint,
            "proof_mode": operation.proof_mode,
            "constraint_mappings": [dict(item) for item in getattr(operation, "constraint_mappings", ())],
            "constraint_metadata": [dict(item) for item in step.constraint_metadata],
            "input_variable_ids": list(step.input_bindings.values()),
            "removed_retrieval_keys": sorted(removed_retrieval_keys or set()),
            "native_field_bindings": {
                key: list(values)
                for key, values in operation.native_field_bindings.items()
            },
            "output_value_bindings": {
                key: list(values)
                for key, values in operation.output_value_bindings.items()
            },
            "nested_field_bindings": {
                key: dict(value)
                for key, value in getattr(operation, "nested_field_bindings", {}).items()
            },
        }
    parameters["query_intent"] = intent.to_dict()
    raw_partition = getattr(scope, "native_partition", {}) or {}
    native_partition = dict(raw_partition) if isinstance(raw_partition, Mapping) and not isinstance(raw_partition, (str, bytes)) else {}
    logical_plan = logical_plan_from_intent(
        intent,
        provider_id=plan.provider_id,
        scope_id=scope.scope_id,
        plan_id=query_id or f"{plan.id}-{step.id}",
        native_partition=native_partition,
        retention_days=getattr(scope, "retention_days", None),
        cursor=cursor,
        adjacency=adjacency_plan_from_operation(operation),
        pagination=str(getattr(operation, "pagination", "none") or "none") if operation is not None else "none",
    )
    native_plan = compile_operation_envelope(
        logical_plan,
        operation_id=step.operation_id,
        source_id=source_id,
        bindings=dict(step.input_bindings),
    )
    parameters["logical_query_plan"] = logical_plan.to_dict()
    parameters["native_query_plan"] = native_plan.to_dict()
    parameters["c3_invoked"] = should_invoke_c3(admitted=True, deterministic_plan=logical_plan)
    parameters["query_replay"] = {
        "provider_id": plan.provider_id,
        "scope_id": scope.scope_id,
        "source_id": source_id,
        "operation_id": step.operation_id,
        "time_window": time_window,
        "query_id": query_id or f"{plan.id}-{step.id}",
        "native_query": native_plan.native_query,
        "job_id": native_plan.job_id,
        "cost_status": logical_plan.cost_status,
        "retention_days": logical_plan.retention_days,
        "cancellation_cap": logical_plan.cancellation_cap,
        "cursor": logical_plan.cursor,
        "pagination": logical_plan.pagination,
        "adjacency": list(logical_plan.adjacency),
    }
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


def _typed_projection_fields(operation: ProviderOperation | None, step: PlanStep) -> tuple[str, ...]:
    """Native fields declared for typed output ports; empty when no port kind exists."""
    if operation is None:
        return ()
    fields: list[str] = []
    port_kinds = dict(getattr(operation, "output_binding_entity_kinds", {}) or {})
    port_fields = dict(getattr(operation, "output_value_bindings", {}) or {})
    for binding_name in step.output_bindings:
        declared = str(port_kinds.get(binding_name) or "").strip()
        if not declared:
            continue
        for field_name in port_fields.get(binding_name, ()):
            if native_field_compatible_with_kind(str(field_name), declared):
                fields.append(str(field_name))
    return tuple(dict.fromkeys(fields))


__all__ = [
    "adjacency_plan_from_operation",
    "compile_operation_envelope",
    "logical_plan_from_intent",
    "query_plan_from_step",
    "split_time_window",
]
