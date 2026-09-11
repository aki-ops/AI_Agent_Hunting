"""Deterministic proof-aware readiness for semantic relation routes."""
from __future__ import annotations

from collections.abc import Iterable

from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import LogicalPlan, SemanticGoalGraph
from hunting.contracts.semantic_route import (
    CapabilityReadiness,
    SemanticRouteAssessment,
    SemanticRouteStatus,
)


def _constraint_keys(graph: SemanticGoalGraph, goal_id: str) -> set[str]:
    goal = next(item for item in graph.relations if item.id == goal_id)
    target = next(item for item in graph.variables if item.id == goal.object)
    keys = {item.key.casefold() for item in target.constraints}
    keys.update(
        item.qualifier.casefold()
        for item in graph.qualifiers
        if item.target_goal_id == goal_id and item.required
    )
    return keys


def _operation_gaps(
    operation: ProviderOperation,
    required_keys: set[str],
    provider_id: str,
) -> tuple[list[str], list[str]]:
    capability_gaps: list[str] = []
    proof_gaps: list[str] = []
    if operation.provider_id != provider_id:
        capability_gaps.append("provider_provenance_mismatch")
    if not operation.scope_ids:
        capability_gaps.append("provider_scope_not_declared")
    if operation.query_builder == "runtime.source_profile.v1":
        if not operation.runtime_source_id:
            capability_gaps.append("runtime_source_provenance_missing")
        if not operation.schema_fingerprint:
            capability_gaps.append("runtime_schema_provenance_missing")
    if operation.proof_mode != "relation_observable":
        proof_gaps.append("relation_not_proof_observable")
    supported = {
        str(key).strip().casefold()
        for key in operation.supported_constraints
        if str(key).strip()
    }
    proof_gaps.extend(
        f"constraint_not_proof_observable:{key}"
        for key in sorted(required_keys - supported)
    )
    return capability_gaps, proof_gaps


def assess_semantic_readiness(
    graph: SemanticGoalGraph,
    plan: LogicalPlan,
    operations: Iterable[ProviderOperation],
    *,
    prior_assessments: Iterable[SemanticRouteAssessment] = (),
) -> list[SemanticRouteAssessment]:
    """Classify each goal without equating composability with proof readiness.

    The assessment uses only declared typed contracts. Searchable constraints can
    make a route retrieval-capable, but only ``relation_observable`` plus full
    ``supported_constraints`` coverage makes it proof-capable.
    """
    operation_by_id = {item.id: item for item in operations}
    prior_by_goal = {item.goal_id: item for item in prior_assessments}
    assessments: list[SemanticRouteAssessment] = []

    for goal in graph.relations:
        prior = prior_by_goal.get(goal.id)
        if prior is not None and prior.route_exhausted:
            assessments.append(SemanticRouteAssessment(
                goal_id=goal.id,
                relation=goal.relation,
                status=SemanticRouteStatus.ROUTE_EXHAUSTED,
                execution_complete=prior.execution_complete,
                proof_complete=prior.proof_complete,
                route_exhausted=True,
                readiness=CapabilityReadiness.ROUTE_EXHAUSTED,
                attempts=list(prior.attempts),
                proof_gaps=list(prior.proof_gaps),
                capability_gaps=list(prior.capability_gaps),
                terminal_cause=prior.terminal_cause,
            ))
            continue

        step = next(
            (item for item in plan.steps if goal.id in item.advances_goal_ids),
            None,
        )
        if step is None or goal.id in plan.unresolved_goal_ids:
            assessments.append(SemanticRouteAssessment(
                goal_id=goal.id,
                relation=goal.relation,
                status=SemanticRouteStatus.CAPABILITY_GAP,
                readiness=CapabilityReadiness.CAPABILITY_GAP,
                capability_gaps=["no_typed_reachable_route"],
            ))
            continue

        required_keys = _constraint_keys(graph, goal.id)
        route_ids = (step.operation_id, *step.alternative_operation_ids)
        route_operations = [
            operation_by_id[operation_id]
            for operation_id in route_ids
            if operation_id in operation_by_id
        ]
        if not route_operations:
            assessments.append(SemanticRouteAssessment(
                goal_id=goal.id,
                relation=goal.relation,
                status=SemanticRouteStatus.CAPABILITY_GAP,
                readiness=CapabilityReadiness.CAPABILITY_GAP,
                capability_gaps=["planned_operation_contract_missing"],
            ))
            continue

        route_diagnostics = [
            (operation, *_operation_gaps(operation, required_keys, plan.provider_id))
            for operation in route_operations
        ]
        proof_ready = next(
            (
                operation
                for operation, capability_gaps, proof_gaps in route_diagnostics
                if not capability_gaps and not proof_gaps
            ),
            None,
        )
        if proof_ready is not None:
            assessments.append(SemanticRouteAssessment(
                goal_id=goal.id,
                relation=goal.relation,
                status=SemanticRouteStatus.PLANNED,
                readiness=CapabilityReadiness.PROOF_CAPABLE,
            ))
            continue

        capability_gaps = sorted({
            gap
            for _, operation_capability_gaps, _ in route_diagnostics
            for gap in operation_capability_gaps
        })
        proof_gaps = sorted({
            gap
            for _, _, operation_proof_gaps in route_diagnostics
            for gap in operation_proof_gaps
        })
        assessments.append(SemanticRouteAssessment(
            goal_id=goal.id,
            relation=goal.relation,
            status=(
                SemanticRouteStatus.CAPABILITY_GAP
                if capability_gaps and len(capability_gaps) == len(route_operations)
                else SemanticRouteStatus.PROOF_GAP
            ),
            readiness=(
                CapabilityReadiness.CAPABILITY_GAP
                if capability_gaps and len(capability_gaps) == len(route_operations)
                else CapabilityReadiness.RETRIEVAL_CAPABLE
            ),
            proof_gaps=proof_gaps,
            capability_gaps=capability_gaps,
        ))

    return assessments


__all__ = ["assess_semantic_readiness"]
