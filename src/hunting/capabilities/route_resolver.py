"""Build goal-scoped routes from typed provider capabilities.

This is a retrieval/admission layer.  It never turns a route into incident
proof.  Relation wording is used as a retrieval feature only; once a route is
created, the planner keys it by ``goal_id`` and the operation's declared
typed contract is what makes it executable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from hunting.contracts.candidate_route import (
    CandidateRoute,
    RouteAdmission,
    RouteClass,
    RouteMode,
)
from hunting.contracts.capability_query import CapabilityQuery, build_capability_queries
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import SemanticGoalGraph


def _tokens(value: Any) -> set[str]:
    return {
        token for token in re.findall(r"[A-Za-z0-9]+", str(value or "").casefold())
        if len(token) > 1
    }


@dataclass(frozen=True)
class RouteResolution:
    routes_by_goal: dict[str, tuple[CandidateRoute, ...]]
    unexamined_goal_ids: tuple[str, ...] = ()
    audit: tuple[dict[str, Any], ...] = ()


class CapabilityRouteResolver:
    """Resolve provider operations to semantic goals without proof shortcuts."""

    _endpoint_types = {"device", "endpoint", "host", "workstation", "computer"}
    _artifact_types = {"file", "artifact", "document", "file_artifact"}

    @classmethod
    def _type_compatible(cls, left: str, right: str) -> bool:
        left, right = str(left or "").casefold(), str(right or "").casefold()
        if left == "any" or right == "any" or left == right:
            return True
        if left in cls._endpoint_types and right in cls._endpoint_types:
            return True
        return left in cls._artifact_types and right in cls._artifact_types

    @staticmethod
    def _answer_compatible(
        operation: ProviderOperation,
        answer_role: str,
        object_type: str = "",
    ) -> bool:
        wanted = _tokens(answer_role)
        if not wanted:
            return True
        # An answer contract may ask for the entity itself (``process``,
        # ``file``, ``domain``), not a native field named after that entity.
        # The declared output type is then the relevant typed evidence.
        if object_type and any(
            CapabilityRouteResolver._type_compatible(object_type, kind)
            and bool(wanted & _tokens(kind))
            for kind in operation.output_entity_kinds
        ):
            return True
        declared: set[str] = set(operation.output_roles) | set(operation.output_fields)
        declared.update(
            str(binding.get("key", ""))
            for binding in getattr(operation, "nested_field_bindings", {}).values()
            if isinstance(binding, dict)
        )
        if not declared:
            return True
        return bool(wanted & set().union(*(_tokens(item) for item in declared)))

    @staticmethod
    def _operation_terms(operation: ProviderOperation) -> set[str]:
        values = (
            operation.semantic_intents,
            operation.input_entity_kinds,
            operation.output_entity_kinds,
            operation.input_roles,
            operation.output_roles,
            operation.output_fields,
            operation.output_fact_kinds,
            operation.guaranteed_relations,
        )
        return set().union(*(_tokens(item) for group in values for item in group))

    def resolve(
        self,
        graph: SemanticGoalGraph,
        operations: Iterable[ProviderOperation],
        provider_id: str,
    ) -> RouteResolution:
        queries = {item.goal_id: item for item in build_capability_queries(graph)}
        routes: dict[str, tuple[CandidateRoute, ...]] = {}
        unexamined: list[str] = []
        audit: list[dict[str, Any]] = []
        for goal in graph.relations:
            query: CapabilityQuery | None = queries.get(goal.id)
            if query is None:
                unexamined.append(goal.id)
                continue
            candidates: list[CandidateRoute] = []
            query_terms = _tokens(query.relation_text) | _tokens(query.canonical_relation)
            for operation in operations:
                if operation.provider_id != provider_id or getattr(operation, "legacy_alias", False):
                    continue
                if operation.route_goal_ids and goal.id not in operation.route_goal_ids:
                    continue
                if operation.input_entity_kinds and not self._type_compatible(
                    query.subject_type, operation.input_entity_kinds[0]
                ):
                    continue
                if operation.output_entity_kinds and not any(
                    self._type_compatible(query.object_type, kind)
                    for kind in operation.output_entity_kinds
                ):
                    continue
                if not self._answer_compatible(operation, query.answer_role, query.object_type):
                    continue
                op_terms = self._operation_terms(operation)
                overlap = query_terms & op_terms
                # An explicitly goal-bound runtime route is already admitted
                # by its capability probe and does not need relation overlap.
                explicitly_bound = goal.id in operation.route_goal_ids
                if not explicitly_bound and not overlap and not operation.semantic_intents:
                    continue
                score = float(len(overlap)) + (10.0 if explicitly_bound else 0.0)
                route_class = RouteClass(str(getattr(operation, "route_class", "EXECUTABLE")))
                mode = RouteMode(str(getattr(operation, "route_mode", "EXPLORE")))
                if route_class != RouteClass.EXECUTABLE:
                    mode = RouteMode.EXPLORE
                candidates.append(CandidateRoute(
                    route_id=f"route:{goal.id}:{operation.id}",
                    goal_id=goal.id,
                    provider_id=provider_id,
                    source_id=(operation.runtime_source_id or operation.id),
                    operation_id=operation.id,
                    subject_type=query.subject_type,
                    object_type=query.object_type,
                    input_role_bindings=dict(operation.native_field_bindings),
                    output_role_bindings=dict(operation.output_value_bindings),
                    supported_constraint_keys=tuple(operation.supported_constraints),
                    mode=mode,
                    route_class=route_class,
                    discovery_provenance=tuple(getattr(operation, "discovery_provenance", ())) or ("F1_TYPED_OPERATION",),
                    admission_status=RouteAdmission.ADMITTED if route_class == RouteClass.EXECUTABLE else RouteAdmission.PROPOSED,
                    proof_contract_id=None,
                    schema_fingerprint=operation.schema_fingerprint,
                    score=score,
                ))
            candidates.sort(key=lambda item: (-item.score, item.operation_id or ""))
            routes[goal.id] = tuple(candidates)
            if not candidates:
                unexamined.append(goal.id)
            audit.append({
                "goal_id": goal.id,
                "provider_id": provider_id,
                "candidate_count": len(candidates),
                "route_ids": [route.route_id for route in candidates],
                "goal_scoped": True,
                "relation_used_as_proof": False,
            })
        return RouteResolution(routes, tuple(unexamined), tuple(audit))


__all__ = ["CapabilityRouteResolver", "RouteResolution"]
