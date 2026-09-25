"""Build goal-scoped routes from typed provider capabilities.

This is a retrieval/admission layer.  It never turns a route into incident
proof.  Relation wording is used as a retrieval feature only; once a route is
created, the planner keys it by ``goal_id`` and the operation's declared
typed contract is what makes it executable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from hunting.capabilities.admission import AdmissionResult, CapabilityAdmissionGate
from hunting.capabilities.semantic_index import SemanticCapabilityIndex
from hunting.contracts.candidate_route import (
    CandidateRoute,
    RouteAdmission,
    RouteClass,
    RouteMode,
)
from hunting.contracts.capability_query import CapabilityQuery, build_capability_queries
from hunting.contracts.ontology import types_are_compatible
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import SemanticGoalGraph


@dataclass(frozen=True)
class RouteResolution:
    routes_by_goal: dict[str, tuple[CandidateRoute, ...]]
    unexamined_goal_ids: tuple[str, ...] = ()
    audit: tuple[dict[str, Any], ...] = ()


class CapabilityRouteResolver:
    """Resolve provider operations to semantic goals without proof shortcuts."""

    def resolve(
        self,
        graph: SemanticGoalGraph,
        operations: Iterable[ProviderOperation],
        provider_id: str,
        *,
        profiles: Iterable[Any] = (),
        retrievals: dict[str, Any] | None = None,
        k: int = 8,
        content_registry: Any | None = None,
    ) -> RouteResolution:
        queries = {item.goal_id: item for item in build_capability_queries(graph)}
        operations = tuple(
            operation for operation in operations
            if operation.provider_id == provider_id and not getattr(operation, "legacy_alias", False)
        )
        if content_registry is not None:
            from hunting.registry.package_f0 import merge_f0_operations
            operations = merge_f0_operations(operations, content_registry, provider_id)
        profile_list = tuple(profiles)
        profiles_by_source = {
            str(getattr(profile, "source_id", "")): profile
            for profile in profile_list
            if getattr(profile, "source_id", None)
        }
        index = SemanticCapabilityIndex(profile_list, operations=operations)
        routes: dict[str, tuple[CandidateRoute, ...]] = {}
        unexamined: list[str] = []
        audit: list[dict[str, Any]] = []
        admission_gate = CapabilityAdmissionGate()
        for goal in graph.relations:
            query: CapabilityQuery | None = queries.get(goal.id)
            if query is None:
                unexamined.append(goal.id)
                continue
            retrieval = (retrievals or {}).get(goal.id)
            if retrieval is None:
                retrieval = index.retrieve(query, k=k)
            relevant_operation_ids = {
                str(hit.operation_id)
                for hit in getattr(retrieval, "operation_hits", ()) or ()
                if getattr(hit, "relevant", False) and getattr(hit, "operation_id", None)
            }
            f0_operation_ids = {
                str(hit.operation_id)
                for hit in getattr(retrieval, "operation_hits", ()) or ()
                if getattr(hit, "frontier_stage", "") == "F0_CERTIFIED" and getattr(hit, "operation_id", None)
            }
            hit_by_operation = {
                str(hit.operation_id): hit
                for hit in getattr(retrieval, "operation_hits", ()) or ()
                if getattr(hit, "operation_id", None)
            }
            candidates: list[CandidateRoute] = []
            for operation in operations:
                if operation.route_goal_ids and goal.id not in operation.route_goal_ids:
                    continue
                input_kinds = tuple(operation.input_entity_kinds or ())
                output_kinds = tuple(operation.output_entity_kinds or ())
                if input_kinds and not any(
                    types_are_compatible(query.subject_type, kind) for kind in input_kinds
                ):
                    continue
                if output_kinds and not any(
                    types_are_compatible(query.object_type, kind) for kind in output_kinds
                ):
                    continue
                explicitly_bound = goal.id in operation.route_goal_ids
                package_f0 = "F0_PACKAGE" in tuple(getattr(operation, "discovery_provenance", ()) or ())
                f0_hit = operation.id in f0_operation_ids or package_f0
                f1_hit = operation.id in relevant_operation_ids
                if not explicitly_bound and not f0_hit and not f1_hit:
                    continue
                hit = hit_by_operation.get(operation.id)
                if explicitly_bound:
                    admission = admission_gate.evaluate_operation(
                        operation,
                        {
                            "subject_type": query.subject_type,
                            "object_type": query.object_type,
                            "answer_role": query.answer_role,
                            "goal_id": goal.id,
                            "allow_scope_explore": True,
                        },
                    )
                    if not admission.admitted and "missing_native_mapping" in admission.reasons:
                        admission = AdmissionResult(True, ())
                    if not admission.admitted and admission.reasons and all(
                        r == "missing_native_mapping" or r.startswith("answer_role_not_reachable")
                        for r in admission.reasons
                    ):
                        # Explicitly bound runtime route: F1 + probe already
                        # validated the source for this goal. The final answer
                        # slot (e.g. file_name from a message payload) is
                        # extracted downstream, not a census field requirement.
                        admission = AdmissionResult(True, ())
                else:
                    admission = admission_gate.evaluate_operation(
                        operation,
                        {
                            "subject_type": query.subject_type,
                            "object_type": query.object_type,
                            "answer_role": query.answer_role,
                            "goal_id": goal.id,
                        },
                        profiles_by_source.get(str(getattr(operation, "runtime_source_id", "") or "")),
                    )
                requested_class = RouteClass(str(getattr(operation, "route_class", "EXECUTABLE")))
                if not explicitly_bound and getattr(hit, "route_class", None):
                    requested_class = RouteClass(str(hit.route_class))
                if requested_class == RouteClass.EXECUTABLE and not admission.admitted:
                    route_class = RouteClass.MAPPING_REQUIRED
                    admission_status = RouteAdmission.REJECTED
                    rejection = admission.reasons
                elif requested_class != RouteClass.EXECUTABLE:
                    route_class = requested_class
                    admission_status = RouteAdmission.PROPOSED
                    rejection = ()
                else:
                    route_class = RouteClass.EXECUTABLE
                    admission_status = RouteAdmission.ADMITTED
                    rejection = ()
                mode = RouteMode(str(getattr(operation, "route_mode", "EXPLORE")))
                if route_class != RouteClass.EXECUTABLE:
                    mode = RouteMode.EXPLORE
                proof_contract_id = getattr(operation, "proof_contract_id", None)
                if mode == RouteMode.PROVE and not proof_contract_id:
                    mode = RouteMode.EXPLORE
                if mode == RouteMode.DISCRIMINATE and not tuple(
                    getattr(operation, "discriminator_fields", ()) or ()
                ):
                    mode = RouteMode.EXPLORE
                provenance = tuple(getattr(operation, "discovery_provenance", ()) or ())
                if not provenance:
                    if package_f0:
                        provenance = tuple(getattr(operation, "discovery_provenance", ()) or ("F0_PACKAGE",))
                    elif f0_hit:
                        provenance = ("F0_EXACT_OPERATION",)
                    elif f1_hit:
                        provenance = ("F1_TYPED_OPERATION",)
                    else:
                        provenance = ("GOAL_BOUND_RUNTIME",)
                frontier_stage = "F0_CERTIFIED" if f0_hit or package_f0 else getattr(hit, "frontier_stage", "F1_METADATA")
                score = float(getattr(hit, "score", 0.0) or 0.0) + (10.0 if explicitly_bound else 0.0)
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
                    frontier_stage=str(frontier_stage or "F1_METADATA"),
                    route_class=route_class,
                    discovery_provenance=provenance,
                    admission_status=admission_status,
                    rejection_reasons=rejection,
                    proof_contract_id=proof_contract_id if mode == RouteMode.PROVE else None,
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
                "f0_hits": sorted(f0_operation_ids),
                "f1_hits": sorted(relevant_operation_ids),
            })
        return RouteResolution(routes, tuple(unexamined), tuple(audit))


__all__ = ["CapabilityRouteResolver", "RouteResolution"]
