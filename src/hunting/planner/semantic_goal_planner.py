"""Provider-neutral composition of semantic goals into logical plan steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from hunting.contracts.ontology import canonicalize_relation, types_are_compatible
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep, ProofMethod, SemanticGoalGraph
from hunting.contracts.transforms import is_literal_telemetry_token

_ROUTE_CLASS_RANK = {"EXECUTABLE": 0, "MAPPING_REQUIRED": 1, "DISCOVERY_ONLY": 2}


@dataclass(frozen=True)
class PlannerDiagnostic:
    goal_id: str
    reason: str


class SemanticGoalPlanner:
    """Compose operations using declared typed contracts.

    The planner deliberately does not inspect operation IDs, native fields or
    keywords.  An adapter must declare the relation it guarantees; otherwise
    the operation cannot be used to claim that a semantic goal was verified.
    """

    def __init__(self, operations: Iterable[ProviderOperation], provider_id: str) -> None:
        self.operations = tuple(operations)
        self.provider_id = provider_id

    @staticmethod
    def _route_mode(
        operation: ProviderOperation,
        goal_id: str,
        candidate_routes: dict[str, tuple[Any, ...]] | None,
    ) -> str:
        """Return mode from the admitted route, never from relation prose.

        A route is the authority for production plans.  The operation's
        declaration is retained as a compatibility fallback for typed plans
        that predate CandidateRoute.
        """
        for route in (candidate_routes or {}).get(goal_id, ()):
            if getattr(route, "operation_id", None) != operation.id:
                continue
            if not bool(getattr(route, "executable", False)):
                continue
            mode = getattr(getattr(route, "mode", None), "value", getattr(route, "mode", None))
            if mode:
                return str(mode).upper()
        return str(getattr(operation, "route_mode", "EXPLORE") or "EXPLORE").upper()

    @staticmethod
    def _has_native_mapping(operation: ProviderOperation) -> bool:
        return bool(operation.native_field_bindings or operation.output_value_bindings)

    @classmethod
    def _route_rank_key(
        cls,
        operation: ProviderOperation,
        goal_id: str,
        candidate_routes: dict[str, tuple[Any, ...]] | None,
        goal_constraints: list[str],
    ) -> tuple[Any, ...]:
        route = None
        for item in (candidate_routes or {}).get(goal_id, ()):
            if getattr(item, "operation_id", None) == operation.id:
                route = item
                break
        route_class = str(
            getattr(getattr(route, "route_class", None), "value", None)
            or getattr(route, "route_class", None)
            or operation.route_class
            or "DISCOVERY_ONLY"
        )
        class_rank = _ROUTE_CLASS_RANK.get(route_class, 2)
        stage = str(getattr(route, "frontier_stage", "") or "")
        provenance = ",".join(getattr(operation, "discovery_provenance", ()) or ())
        text = f"{stage} {provenance}".upper()
        if "F0" in text:
            frontier = 0
        elif "F1" in text:
            frontier = 1
        else:
            frontier = 2
        mapping_rank = 0 if cls._has_native_mapping(operation) else 1
        if operation.input_entity_kinds and operation.output_entity_kinds:
            narrow = (0, len(operation.input_entity_kinds) + len(operation.output_entity_kinds))
        else:
            narrow = (1, 10**6)
        coverage = -sum(
            1 for constraint in goal_constraints
            if cls._constraint_key(constraint) in {
                str(key).strip().casefold()
                for key in operation.supported_constraints
            }
        )
        cost = operation.expected_cost if operation.expected_cost is not None else 1
        return (class_rank, frontier, mapping_rank, narrow[0], narrow[1], coverage, cost, operation.id)

    def compose(
        self,
        graph: SemanticGoalGraph,
        *,
        plan_id: str = "logical-plan",
        candidate_routes: dict[str, tuple[Any, ...]] | None = None,
        legacy_relation_matching: bool = True,
    ) -> LogicalPlan:
        """Compose a plan from goal-scoped routes when supplied.

        The route map is the production authority for capability matching.
        The relation-equality branch is retained only for callers that have
        not migrated to route resolution yet; this makes the migration
        observable instead of silently changing old fixture semantics.
        """
        known = {variable.id for variable in graph.variables if variable.value is not None or bool(variable.constraints)}
        variable_types = {variable.id: variable.entity_type for variable in graph.variables}
        remaining = list(graph.relations)
        steps: list[PlanStep] = []
        diagnostics: list[PlannerDiagnostic] = []
        step_for_variable: dict[str, str] = {}
        step_for_goal: dict[str, str] = {}
        proof_methods: list[ProofMethod] = []
        selected_method_ids: dict[str, str] = {}
        route_map = candidate_routes or {}

        progress = True
        while remaining and progress:
            progress = False
            for goal in list(remaining):
                remaining_goal_ids = {r.id for r in remaining}
                if goal.dependencies:
                    if goal.dependency_operator in {"AND", "GATE"}:
                        if any(dep in remaining_goal_ids for dep in goal.dependencies):
                            continue
                    elif goal.dependency_operator == "OR":
                        if all(dep in remaining_goal_ids for dep in goal.dependencies):
                            continue

                subject = next(variable for variable in graph.variables if variable.id == goal.subject)
                target = next(variable for variable in graph.variables if variable.id == goal.object)
                # A variable's restrictions belong to grounding that
                # variable.  Do not push a host/device restriction into a
                # downstream host->file (or host->domain) operation: that
                # turns an otherwise valid graph into a false capability
                # failure and couples unrelated steps.  Relation qualifiers
                # remain scoped to this relation.
                relevant_constraint_vars = [target]
                if subject.id not in step_for_variable and (subject.value is None or bool(subject.constraints)):
                    relevant_constraint_vars.append(subject)

                goal_constraints: list[str] = []
                retrieval_terms_list: list[tuple[str, str]] = []
                goal_constraint_metadata: list[dict[str, Any]] = []

                for c_var in relevant_constraint_vars:
                    goal_constraints.extend([item.text() for item in c_var.constraints])
                    for item in c_var.constraints:
                        if is_literal_telemetry_token(item.value) and c_var.value_origin == "request":
                            retrieval_terms_list.append((item.key, str(item.value).strip()))
                        goal_constraint_metadata.append({
                            "key": item.key,
                            "operator": item.operator,
                            "value": item.value,
                            "variable_id": c_var.id,
                            "provenance": "semantic_graph",
                            "trust_class": (
                                "request_grounded"
                                if c_var.value_origin == "request"
                                else "compiler_proposed"
                            ),
                        })
                for qualifier in graph.qualifiers:
                    if qualifier.target_goal_id != goal.id or not qualifier.required:
                        continue
                    goal_constraints.append(
                        qualifier.qualifier if qualifier.expected_value is None
                        else f"{qualifier.qualifier}={qualifier.value_text()}"
                    )
                    goal_constraint_metadata.append({
                        "key": qualifier.qualifier,
                        "operator": "exists" if qualifier.expected_value is None else "equals",
                        "value": qualifier.expected_value,
                        "provenance": f"semantic_qualifier:{qualifier.id}",
                        "trust_class": "compiler_proposed",
                    })

                seen_terms: set[tuple[str, str]] = set()
                deduped_retrieval: list[tuple[str, str]] = []
                for entry in retrieval_terms_list:
                    if entry not in seen_terms:
                        seen_terms.add(entry)
                        deduped_retrieval.append(entry)
                goal_retrieval_terms = tuple(deduped_retrieval)
                execution_subject_id = subject.id
                prerequisite_goal_ids = tuple(
                    relation.id for relation in graph.relations
                    if relation.object == goal.subject and relation.id != goal.id and relation.required
                )
                if goal.dependencies and goal.dependency_operator in {"AND", "GATE"}:
                    prerequisite_goal_ids = tuple(dict.fromkeys(prerequisite_goal_ids + goal.dependencies))
                if goal.id in route_map:
                    route_operation_ids = {
                        str(getattr(route, "operation_id", ""))
                        for route in route_map.get(goal.id, ())
                        if bool(getattr(route, "executable", False))
                    }
                    candidates = list({operation.id: operation for operation in self.operations
                        if operation.id in route_operation_ids
                        and operation.provider_id == self.provider_id
                        and (
                            not operation.output_entity_kinds
                            or any(
                                types_are_compatible(target.entity_type, kind)
                                for kind in operation.output_entity_kinds
                            )
                        )
                    }.values())
                elif legacy_relation_matching:
                    candidates = list({operation.id: operation for operation in self.operations
                        if (
                            goal.relation.casefold() in {value.casefold() for value in operation.guaranteed_relations}
                            or canonicalize_relation(goal.relation) in {canonicalize_relation(value) for value in operation.guaranteed_relations}
                        )
                        and operation.provider_id == self.provider_id
                        and operation.output_entity_kinds
                        and any(
                            types_are_compatible(target.entity_type, kind)
                            for kind in operation.output_entity_kinds
                        )
                    }.values())
                else:
                    candidates = []
                canonical_candidates = [
                    operation for operation in candidates
                    if not getattr(operation, "legacy_alias", False)
                ]
                if canonical_candidates:
                    candidates = canonical_candidates
                for candidate_index, candidate in enumerate(candidates, start=1):
                    # A proof method must be executable for this relation's
                    # subject.  Previously every operation with the right
                    # output/relation was printed as an alternative, even
                    # when it required a different input type (for example a
                    # host->IP operation listed for an account->host goal).
                    # Such entries were not real routes and made the report
                    # claim options the executor could never use.
                    if candidate.input_entity_kinds and not any(
                        types_are_compatible(subject.entity_type, kind)
                        for kind in candidate.input_entity_kinds
                    ):
                        continue
                    if goal.dependency_operator == "OR" and goal.dependencies:
                        for dep_index, dep in enumerate(goal.dependencies, start=1):
                            branch_prereqs = tuple(dict.fromkeys(prerequisite_goal_ids + (dep,)))
                            method_id = f"method-{goal.id}-{candidate_index}-or-{dep_index}"
                            if not any(method.id == method_id for method in proof_methods):
                                proof_methods.append(ProofMethod(
                                    id=method_id,
                                    goal_id=goal.id,
                                    prerequisite_goal_ids=branch_prereqs,
                                    operation_ids=(candidate.id,),
                                    expected_cost=candidate.expected_cost or 1,
                                    description=f"{candidate.id} declares relation {goal.relation} (OR-branch {dep})",
                                ))
                    else:
                        method_id = f"method-{goal.id}-{candidate_index}"
                        if not any(method.id == method_id for method in proof_methods):
                            proof_methods.append(ProofMethod(
                                id=method_id,
                                goal_id=goal.id,
                                prerequisite_goal_ids=prerequisite_goal_ids,
                                operation_ids=(candidate.id,),
                                expected_cost=candidate.expected_cost or 1,
                                description=f"{candidate.id} declares relation {goal.relation}",
                            ))
                ready = [
                    operation for operation in candidates
                    if operation.input_entity_kinds
                    and any(
                        types_are_compatible(subject.entity_type, kind)
                        for kind in operation.input_entity_kinds
                    )
                    and subject.id in known
                ]
                if not ready:
                    # Find a typed capability path to the operation's input
                    # entity.  This creates intermediate variables instead of
                    # assuming the user's subject is already a host/account.
                    path = self._find_typed_path(
                        subject.entity_type,
                        candidates,
                        preferred_relations={goal.relation.casefold()},
                    )
                    if path is None:
                        continue
                    previous_variable = subject.id
                    previous_type = subject.entity_type
                    for path_index, operation in enumerate(path):
                        output_type = next(
                            (kind for kind in operation.output_entity_kinds if kind in operation.output_entity_kinds),
                            "entity",
                        )
                        intermediate = f"__intermediate_{len(steps) + 1}"
                        step_id = f"step-{len(steps) + 1}"
                        steps.append(PlanStep(
                            id=step_id,
                            operation_id=operation.id,
                            input_bindings={"subject": previous_variable},
                            output_bindings={"object": intermediate},
                            advances_goal_ids=(goal.id,),
                            depends_on=tuple(
                                dependency for variable_id, dependency in step_for_variable.items()
                                if variable_id == previous_variable
                            ),
                            expected_cost=operation.expected_cost or 1,
                            constraints=(),
                            constraint_retrieval_terms=(),
                            relation=(operation.guaranteed_relations[0] if operation.guaranteed_relations else "observed"),
                            mode=self._route_mode(operation, goal.id, route_map),
                        ))
                        variable_types[intermediate] = output_type
                        known.add(intermediate)
                        step_for_variable[intermediate] = step_id
                        previous_variable = intermediate
                        previous_type = output_type
                    ready = [operation for operation in candidates if any(
                        types_are_compatible(previous_type, kind)
                        for kind in operation.input_entity_kinds
                    )]
                    if not ready:
                        continue
                    execution_subject_id = previous_variable
                # Prefer a cheaper *and narrower* capability.  A generic
                # file scan accepting host/account/process/file must not win
                # over a declared host-to-file operation merely because it
                # appears first in a provider descriptor.
                operation = min(
                    ready,
                    key=lambda item: self._route_rank_key(
                        item, goal.id, route_map, goal_constraints,
                    ),
                )
                selected_method = next(
                    (
                        method for method in proof_methods
                        if method.goal_id == goal.id
                        and method.operation_ids == (operation.id,)
                    ),
                    None,
                )
                if selected_method is None:
                    # The selected operation became reachable through a
                    # typed intermediate path.  Publish that complete route
                    # instead of pointing at a method whose input type does
                    # not match the relation subject.
                    route_operation_ids = tuple(
                        [
                            step.operation_id
                            for step in steps
                            if step.id in {
                                dependency
                                for variable_id, dependency in step_for_variable.items()
                                if variable_id == execution_subject_id
                            }
                        ]
                        + [operation.id]
                    )
                    selected_method = ProofMethod(
                        id=f"method-{goal.id}-{len(proof_methods) + 1}",
                        goal_id=goal.id,
                        prerequisite_goal_ids=prerequisite_goal_ids,
                        operation_ids=route_operation_ids,
                        expected_cost=operation.expected_cost or 1,
                        description=(
                            f"typed route via {', '.join(route_operation_ids)} "
                            f"declares relation {goal.relation}"
                        ),
                    )
                    proof_methods.append(selected_method)
                selected_method_ids[goal.id] = selected_method.id
                step_id = f"step-{len(steps) + 1}"
                var_dependencies = tuple(
                    dependency for variable_id, dependency in step_for_variable.items()
                    if variable_id == execution_subject_id
                )
                declared_step_deps: list[str] = []
                if goal.dependencies:
                    if goal.dependency_operator in {"AND", "GATE"}:
                        for dep in goal.dependencies:
                            if dep in step_for_goal:
                                declared_step_deps.append(step_for_goal[dep])
                    elif goal.dependency_operator == "OR":
                        for dep in goal.dependencies:
                            if dep in step_for_goal:
                                declared_step_deps.append(step_for_goal[dep])
                                break
                step_dependencies = tuple(dict.fromkeys(list(var_dependencies) + declared_step_deps))
                steps.append(
                    PlanStep(
                        id=step_id,
                        operation_id=operation.id,
                        input_bindings={"subject": execution_subject_id},
                        output_bindings={"object": target.id},
                        advances_goal_ids=(goal.id,),
                        depends_on=step_dependencies,
                        expected_cost=operation.expected_cost or 1,
                        constraints=tuple(dict.fromkeys(goal_constraints)),
                        constraint_retrieval_terms=goal_retrieval_terms,
                        relation=goal.relation,
                        constraint_metadata=tuple(goal_constraint_metadata),
                        alternative_operation_ids=tuple(
                            candidate.id for candidate in ready if candidate.id != operation.id
                        ),
                        dependency_operator=goal.dependency_operator,
                        gate_condition=goal.gate_condition,
                        mode=self._route_mode(operation, goal.id, route_map),
                    )
                )
                step_for_goal[goal.id] = step_id
                step_for_variable[target.id] = step_id
                known.add(target.id)
                remaining.remove(goal)
                progress = True

        unresolved_reasons: dict[str, str] = {}
        for goal in remaining:
            has_executable = any(
                bool(getattr(route, "executable", False))
                for route in route_map.get(goal.id, ())
            )
            reason = "blocked_on_dependency" if has_executable else "no_typed_reachable_route"
            unresolved_reasons[goal.id] = reason
            diagnostics.append(PlannerDiagnostic(goal.id, reason))

        plan = LogicalPlan(
            id=plan_id,
            goal_graph_id=graph.id,
            provider_id=self.provider_id,
            steps=steps,
            unresolved_goal_ids=[diagnostic.goal_id for diagnostic in diagnostics],
            proof_methods=proof_methods,
            selected_method_ids=selected_method_ids,
            graph_revision=getattr(graph, "graph_revision", "G0"),
            unresolved_reasons=unresolved_reasons,
        )
        # Keep diagnostics auditable without adding provider-specific state to
        # the contract itself.  The executor/report layer can serialize them.
        return plan

    @staticmethod
    def _constraint_key(raw: str) -> str:
        return str(raw).split("=", 1)[0].split(":", 1)[0].strip().casefold()

    def _find_typed_path(
        self,
        start_type: str,
        candidates: list[ProviderOperation],
        preferred_relations: set[str] | None = None,
    ) -> list[ProviderOperation] | None:
        """Find a short declared capability path to a candidate input type."""
        wanted = {kind.casefold() for operation in candidates for kind in operation.input_entity_kinds}
        queue: list[tuple[str, list[ProviderOperation]]] = [(start_type.casefold(), [])]
        visited = {start_type.casefold()}
        while queue:
            current, path = queue.pop(0)
            if any(types_are_compatible(current, candidate) for candidate in wanted) and path:
                return path
                return path
            ordered_operations = sorted(
                self.operations,
                key=lambda operation: 0 if preferred_relations and preferred_relations.intersection(
                    {value.casefold() for value in operation.guaranteed_relations}
                ) else 1,
            )
            for operation in ordered_operations:
                inputs = {kind.casefold() for kind in operation.input_entity_kinds}
                outputs = {kind.casefold() for kind in operation.output_entity_kinds}
                if not any(types_are_compatible(current, candidate) for candidate in inputs) or not outputs:
                    continue
                for output in outputs:
                    if output not in visited:
                        visited.add(output)
                        queue.append((output, path + [operation]))
        return None


__all__ = ["PlannerDiagnostic", "SemanticGoalPlanner"]
