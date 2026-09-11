"""Provider-neutral composition of semantic goals into logical plan steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep, ProofMethod, SemanticGoalGraph


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
    def _type_compatible(actual: str, declared: str) -> bool:
        """Apply the small provider-neutral endpoint type ontology.

        ``device``, ``endpoint`` and ``host`` are different vocabulary choices
        for the same executable identity layer in many telemetry estates.  A
        planner must not reject a graph solely because the LLM used one of
        these semantic labels while an adapter declared another.  This is a
        type compatibility rule, not a scenario route or source heuristic.
        """
        left = str(actual or "").casefold()
        right = str(declared or "").casefold()
        if left == right:
            return True
        endpoint_types = {"device", "endpoint", "host", "workstation", "computer"}
        if left in endpoint_types and right in endpoint_types:
            return True
        # Artifact vocabulary is likewise not uniform across compilers and
        # telemetry products.  The provider contract may call the output a
        # file while the semantic graph calls it an artifact/document.  This
        # compatibility is only used for typed planning; it does not prove
        # that the artifact satisfies its content/state qualifiers.
        artifact_types = {"file", "artifact", "document", "file_artifact"}
        return left in artifact_types and right in artifact_types

    def compose(self, graph: SemanticGoalGraph, *, plan_id: str = "logical-plan") -> LogicalPlan:
        known = {variable.id for variable in graph.variables if variable.value is not None}
        variable_types = {variable.id: variable.entity_type for variable in graph.variables}
        remaining = list(graph.relations)
        steps: list[PlanStep] = []
        diagnostics: list[PlannerDiagnostic] = []
        step_for_variable: dict[str, str] = {}
        proof_methods: list[ProofMethod] = []
        selected_method_ids: dict[str, str] = {}

        progress = True
        while remaining and progress:
            progress = False
            for goal in list(remaining):
                subject = next(variable for variable in graph.variables if variable.id == goal.subject)
                target = next(variable for variable in graph.variables if variable.id == goal.object)
                # A variable's restrictions belong to grounding that
                # variable.  Do not push a host/device restriction into a
                # downstream host->file (or host->domain) operation: that
                # turns an otherwise valid graph into a false capability
                # failure and couples unrelated steps.  Relation qualifiers
                # remain scoped to this relation.
                goal_constraints = [item.text() for item in target.constraints]
                goal_retrieval_terms = tuple(
                    (item.key, term)
                    for item in target.constraints
                    for term in item.retrieval_terms
                )
                goal_constraint_metadata = [
                    {
                        "key": item.key,
                        "operator": item.operator,
                        "value": item.value,
                        "provenance": "semantic_graph",
                        "trust_class": (
                            "request_grounded"
                            if target.value_origin == "request"
                            else "compiler_proposed"
                        ),
                    }
                    for item in target.constraints
                ]
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
                        "trust_class": "request_grounded",
                    })
                execution_subject_id = subject.id
                prerequisite_goal_ids = tuple(
                    relation.id for relation in graph.relations
                    if relation.object == goal.subject and relation.id != goal.id and relation.required
                )
                candidates = list({operation.id: operation for operation in self.operations
                    if goal.relation.casefold() in {value.casefold() for value in operation.guaranteed_relations}
                    and operation.provider_id == self.provider_id
                    and (not operation.output_entity_kinds or any(
                        self._type_compatible(target.entity_type, kind)
                        for kind in operation.output_entity_kinds
                    ))
                }.values())
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
                        self._type_compatible(subject.entity_type, kind)
                        for kind in candidate.input_entity_kinds
                    ):
                        continue
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
                    if (not operation.input_entity_kinds or any(
                        self._type_compatible(subject.entity_type, kind)
                        for kind in operation.input_entity_kinds
                    ))
                    and (not operation.input_entity_kinds or subject.id in known)
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
                            advances_goal_ids=(),
                            depends_on=tuple(
                                dependency for variable_id, dependency in step_for_variable.items()
                                if variable_id == previous_variable
                            ),
                            expected_cost=operation.expected_cost or 1,
                            constraints=(),
                            constraint_retrieval_terms=(),
                            relation=(operation.guaranteed_relations[0] if operation.guaranteed_relations else "observed"),
                        ))
                        variable_types[intermediate] = output_type
                        known.add(intermediate)
                        step_for_variable[intermediate] = step_id
                        previous_variable = intermediate
                        previous_type = output_type
                    ready = [operation for operation in candidates if any(
                        self._type_compatible(previous_type, kind)
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
                    key=lambda item: (
                        -sum(
                            1 for constraint in goal_constraints
                            if self._constraint_key(constraint) in {
                                str(key).strip().casefold()
                                for key in item.supported_constraints
                            }
                        ),
                        item.expected_cost if item.expected_cost is not None else 1,
                        len(item.input_entity_kinds) or 999,
                        item.id,
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
                dependencies = tuple(
                    dependency for variable_id, dependency in step_for_variable.items()
                    if variable_id == execution_subject_id
                )
                steps.append(
                    PlanStep(
                        id=step_id,
                        operation_id=operation.id,
                        input_bindings={"subject": execution_subject_id},
                        output_bindings={"object": target.id},
                        advances_goal_ids=(goal.id,),
                        depends_on=dependencies,
                        expected_cost=operation.expected_cost or 1,
                        constraints=tuple(dict.fromkeys(goal_constraints)),
                        constraint_retrieval_terms=goal_retrieval_terms,
                        relation=goal.relation,
                        constraint_metadata=tuple(goal_constraint_metadata),
                        alternative_operation_ids=tuple(
                            candidate.id for candidate in ready if candidate.id != operation.id
                        ),
                    )
                )
                step_for_variable[target.id] = step_id
                known.add(target.id)
                remaining.remove(goal)
                progress = True

        for goal in remaining:
            diagnostics.append(PlannerDiagnostic(goal.id, "No declared capability path can satisfy this relation with currently known variables"))

        plan = LogicalPlan(
            id=plan_id,
            goal_graph_id=graph.id,
            provider_id=self.provider_id,
            steps=steps,
            unresolved_goal_ids=[diagnostic.goal_id for diagnostic in diagnostics],
            proof_methods=proof_methods,
            selected_method_ids=selected_method_ids,
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
            if any(self._type_compatible(current, candidate) for candidate in wanted) and path:
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
                if not any(self._type_compatible(current, candidate) for candidate in inputs) or not outputs:
                    continue
                for output in outputs:
                    if output not in visited:
                        visited.add(output)
                        queue.append((output, path + [operation]))
        return None


__all__ = ["PlannerDiagnostic", "SemanticGoalPlanner"]
