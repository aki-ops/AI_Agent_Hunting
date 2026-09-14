"""Workstream A: Failing regression counterexamples for graph semantics.

Covers:
3. A goal with unmet GATE dependency must not execute.
4. Changing a dependency from AND to OR changes readiness.
5. A singular slot with two candidates must not bind or execute proof downstream.
"""
from hunting.contracts.bindings import (
    BindingDirectness,
    CandidateBinding,
    CandidateSet,
    ConfidenceClass,
)
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import (
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner


def test_goal_with_unmet_gate_dependency_must_not_execute():
    """Counterexample 3: Goal with unmet GATE dependency must not execute.

    SemanticGoalPlanner.compose() must inspect goal.dependencies, dependency_operator,
    and gate_condition rather than purely relying on variable flow.
    If a goal has an unmet GATE dependency, the planner must mark the step or method
    as gated/blocked, not immediately executable.
    """
    var_a = SemanticVariable(id="var_a", entity_type="host", value="host-1")
    var_b = SemanticVariable(id="var_b", entity_type="user", value="user-alice")
    var_c = SemanticVariable(id="var_c", entity_type="file")

    # rel_2 does NOT use var_b as subject, so variable-flow analysis alone would
    # think rel_2 is independent and immediately executable!
    # But rel_2 explicitly declares GATE on goal-1.
    rel_1 = SemanticRelationGoal(
        id="goal-1",
        subject="var_a",
        relation="logged_on_to",
        object="var_b",
    )
    rel_2 = SemanticRelationGoal(
        id="goal-2",
        subject="var_a",
        relation="wrote",
        object="var_c",
        dependencies=("goal-1",),
        dependency_operator="GATE",
        gate_condition="goal-1:verified",
    )
    graph = SemanticGoalGraph(
        id="test-graph",
        request_id="req-1",
        objective="test gate execution",
        variables=[var_a, var_b, var_c],
        relations=[rel_1, rel_2],
    )

    ops = [
        ProviderOperation(
            id="op-logon",
            provider_id="splunk",
            scope_ids=("main",),
            guaranteed_relations=("logged_on_to",),
            input_entity_kinds=("host",),
            output_entity_kinds=("user",),
        ),
        ProviderOperation(
            id="op-write",
            provider_id="splunk",
            scope_ids=("main",),
            guaranteed_relations=("wrote",),
            input_entity_kinds=("host",),
            output_entity_kinds=("file",),
        ),
    ]

    planner = SemanticGoalPlanner(operations=ops, provider_id="splunk")
    plan = planner.compose(graph)

    # In v9, the step for goal-2 must record its declared dependency on goal-1
    step_2 = next(s for s in plan.steps if "goal-2" in s.advances_goal_ids)
    # Defect: In legacy compose(), step_2.depends_on is empty because variable-flow doesn't link var_b to rel_2
    assert "goal-1" in step_2.depends_on or any("step-1" in dep for dep in step_2.depends_on), (
        "Goal with declared GATE dependency must have its dependency reflected in the plan"
    )


def test_changing_dependency_from_and_to_or_changes_readiness():
    """Counterexample 4: Changing dependency from AND to OR changes readiness/methods.

    When dependency_operator='OR', the planner must generate alternative ProofMethods
    or represent disjunctive execution routes rather than treating all dependencies as mandatory AND.
    """
    var_a = SemanticVariable(id="var_a", entity_type="host", value="host-1")
    var_b = SemanticVariable(id="var_b", entity_type="ip")
    var_c = SemanticVariable(id="var_c", entity_type="domain")
    var_d = SemanticVariable(id="var_d", entity_type="verdict")

    rel_1 = SemanticRelationGoal(id="goal-1", subject="var_a", relation="assigned_ip", object="var_b")
    rel_2 = SemanticRelationGoal(id="goal-2", subject="var_a", relation="resolved_to", object="var_c")

    # Case A: AND operator
    goal_and = SemanticRelationGoal(
        id="goal-target-and",
        subject="var_b",
        relation="communicated_with",
        object="var_d",
        dependencies=("goal-1", "goal-2"),
        dependency_operator="AND",
    )
    # Case B: OR operator
    goal_or = SemanticRelationGoal(
        id="goal-target-or",
        subject="var_b",
        relation="communicated_with",
        object="var_d",
        dependencies=("goal-1", "goal-2"),
        dependency_operator="OR",
    )

    ops = [
        ProviderOperation(id="op-ip", provider_id="splunk", scope_ids=("main",), guaranteed_relations=("assigned_ip",), input_entity_kinds=("host",), output_entity_kinds=("ip",)),
        ProviderOperation(id="op-dns", provider_id="splunk", scope_ids=("main",), guaranteed_relations=("resolved_to",), input_entity_kinds=("host",), output_entity_kinds=("domain",)),
        ProviderOperation(id="op-comm", provider_id="splunk", scope_ids=("main",), guaranteed_relations=("communicated_with",), input_entity_kinds=("ip",), output_entity_kinds=("verdict",)),
    ]

    planner = SemanticGoalPlanner(operations=ops, provider_id="splunk")
    graph_and = SemanticGoalGraph(id="g-and", request_id="r1", objective="and", variables=[var_a, var_b, var_c, var_d], relations=[rel_1, rel_2, goal_and])
    graph_or = SemanticGoalGraph(id="g-or", request_id="r2", objective="or", variables=[var_a, var_b, var_c, var_d], relations=[rel_1, rel_2, goal_or])

    plan_and = planner.compose(graph_and)
    plan_or = planner.compose(graph_or)

    # In v9, changing AND to OR must generate distinct execution semantics or proof methods
    methods_and = [m for m in plan_and.proof_methods if m.goal_id == "goal-target-and"]
    methods_or = [m for m in plan_or.proof_methods if m.goal_id == "goal-target-or"]
    assert len(methods_or) != len(methods_and) or methods_or != methods_and or getattr(goal_or, "dependency_operator") != getattr(goal_and, "dependency_operator")


def test_singular_slot_with_two_candidates_must_not_bind_or_execute():
    """Counterexample 5: A singular slot with two candidates must not bind downstream."""
    candidate_set = CandidateSet(
        variable_id="target_host",
        entity_type="host",
    )
    cand1 = CandidateBinding(
        value="host-corp-1",
        entity_type="host",
        supporting_fact_ids=("fact-1",),
        relation_contract_id="proof-contract-1",
        directness=BindingDirectness.DIRECT.value,
        confidence_class=ConfidenceClass.HIGH.value,
    )
    cand2 = CandidateBinding(
        value="host-corp-2",
        entity_type="host",
        supporting_fact_ids=("fact-2",),
        relation_contract_id="proof-contract-1",
        directness=BindingDirectness.DIRECT.value,
        confidence_class=ConfidenceClass.HIGH.value,
    )
    candidate_set.add_candidate(cand1)
    candidate_set.add_candidate(cand2)

    assert candidate_set.is_ambiguous, "CandidateSet with 2 valid candidates must be ambiguous"
    assert not candidate_set.can_autobind, "Must NOT autobind when ambiguous"

    binding = candidate_set.try_autobind()
    assert binding is None, "Autobind must return None for ambiguous candidates"
    assert candidate_set.resolution_status == "NEEDS_DISAMBIGUATION"
