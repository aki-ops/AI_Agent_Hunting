"""Workstream D: Tests for Executable AND/OR/GATE Planner, Proof Methods, and GateEvaluator.

Acceptance gate D:
- AND/OR/GATE tests execute different expected step sets;
- blocked gates issue zero provider queries;
- intermediate goals are visible in graph history;
- a one-goal factual lookup stays one goal when no intermediate binding is needed.
"""
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.observation_class import (
    CoverageStatus,
    ExecutionStatus,
    ProofStatus,
)
from hunting.contracts.queries import (
    ProviderOperation,
    QueryOutcome,
    QueryResult,
)
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.state import GoalRuntimeState
from hunting.planner.gate_evaluator import GateEvaluator
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner


def test_gate_evaluator_predicates_and_safety() -> None:
    """Test GateEvaluator deterministic logic and safety boundaries."""
    goal_states: dict[str, Any] = {
        "g-proven": GoalRuntimeState(
            goal_id="g-proven",
            execution_status=ExecutionStatus.EXECUTED,
            proof_status=ProofStatus.PROVEN,
            coverage_status=CoverageStatus.COMPLETE,
        ),
        "g-unproven": GoalRuntimeState(
            goal_id="g-unproven",
            execution_status=ExecutionStatus.EXECUTED,
            proof_status=ProofStatus.UNPROVEN,
            coverage_status=CoverageStatus.PARTIAL,
        ),
        "g-refuted": GoalRuntimeState(
            goal_id="g-refuted",
            execution_status=ExecutionStatus.EXECUTED,
            proof_status=ProofStatus.REFUTED,
            coverage_status=CoverageStatus.COMPLETE,
        ),
    }

    # 1. Empty gate condition passes
    res_empty = GateEvaluator.evaluate("", goal_states)
    assert res_empty.passed

    # 2. Verified predicate
    res_proven = GateEvaluator.evaluate("g-proven:verified", goal_states)
    assert res_proven.passed

    res_unproven = GateEvaluator.evaluate("g-unproven:verified", goal_states)
    assert not res_unproven.passed
    assert "expected PROVEN" in res_unproven.reason

    # 3. Refuted predicate
    res_refuted = GateEvaluator.evaluate("g-refuted:refuted", goal_states)
    assert res_refuted.passed

    # 4. Status checks
    res_cov = GateEvaluator.evaluate("g-proven:coverage_status=COMPLETE", goal_states)
    assert res_cov.passed

    res_cov_fail = GateEvaluator.evaluate("g-unproven:coverage_status=COMPLETE", goal_states)
    assert not res_cov_fail.passed

    # 5. Safety: Injection / SQL / SPL fragments rejected
    res_injection = GateEvaluator.evaluate("g-proven:verified | table *", goal_states)
    assert not res_injection.passed
    assert "forbidden expression" in res_injection.reason

    res_sql = GateEvaluator.evaluate("SELECT * FROM users", goal_states)
    assert not res_sql.passed
    assert "forbidden expression" in res_sql.reason

    # 6. Compound AND / OR
    res_compound_and = GateEvaluator.evaluate("g-proven:verified AND g-unproven:verified", goal_states)
    assert not res_compound_and.passed

    res_compound_or = GateEvaluator.evaluate("g-proven:verified OR g-unproven:verified", goal_states)
    assert res_compound_or.passed


def test_blocked_gate_issues_zero_provider_queries() -> None:
    """Acceptance Gate D: Blocked gates issue zero provider queries."""
    step_1 = PlanStep(
        id="s1",
        operation_id="op-1",
        input_bindings={"subject": "host"},
        output_bindings={"object": "user"},
        advances_goal_ids=("goal-1",),
    )
    step_2 = PlanStep(
        id="s2",
        operation_id="op-2",
        input_bindings={"subject": "host"},
        output_bindings={"object": "file"},
        advances_goal_ids=("goal-2",),
        depends_on=("s1",),
        dependency_operator="GATE",
        gate_condition="goal-1:verified",
    )

    plan = LogicalPlan(
        id="gate-plan",
        goal_graph_id="g1",
        provider_id="mock",
        steps=[step_1, step_2],
    )

    class FakeAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, **kwargs):
            self.calls.append(kwargs)
            # Step 1 returns empty rows (meaning goal-1 is NOT proven)
            if kwargs["operation_id"] == "op-1":
                return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[])
            return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[{"file": "foo.txt"}])

    adapter = FakeAdapter()
    ops = [
        ProviderOperation("op-1", "mock", ("test",), input_entity_kinds=("host",), output_entity_kinds=("user",)),
        ProviderOperation("op-2", "mock", ("test",), input_entity_kinds=("host",), output_entity_kinds=("file",)),
    ]
    executor = SemanticPlanExecutor(adapter, ops)
    scope = ProviderScope(provider_id="mock", native_partition={"index": "main"}, scope_id="test")

    res = executor.execute(
        plan=plan,
        scope=scope,
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        initial_variables={"host": "host-1"},
    )

    # Step 1 issued a query
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["operation_id"] == "op-1"
    # Step 2 was BLOCKED by the gate -> ZERO queries issued for s2!
    assert any("GATE blocked" in reason for reason in res.unresolved_reasons.values())


def test_audited_graph_expansion_revisions() -> None:
    """Acceptance Gate D: Intermediate goals are visible in graph history."""
    var_a = SemanticVariable(id="var_a", entity_type="user", value="alice")
    var_b = SemanticVariable(id="var_b", entity_type="file")
    rel_1 = SemanticRelationGoal(id="g1", subject="var_a", relation="wrote", object="var_b")

    g0 = SemanticGoalGraph(
        id="graph-1",
        request_id="req-1",
        objective="Find files written by alice",
        variables=[var_a, var_b],
        relations=[rel_1],
    )
    assert g0.graph_revision == "G0"
    assert len(g0.revision_history) == 0

    # Propose expansion: introduce intermediate host variable and relations
    var_host = SemanticVariable(id="var_host", entity_type="host")
    rel_intermediate = SemanticRelationGoal(id="g-int", subject="var_a", relation="logged_on_to", object="var_host")

    g1 = g0.propose_expansion(
        intermediate_variables=[var_host],
        intermediate_relations=[rel_intermediate],
        reason="No direct user->file capability; typed route requires intermediate host",
    )

    assert g1.graph_revision == "G1"
    assert len(g1.revision_history) == 1
    entry = g1.revision_history[0]
    assert entry["from_revision"] == "G0"
    assert entry["to_revision"] == "G1"
    assert "intermediate host" in entry["reason"]
    assert "var_host" in entry["added_variables"]
    assert "g-int" in entry["added_relations"]

    # Serialization roundtrip preserves history
    data = g1.to_dict()
    assert data["graph_revision"] == "G1"
    assert len(data["revision_history"]) == 1

    g1_deserialized = SemanticGoalGraph.from_dict(data)
    assert g1_deserialized.graph_revision == "G1"
    assert g1_deserialized.revision_history[0]["to_revision"] == "G1"


def test_single_goal_factual_lookup_stays_single_goal() -> None:
    """Acceptance Gate D: A one-goal factual lookup stays one goal when no intermediate binding is needed."""
    var_host = SemanticVariable(id="host", entity_type="host", value="desktop-01")
    var_version = SemanticVariable(id="ver", entity_type="version")
    rel = SemanticRelationGoal(id="g-ver", subject="host", relation="installed_version", object="ver")

    graph = SemanticGoalGraph(
        id="g-simple",
        request_id="req-simple",
        objective="What version is installed?",
        variables=[var_host, var_version],
        relations=[rel],
    )

    ops = [
        ProviderOperation(
            id="op-ver",
            provider_id="splunk",
            scope_ids=("main",),
            guaranteed_relations=("installed_version",),
            input_entity_kinds=("host",),
            output_entity_kinds=("version",),
        )
    ]

    planner = SemanticGoalPlanner(operations=ops, provider_id="splunk")
    plan = planner.compose(graph)

    assert len(plan.steps) == 1
    assert plan.steps[0].operation_id == "op-ver"
    assert plan.steps[0].advances_goal_ids == ("g-ver",)
    assert len(plan.unresolved_goal_ids) == 0
