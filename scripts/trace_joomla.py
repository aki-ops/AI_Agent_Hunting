"""Replay the exact Joomla graph through planner + executor, no LLM."""
import sys

sys.path.insert(0, "src")
from hunting.contracts.semantic_graph import (
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.m5_adapter import CdbAdapter
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner

adapter = CdbAdapter("data/botsv1_eval.sqlite")
desc = adapter.get_capability_descriptor()
ops = [op for op in desc.operations if not getattr(op, "legacy_alias", False)
       and op.query_builder != "runtime.source_profile.v1"
       and op.guaranteed_relations]

# Exact shape from report.md decomposition (with qualifier)
graph = SemanticGoalGraph(
    id="goal-graph-test", request_id="test",
    objective="Attacker exploits Joomla search component on imreallynotbatman.com",
    variables=[
        SemanticVariable(id="site", entity_type="domain", value="imreallynotbatman.com",
                         value_origin="request", verification_status="UNVERIFIED",
                         constraints=(SemanticConstraint(key="domain", operator="equals",
                                                         value="imreallynotbatman.com",
                                                         retrieval_terms=["imreallynotbatman.com"]),)),
        SemanticVariable(id="exploit_request", entity_type="artifact",
                         value="Joomla search component",
                         value_origin="request", verification_status="UNVERIFIED",
                         constraints=(SemanticConstraint(key="component", operator="equals",
                                                         value="Joomla search component"),)),
    ],
    relations=[SemanticRelationGoal(id="goal-1", subject="site", relation="web_request",
                                    object="exploit_request", required=True,
                                    description="web requests to site exploiting Joomla")],
    qualifiers=[SemanticQualifierGoal(id="q-1", target_goal_id="goal-1",
                                  qualifier="component",
                                  expected_value="Joomla search component",
                                  required=True)],
    answers=[], assumptions=[], uncertainties=[],
)
plan = SemanticGoalPlanner(ops, "cdb").compose(graph, plan_id="logical-test")
print("steps:", [(s.id, s.operation_id, s.input_bindings, s.constraints) for s in plan.steps], flush=True)
print("unresolved:", plan.unresolved_goal_ids, flush=True)
print("methods:", [(m.id, m.operation_ids) for m in plan.proof_methods], flush=True)

# Now run the executor the way the engine does
from hunting.contracts.cells import ProviderScope
from hunting.planner.semantic_executor import SemanticPlanExecutor

scope = ProviderScope(provider_id="cdb", native_partition={"database": "x", "table": "events"},
                      scope_id="cdb_security")
ex = SemanticPlanExecutor(adapter, tuple(ops)).execute(
    plan, scope, "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z",
    {"site": ["imreallynotbatman.com"], "exploit_request": ["Joomla search component"]},
    limit=1000,
    variable_types={"site": "domain", "exploit_request": "artifact"},
    initial_variable_sources={"site": "request", "exploit_request": "request"},
)
for item in ex.executions:
    print(f"exec step={item.step_id} op={item.operation_id} status={item.status} "
          f"rows={len(item.result.rows or [])} complete={item.result.complete} "
          f"diag={item.result.diagnostic} trunc={item.result.truncation_reason!r}", flush=True)
print("route assessments:", [(a.goal_id, a.status, a.readiness) for a in ex.route_assessments], flush=True)
