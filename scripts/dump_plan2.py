"""Dump plan with the exact graph shape the model now returns."""
import sys

sys.path.insert(0, "src")
from hunting.contracts.semantic_graph import (
    SemanticConstraint,
    SemanticGoalGraph,
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

graph = SemanticGoalGraph(
    id="goal-graph-test", request_id="test",
    objective="Attacker exploits Joomla search component on imreallynotbatman.com",
    variables=[
        SemanticVariable(id="site", entity_type="domain", value="imreallynotbatman.com",
                         value_origin="request", verification_status="UNVERIFIED",
                         constraints=(SemanticConstraint(key="domain", operator="equals",
                                                         value="imreallynotbatman.com",
                                                         retrieval_terms=["imreallynotbatman.com"]),)),
        SemanticVariable(id="exploit_request", entity_type="value", value="Joomla search component",
                         value_origin="request", verification_status="UNVERIFIED",
                         constraints=(SemanticConstraint(key="component", operator="equals",
                                                         value="Joomla search component"),)),
    ],
    relations=[SemanticRelationGoal(id="goal-1", subject="site", relation="web_request",
                                    object="exploit_request", required=True,
                                    description="web requests exploiting Joomla")],
    qualifiers=[], answers=[],
    assumptions=[], uncertainties=[],
)
planner = SemanticGoalPlanner(ops, "cdb")
plan = planner.compose(graph, plan_id="logical-test")
print("steps:", [(s.id, s.operation_id, s.input_bindings) for s in plan.steps], flush=True)
print("unresolved:", plan.unresolved_goal_ids, flush=True)
# Manual candidate check
for op in ops:
    if "web_request" in [g.casefold() for g in op.guaranteed_relations]:
        ok_in = planner._type_compatible("domain", op.input_entity_kinds[0])
        print(f"  {op.id} inputs={op.input_entity_kinds} domain-compatible={ok_in}", flush=True)
