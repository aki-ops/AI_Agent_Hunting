"""Dump the logical plan for a Joomla-like graph against the CDB descriptor."""
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
print("canonical ops:", [(o.id, o.input_entity_kinds, o.guaranteed_relations) for o in ops], flush=True)

graph = SemanticGoalGraph(
    id="goal-graph-test", request_id="test",
    objective="Attacker exploits Joomla search component on imreallynotbatman.com",
    variables=[
        SemanticVariable(id="site", entity_type="domain", value="imreallynotbatman.com",
                         value_origin="request", verification_status="UNVERIFIED",
                         constraints=(SemanticConstraint(key="domain", operator="equals",
                                                         value="imreallynotbatman.com",
                                                         retrieval_terms=["imreallynotbatman.com"]),)),
        SemanticVariable(id="req", entity_type="artifact", value=None,
                         value_origin="llm_proposal", verification_status="UNVERIFIED",
                         constraints=()),
    ],
    relations=[SemanticRelationGoal(id="goal-1", subject="site", relation="web_request",
                                    object="req", required=True,
                                    description="web requests exploiting Joomla")],
    qualifiers=[], answers=[],
    assumptions=[], uncertainties=[],
)
plan = SemanticGoalPlanner(ops, "cdb").compose(graph, plan_id="logical-test")
print("steps:", [(s.id, s.operation_id) for s in plan.steps], flush=True)
print("unresolved:", plan.unresolved_goal_ids, flush=True)
