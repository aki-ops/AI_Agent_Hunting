from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.semantic_route import CapabilityReadiness, SemanticRouteAssessment, SemanticRouteStatus
from hunting.planner.semantic_readiness import assess_semantic_readiness


def _graph(constraints=()):
    return SemanticGoalGraph(
        "g", "r", "Find a file",
        variables=[
            SemanticVariable("host", "host", "host-1"),
            SemanticVariable("file", "file", constraints=constraints),
        ],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
    )


def test_retrieval_only_route_does_not_claim_proof_readiness():
    operation = ProviderOperation(
        "file-search", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), searchable_constraints=("format",),
    )
    graph = _graph(("format=presentation",))
    plan = LogicalPlan("p", "g", "p", [PlanStep("s", "file-search", {"subject": "host"}, {"object": "file"}, advances_goal_ids=("changed",), constraints=("format=presentation",))])
    assessment = assess_semantic_readiness(graph, plan, (operation,))[0]
    assert assessment.readiness == CapabilityReadiness.RETRIEVAL_CAPABLE
    assert assessment.status == SemanticRouteStatus.PROOF_GAP


def test_relation_observable_route_with_supported_constraints_is_proof_capable():
    operation = ProviderOperation(
        "file-proof", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), supported_constraints=("format",),
    )
    graph = _graph(("format=presentation",))
    plan = LogicalPlan("p", "g", "p", [PlanStep("s", "file-proof", {"subject": "host"}, {"object": "file"}, advances_goal_ids=("changed",), constraints=("format=presentation",))])
    assessment = assess_semantic_readiness(graph, plan, (operation,))[0]
    assert assessment.readiness == CapabilityReadiness.PROOF_CAPABLE


def test_prior_exhaustion_is_preserved_and_not_reopened():
    operation = ProviderOperation(
        "file-search", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",), guaranteed_relations=("modified",),
    )
    graph = _graph()
    plan = LogicalPlan("p", "g", "p", [PlanStep("s", "file-search", {"subject": "host"}, {"object": "file"}, advances_goal_ids=("changed",))])
    prior = SemanticRouteAssessment("changed", "modified", status=SemanticRouteStatus.ATTEMPTED_EMPTY, route_exhausted=True)
    assessment = assess_semantic_readiness(graph, plan, (operation,), prior_assessments=(prior,))[0]
    assert assessment.readiness == CapabilityReadiness.ROUTE_EXHAUSTED
    assert assessment.route_exhausted is True
