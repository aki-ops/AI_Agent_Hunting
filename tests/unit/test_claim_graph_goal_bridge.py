from types import SimpleNamespace

from hunting.contracts.semantic_graph import goal_graph_from_claim_graph


def test_legacy_claims_are_exposed_as_generic_goals() -> None:
    graph = SimpleNamespace(
        id="claims-1",
        request_id="req-1",
        objective="Find an observed artifact",
        claims=[SimpleNamespace(
            id="claim-1",
            subject="Amber",
            predicate="observed",
            object_or_value="artifact",
            value_type="artifact",
            optional=False,
            reason="request-derived",
        )],
    )
    result = goal_graph_from_claim_graph(graph)
    assert result.relations[0].relation == "observed"
    assert result.relations[0].subject == "amber"
    assert result.relations[0].object == "artifact"
    assert result.uncertainties
