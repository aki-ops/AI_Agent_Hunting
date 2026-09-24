"""M4 counterexamples: typed planning and EvidenceGraph authority.

Proximity is not proof. C3 cannot replace a successful deterministic compile.
"""
from __future__ import annotations

import pytest

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import LogicalQueryPlan
from hunting.contracts.native_query import NativeQueryCandidate
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.query_intent import QueryIntentSpec, QueryPredicateSpec
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep
from hunting.evidence.evidence_graph import EvidenceEdgeClass, EvidenceGraph
from hunting.planner.semantic_query_compiler import query_plan_from_step
from hunting.query_safety.c3_admission import should_invoke_c3
from hunting.query_safety.native_query_gate import NativeQueryGate


def _scope(provider: str = "cdb", dataset: str = "test", scope_id: str = "scope") -> ProviderScope:
    return ProviderScope(provider, {"dataset": dataset}, scope_id, retention_days=30)


def _observation(obs_id: str, host: str, provider: str = "cdb", query_id: str = "q-1") -> Observation:
    return Observation(
        id=obs_id,
        provider_scope=_scope(provider, provider, f"{provider}-scope"),
        cell_id="cell-1",
        timestamp="2026-02-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="process_creation",
        fields={"host": host, "image": "powershell.exe", "cmdline": "powershell -enc x", "pid": 7},
        query_id=query_id,
    )


def _intent() -> QueryIntentSpec:
    return QueryIntentSpec(
        goal_id="g-1",
        operation_id="find-host",
        source_id="src-1",
        relation="observed-on",
        bindings={"host": "HOST-1"},
        predicates=(QueryPredicateSpec(key="host", operator="equals", value="HOST-1"),),
        time_window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        projection_roles=("host",),
        expected_output=("host",),
        max_rows=25,
    )


def test_proximity_does_not_create_causal_attribution() -> None:
    graph = EvidenceGraph.from_observations([
        _observation("o-1", "HOST-1"),
        _observation("o-2", "HOST-1"),
    ])
    assert graph.edges
    assert all(edge.proof_status == "NOT_PROOF" for edge in graph.edges.values())
    assert not any(edge.edge_class == EvidenceEdgeClass.CAUSAL_ATTRIBUTION.value for edge in graph.edges.values())


def test_contains_fact_is_provenance_not_transition() -> None:
    graph = EvidenceGraph.from_observations([_observation("o-1", "HOST-1")])
    classes = {edge.edge_type: edge.edge_class for edge in graph.edges.values()}
    assert classes["contains_fact"] == EvidenceEdgeClass.PROVENANCE_DEPENDENCY.value
    assert classes["has_field"] == EvidenceEdgeClass.PROVENANCE_DEPENDENCY.value
    assert any(edge.edge_class == EvidenceEdgeClass.OBSERVED_TRANSITION.value for edge in graph.edges.values())


def test_causal_attribution_requires_cited_contract_and_stays_not_proof() -> None:
    graph = EvidenceGraph.from_observations([_observation("o-1", "HOST-1")])
    source = next(node.id for node in graph.nodes.values() if node.node_type == "entity")
    target = next(node.id for node in graph.nodes.values() if node.node_type == "fact")
    with pytest.raises(ValueError, match="approved correlation"):
        graph.add_causal_attribution(
            source_id=source,
            target_id=target,
            observation_ids=("o-1",),
            contract_id="",
        )
    edge = graph.add_causal_attribution(
        source_id=source,
        target_id=target,
        observation_ids=("o-1",),
        contract_id="corr-identity-1",
    )
    assert edge.edge_class == EvidenceEdgeClass.CAUSAL_ATTRIBUTION.value
    assert edge.proof_status == "NOT_PROOF"


def test_from_run_account_rebuilds_from_observations_not_extra_projection() -> None:
    observed = _observation("o-1", "HOST-1")
    live = EvidenceGraph.from_observations([observed])
    mutated = live.to_dict()
    mutated["observation_ids"].append("invented")
    mutated["nodes"].append({
        "id": "observation:invented",
        "node_type": "observation",
        "payload": {"native_fields": {"host": "FAKE"}},
        "provenance_ids": ["invented"],
    })
    account = {
        "semantic_evidence_analysis": {
            "observations": [observed.to_dict()],
            "evidence_graph": mutated,
        }
    }
    restored = EvidenceGraph.from_run_account(account)
    assert restored.observation_ids == ["o-1"]
    assert "observation:invented" not in restored.nodes
    assert all(edge.proof_status == "NOT_PROOF" for edge in restored.edges.values())


def test_multi_provider_observations_share_graph_without_proof() -> None:
    graph = EvidenceGraph.from_observations([
        _observation("o-1", "HOST-1", provider="cdb"),
        _observation("o-2", "HOST-1", provider="splunk"),
    ])
    providers = {
        node.payload.get("provider_id")
        for node in graph.nodes.values()
        if node.node_type == "observation"
    }
    assert providers == {"cdb", "splunk"}
    assert all(edge.proof_status == "NOT_PROOF" for edge in graph.edges.values())
    assert not any(edge.edge_class == EvidenceEdgeClass.CAUSAL_ATTRIBUTION.value for edge in graph.edges.values())


def test_query_intent_compiles_to_logical_and_native_without_c3() -> None:
    plan = LogicalPlan(id="lp-1", goal_graph_id="gg-1", provider_id="cdb")
    step = PlanStep(
        id="s-1",
        operation_id="find-host",
        relation="observed-on",
        advances_goal_ids=["g-1"],
        input_bindings={"host": "HOST-1"},
        output_bindings={"host": "host"},
        constraints=["host=HOST-1"],
        mode="EXPLORE",
    )
    query = query_plan_from_step(plan, step, _scope(), "2026-02-01T00:00:00Z/2026-02-02T00:00:00Z")
    logical = query.parameters["logical_query_plan"]
    native = query.parameters["native_query_plan"]
    replay = query.parameters["query_replay"]
    assert query.parameters["query_intent"]["goal_id"] == "g-1"
    assert logical["provider"] == "cdb"
    assert logical["scope"] == "scope"
    assert logical["cost_status"] == "unknown"
    assert logical["retention_days"] == 30
    assert logical["cancellation_cap"] == 100
    assert query.parameters["c3_invoked"] is False
    assert replay["provider_id"] == "cdb"
    assert replay["scope_id"] == "scope"
    assert replay["time_window"] == "2026-02-01T00:00:00Z/2026-02-02T00:00:00Z"
    assert replay["native_query"] == native["native_query"]
    assert "provider_operation" in native["native_query"]
    assert should_invoke_c3(admitted=True, deterministic_plan=LogicalQueryPlan(
        id=logical["id"],
        requirement_id=logical["requirement_id"],
        provider=logical["provider"],
        scope=logical["scope"],
    )) is False
    assert should_invoke_c3(admitted=True, deterministic_plan=None) is True


def test_query_replay_preserves_scope_provider_and_time() -> None:
    plan = LogicalPlan(id="lp-1", goal_graph_id="gg-1", provider_id="cdb")
    step = PlanStep(
        id="s-1",
        operation_id="find-host",
        relation="observed-on",
        advances_goal_ids=["g-1"],
        mode="PROVE",
        expected_cost=0,
    )
    query = query_plan_from_step(
        plan,
        step,
        _scope("cdb", "bots", "acct"),
        "2026-03-01T00:00:00Z/2026-03-02T00:00:00Z",
        query_id="q-replay",
        limit=10,
    )
    replay = query.parameters["query_replay"]
    assert replay == {
        "provider_id": "cdb",
        "scope_id": "acct",
        "source_id": "acct",
        "operation_id": "find-host",
        "time_window": "2026-03-01T00:00:00Z/2026-03-02T00:00:00Z",
        "query_id": "q-replay",
        "native_query": query.parameters["native_query_plan"]["native_query"],
        "job_id": None,
        "cost_status": "unknown",
        "retention_days": 30,
        "cancellation_cap": 10,
        "cursor": "",
        "pagination": "none",
        "adjacency": [],
    }


def test_c3_gate_rejects_output_roles_outside_intent() -> None:
    intent = _intent()
    gate = NativeQueryGate()
    candidate = NativeQueryCandidate(
        provider="splunk",
        query_text='search index=botsv2 host="HOST-1" | fields user | head 10',
        source_ids=("botsv2",),
        time_window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        expected_fields=("user",),
        max_rows=10,
    )
    result = gate.validate(
        candidate,
        known_sources=["botsv2"],
        known_fields=["host", "user"],
        intent=intent,
    )
    assert result.accepted is False
    assert any(reason.startswith("output_roles_not_in_intent") for reason in result.reasons)
