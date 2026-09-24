"""M2 counterexamples: mode-aware EXPLORE / DISCRIMINATE / PROVE on the production path.

These tests use RecoveryController and HypothesisHuntEngine.execute_semantic_plan.
Scenario names, relation aliases and known answers are not used.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from hunting.contracts.bindings import CandidateBinding, CandidateSet, ConfidenceClass
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, HuntState, StoppingDecision
from hunting.contracts.observation_class import ObservationClass
from hunting.contracts.outcome import (
    FactualAnswerContract,
    HypothesisVerdictContract,
    PopulationDiscoveryContract,
)
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.search_envelope import SearchEnvelope
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
    accept_graph_revision,
)
from hunting.controller.loop_guard import LoopGuard
from hunting.controller.recovery_controller import RecoveryController
from hunting.engine import HypothesisHuntEngine
from hunting.m1_ledger.ledger import ObservationLedger


class _RecordingAdapter:
    def __init__(self, rows_by_op: dict[str, list[dict[str, Any]]]) -> None:
        self.rows_by_op = rows_by_op
        self.calls: list[str] = []

    def execute_query(self, **kwargs: Any) -> QueryResult:
        op_id = str(kwargs.get("operation_id", ""))
        self.calls.append(op_id)
        rows = list(self.rows_by_op.get(op_id, []))
        return QueryResult(
            query_id=str(kwargs.get("query_id", "q")),
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=rows,
            row_count=len(rows),
        )


def _scope() -> ProviderScope:
    return ProviderScope(provider_id="mock", native_partition={"index": "main"}, scope_id="scope")


def _run_plan(
    *,
    graph: SemanticGoalGraph,
    plan: LogicalPlan,
    operations: tuple[ProviderOperation, ...],
    rows_by_op: dict[str, list[dict[str, Any]]],
    outcome_contract: Any = None,
    allow_candidate_inputs: bool = True,
    initial_bindings: dict[str, str | list[str]] | None = None,
) -> tuple[HuntState, _RecordingAdapter]:
    state = HuntState(
        objective=HuntObjective(
            request_id=graph.request_id,
            statement=graph.objective,
            time_window="2026-01-01T00:00:00Z/P1D",
            outcome_contract=outcome_contract,
        ),
    )
    state.semantic_goal_graph = graph
    state.semantic_logical_plan = plan
    state.capability_catalog = SimpleNamespace(operations=operations)
    state.search_envelope = SearchEnvelope()
    adapter = _RecordingAdapter(rows_by_op)
    HypothesisHuntEngine().execute_semantic_plan(
        state,
        adapter,
        _scope(),
        ObservationLedger(),
        allow_candidate_inputs=allow_candidate_inputs,
        initial_bindings=initial_bindings,
    )
    return state, adapter


def test_explore_candidates_do_not_seek_proof() -> None:
    controller = RecoveryController()
    action = controller.choose_next_action(
        classification=ObservationClass.CANDIDATES,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
        candidates=[{"role": "process", "value": "proc-a"}],
        mode="EXPLORE",
    )
    assert action.action_type == "RECORD_CANDIDATE"
    assert action.action_type != "SEEK_PROOF"


def test_prove_candidates_seek_approved_proof_route() -> None:
    controller = RecoveryController()
    action = controller.choose_next_action(
        classification=ObservationClass.PROOF_GAP,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
        candidates=[{"role": "domain", "value": "site.example"}],
        mode="PROVE",
        has_proof_capable_route=True,
    )
    assert action.action_type == "SEEK_PROOF"


def test_missing_proof_contract_preserves_candidates() -> None:
    controller = RecoveryController()
    action = controller.choose_next_action(
        classification=ObservationClass.PROOF_GAP,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
        candidates=[{"role": "domain", "value": "site.example"}],
        mode="PROVE",
        has_proof_capable_route=False,
    )
    assert action.action_type == "PRESERVE_CANDIDATE_LIMITATION"
    assert action.candidate_bindings[0]["value"] == "site.example"


def test_discriminate_requires_declared_differentiating_evidence() -> None:
    controller = RecoveryController()
    cands = [{"role": "host", "value": "h1"}, {"role": "host", "value": "h2"}]
    denied = controller.choose_next_action(
        classification=ObservationClass.AMBIGUOUS,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
        candidates=cands,
        declared_discriminator=False,
    )
    assert denied.action_type == "NEEDS_DISAMBIGUATION"

    allowed = controller.choose_next_action(
        classification=ObservationClass.AMBIGUOUS,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
        candidates=cands,
        declared_discriminator=True,
    )
    assert allowed.action_type == "DISCRIMINATE"


def test_plural_candidates_are_not_ambiguous() -> None:
    controller = RecoveryController()
    attempt = SimpleNamespace(
        executed_ok=True,
        complete=True,
        rows=[{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
        row_count=2,
        diagnostic_errors=[],
        proof_result=None,
        proof_conforming=False,
    )
    obs = controller.classify(
        attempt=attempt,
        extracted_candidates=[
            {"role": "ips", "value": "10.0.0.1"},
            {"role": "ips", "value": "10.0.0.2"},
        ],
        cardinality="plural",
    )
    assert obs != ObservationClass.AMBIGUOUS
    action = controller.choose_next_action(
        classification=ObservationClass.AMBIGUOUS,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
        candidates=[{"role": "ips", "value": "10.0.0.1"}, {"role": "ips", "value": "10.0.0.2"}],
        cardinality="plural",
        declared_discriminator=True,
    )
    assert action.action_type == "RECORD_CANDIDATE"


def test_row_order_score_and_substring_cannot_bind_singular() -> None:
    cset = CandidateSet(variable_id="host", entity_type="host", cardinality="singular")
    cset.add_candidate(CandidateBinding(
        value="host-first",
        entity_type="host",
        confidence_class=ConfidenceClass.HIGH.value,
        metadata={"score": 0.99, "row_index": 0, "provider_order": 0},
    ))
    cset.add_candidate(CandidateBinding(
        value="host-air13",
        entity_type="host",
        confidence_class=ConfidenceClass.MEDIUM.value,
        metadata={"score": 0.1, "substring": "air"},
    ))
    assert cset.try_autobind() is None
    assert cset.selected_binding is None
    assert cset.resolution_status == "NEEDS_DISAMBIGUATION"


def test_candidate_input_cannot_feed_prove_step() -> None:
    graph = SemanticGoalGraph(
        id="g-bind-prove",
        request_id="req-bind-prove",
        objective="observe then prove",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
            SemanticVariable("domain", "domain"),
        ],
        relations=[
            SemanticRelationGoal("g-explore", "host", "observed", "process", required=True),
            SemanticRelationGoal("g-prove", "process", "visited", "domain", required=True),
        ],
    )
    plan = LogicalPlan(
        id="plan-bind-prove",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s-explore",
                operation_id="op-explore",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-explore",),
                mode="EXPLORE",
            ),
            PlanStep(
                id="s-prove",
                operation_id="op-prove",
                input_bindings={"subject": "process"},
                output_bindings={"object": "domain"},
                advances_goal_ids=("g-prove",),
                depends_on=("s-explore",),
                relation="visited",
                mode="PROVE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-explore", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
            route_mode="EXPLORE",
        ),
        ProviderOperation(
            "op-prove", "mock", ("scope",),
            input_entity_kinds=("process",),
            output_entity_kinds=("domain",),
            output_value_bindings={"object": ("site",)},
            route_mode="PROVE",
            proof_contract_id="proof-web-visit-v1",
            proof_mode="relation_observable",
        ),
    )
    state, adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op-explore": [{"image": "/bin/sh"}], "op-prove": [{"site": "example.test"}]},
    )
    assert "op-explore" in adapter.calls
    assert "op-prove" not in adapter.calls
    assert "s-prove" in state.semantic_analysis["unresolved_reasons"]
    assert "verified bindings" in state.semantic_analysis["unresolved_reasons"]["s-prove"]


def test_candidate_input_can_feed_explore_step() -> None:
    graph = SemanticGoalGraph(
        id="g-bind-explore",
        request_id="req-bind-explore",
        objective="explore adjacent values",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
            SemanticVariable("artifact", "artifact"),
        ],
        relations=[
            SemanticRelationGoal("g1", "host", "observed", "process", required=True),
            SemanticRelationGoal("g2", "process", "observed", "artifact", required=True),
        ],
    )
    plan = LogicalPlan(
        id="plan-bind-explore",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s1",
                operation_id="op1",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g1",),
                mode="EXPLORE",
            ),
            PlanStep(
                id="s2",
                operation_id="op2",
                input_bindings={"subject": "process"},
                output_bindings={"object": "artifact"},
                advances_goal_ids=("g2",),
                depends_on=("s1",),
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op1", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
        ),
        ProviderOperation(
            "op2", "mock", ("scope",),
            input_entity_kinds=("process",),
            output_entity_kinds=("artifact",),
            output_value_bindings={"object": ("name",)},
        ),
    )
    state, adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op1": [{"image": "/bin/sh"}], "op2": [{"name": "artifact-1"}]},
    )
    assert adapter.calls == ["op1", "op2"]
    assert "artifact-1" in state.candidate_sets["artifact"].candidates[0].value
    assert state.candidate_sets["artifact"].candidates[0].status == "CANDIDATE"


def test_user_selection_resumes_same_graph_with_immutable_provenance() -> None:
    graph = SemanticGoalGraph(
        id="g-resume",
        request_id="req-resume",
        objective="resume selected host",
        variables=[
            SemanticVariable("user", "person", "alice"),
            SemanticVariable("host", "host"),
            SemanticVariable("process", "process"),
        ],
        relations=[
            SemanticRelationGoal("g-host", "user", "observed", "host", required=True),
            SemanticRelationGoal("g-proc", "host", "observed", "process", required=True),
        ],
    )
    plan = LogicalPlan(
        id="plan-resume",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s-host",
                operation_id="op-host",
                input_bindings={"subject": "user"},
                output_bindings={"object": "host"},
                advances_goal_ids=("g-host",),
                mode="EXPLORE",
            ),
            PlanStep(
                id="s-proc",
                operation_id="op-proc",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-proc",),
                depends_on=("s-host",),
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-host", "mock", ("scope",),
            input_entity_kinds=("person",),
            output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)},
        ),
        ProviderOperation(
            "op-proc", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
        ),
    )
    state, adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op-host": [{"host": "h-1"}, {"host": "h-2"}], "op-proc": [{"image": "/bin/sh"}]},
        outcome_contract=FactualAnswerContract(slots=("host",), cardinality={"host": "singular"}),
        initial_bindings={"host": "h-1"},
    )
    assert state.semantic_goal_graph.id == "g-resume"
    assert state.semantic_goal_graph.graph_revision == "G0"
    assert adapter.calls == ["op-proc"]
    provenance = state.semantic_analysis["binding_provenance"]["host"]
    assert any(item["source"] == "user_selection" and item["value"] == "h-1" for item in provenance)


def test_discriminate_step_without_declared_fields_does_not_run() -> None:
    graph = SemanticGoalGraph(
        id="g-disc",
        request_id="req-disc",
        objective="discriminate hosts",
        variables=[
            SemanticVariable("user", "person", "alice"),
            SemanticVariable("host", "host"),
        ],
        relations=[SemanticRelationGoal("g1", "user", "observed", "host", required=True)],
    )
    plan = LogicalPlan(
        id="plan-disc",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s-disc",
                operation_id="op-disc",
                input_bindings={"subject": "user"},
                output_bindings={"object": "host"},
                advances_goal_ids=("g1",),
                mode="DISCRIMINATE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-disc", "mock", ("scope",),
            input_entity_kinds=("person",),
            output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)},
            route_mode="DISCRIMINATE",
        ),
    )
    state, adapter = _run_plan(graph=graph, plan=plan, operations=operations, rows_by_op={"op-disc": [{"host": "h-1"}]})
    assert adapter.calls == []
    assert "declared differentiating evidence" in state.semantic_analysis["unresolved_reasons"]["s-disc"]


def test_factual_vertical_slice_proves_one_cited_value() -> None:
    graph = SemanticGoalGraph(
        id="g-fact",
        request_id="req-fact",
        objective="prove one cited domain",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("domain", "domain"),
        ],
        relations=[SemanticRelationGoal("g-visit", "host", "visited", "domain", required=True)],
        answers=[SemanticAnswerGoal("domain", "domain")],
    )
    plan = LogicalPlan(
        id="plan-fact",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s-prove",
                operation_id="op-visit",
                input_bindings={"subject": "host"},
                output_bindings={"object": "domain"},
                advances_goal_ids=("g-visit",),
                relation="visited",
                mode="PROVE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-visit", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("domain",),
            output_value_bindings={"object": ("site",)},
            guaranteed_relations=("visited",),
            proof_mode="relation_observable",
            proof_contract_id="proof-web-visit-v1",
            route_mode="PROVE",
        ),
    )
    contract = FactualAnswerContract(
        slots=("domain",),
        types={"domain": "domain"},
        cardinality={"domain": "singular"},
    )
    state, adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op-visit": [{"host": "HOST-1", "site": "cited.example", "http_method": "GET", "uri": "/"}]},
        outcome_contract=contract,
    )
    assert adapter.calls == ["op-visit"]
    assert state.stopping_decision == StoppingDecision.STOP_ANSWERED
    proof = state.proof_results[0]
    assert proof.verified
    assert proof.object_binding == "cited.example"
    assert proof.citations
    assert state.semantic_logical_plan.goal_graph_id == graph.id
    assert state.semantic_analysis["executed_steps"] == ["s-prove"]
    assert state.semantic_analysis["goal_verdicts"][0]["status"] == "SUPPORTED"
    actions = state.semantic_analysis.get("step_actions", [])
    assert any(item.get("observation_class") == "VERIFIED" for item in actions)


def test_hypothesis_vertical_slice_preserves_verdicts() -> None:
    def _hyp_state(rows: list[dict[str, Any]], *, refute: bool = False) -> HuntState:
        goal_id = "g-clean" if refute else "g-support"
        graph = SemanticGoalGraph(
            id="g-hyp",
            request_id="req-hyp",
            objective="hypothesis verdict",
            variables=[
                SemanticVariable("host", "host", "HOST-1"),
                SemanticVariable("domain", "domain"),
            ],
            relations=[SemanticRelationGoal(goal_id, "host", "visited", "domain", required=True)],
        )
        plan = LogicalPlan(
            id="plan-hyp",
            goal_graph_id=graph.id,
            provider_id="mock",
            steps=[
                PlanStep(
                    id="s1",
                    operation_id="op-visit",
                    input_bindings={"subject": "host"},
                    output_bindings={"object": "domain"},
                    advances_goal_ids=(goal_id,),
                    relation="visited",
                    mode="PROVE",
                ),
            ],
        )
        operations = (
            ProviderOperation(
                "op-visit", "mock", ("scope",),
                input_entity_kinds=("host",),
                output_entity_kinds=("domain",),
                output_value_bindings={"object": ("site",)},
                guaranteed_relations=("visited",),
                proof_mode="relation_observable",
                proof_contract_id="proof-web-visit-v1",
                route_mode="PROVE",
            ),
        )
        contract = HypothesisVerdictContract(
            support_obligations=("g-support",),
            refutation_obligations=("g-clean",),
        )
        state, _adapter = _run_plan(
            graph=graph,
            plan=plan,
            operations=operations,
            rows_by_op={"op-visit": rows},
            outcome_contract=contract,
        )
        return state

    supported = _hyp_state([{"host": "HOST-1", "site": "cited.example", "http_method": "GET", "uri": "/"}])
    assert supported.semantic_analysis["goal_verdicts"][0]["status"] == "SUPPORTED"
    assert supported.stopping_decision == StoppingDecision.STOP_ANSWERED

    refuted = _hyp_state(
        [{"host": "HOST-1", "site": "cited.example", "http_method": "GET", "uri": "/"}],
        refute=True,
    )
    assert refuted.semantic_analysis["goal_verdicts"][0]["status"] == "SUPPORTED"
    assert refuted.stopping_decision == StoppingDecision.STOP_ANSWERED

    inconclusive = _hyp_state([{"bogus": "no-roles"}])
    assert inconclusive.semantic_analysis["goal_verdicts"][0]["status"] != "SUPPORTED"
    assert inconclusive.stopping_decision != StoppingDecision.STOP_ANSWERED


def test_population_vertical_slice_preserves_plural_prevalence() -> None:
    graph = SemanticGoalGraph(
        id="g-pop",
        request_id="req-pop",
        objective="enumerate processes",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
        ],
        relations=[SemanticRelationGoal("g-obs", "host", "observed", "process", required=True)],
        answers=[SemanticAnswerGoal("process", "process")],
    )
    plan = LogicalPlan(
        id="plan-pop",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s-pop",
                operation_id="op-pop",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-obs",),
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-pop", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
            route_mode="EXPLORE",
        ),
    )
    contract = PopulationDiscoveryContract(
        population_unit="process",
        candidate_schema={"process": "process"},
        prevalence_aggregation="count",
        coverage_requirement="BOUNDED",
    )
    state, adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op-pop": [{"image": "/bin/a"}, {"image": "/bin/b"}, {"image": "/bin/c"}]},
        outcome_contract=contract,
    )
    assert adapter.calls == ["op-pop"]
    cset = state.candidate_sets["process"]
    assert cset.cardinality == "plural"
    assert [c.value for c in cset.candidates] == ["/bin/a", "/bin/b", "/bin/c"]
    assert all(c.status == "CANDIDATE" for c in cset.candidates)
    assert cset.selected_binding is None
    assert not cset.is_ambiguous
    analysis_next = next(
        item for item in state.semantic_analysis["executed_steps"]
    )
    assert analysis_next == "s-pop"
    # First-row coercion must not replace the population.
    assert isinstance(state.semantic_analysis.get("binding_provenance", {}).get("process"), list)


def test_discovery_remains_useful_without_proof() -> None:
    graph = SemanticGoalGraph(
        id="g-disc-useful",
        request_id="req-disc-useful",
        objective="explore without a proof contract",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
        ],
        relations=[SemanticRelationGoal("g-obs", "host", "unregistered action", "process", required=True)],
        answers=[SemanticAnswerGoal("process", "process")],
    )
    plan = LogicalPlan(
        id="plan-disc-useful",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s-exp",
                operation_id="op-exp",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-obs",),
                relation="unregistered action",
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-exp", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
            route_mode="EXPLORE",
        ),
    )
    state, adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op-exp": [{"image": "/bin/sh"}]},
        outcome_contract=FactualAnswerContract(slots=("process",), cardinality={"process": "singular"}),
    )
    assert adapter.calls == ["op-exp"]
    assert state.stopping_decision != StoppingDecision.STOP_ANSWERED
    assert state.candidate_sets["process"].candidates[0].status == "CANDIDATE"
    assert state.candidate_sets["process"].candidates[0].value == "/bin/sh"
    assert all(not getattr(pr, "verified", False) for pr in state.proof_results)


def test_adjacent_explore_does_not_mutate_accepted_obligations() -> None:
    graph = SemanticGoalGraph(
        id="g-adj",
        request_id="req-adj",
        objective="adjacent explore",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
        ],
        relations=[SemanticRelationGoal("g-obs", "host", "observed", "process", required=True)],
    )
    plan = LogicalPlan(
        id="plan-adj",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s1",
                operation_id="op1",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-obs",),
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op1", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
        ),
    )
    state, _adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op1": [{"image": "/bin/sh"}]},
    )
    assert [(rel.id, rel.relation, rel.required) for rel in state.semantic_goal_graph.relations] == [
        ("g-obs", "observed", True)
    ]
    assert state.semantic_goal_graph.graph_revision == "G0"


def test_material_graph_change_requires_accept_graph_revision() -> None:
    current = SemanticGoalGraph(
        id="g-rev",
        request_id="req-rev",
        objective="keep obligations",
        variables=[SemanticVariable("host", "host", "HOST-1"), SemanticVariable("process", "process")],
        relations=[SemanticRelationGoal("g-obs", "host", "observed", "process", required=True)],
    )
    proposed = current.propose_expansion(
        intermediate_variables=[SemanticVariable("artifact", "artifact")],
        intermediate_relations=[
            SemanticRelationGoal("g-adj", "process", "observed", "artifact", required=False),
        ],
        reason="adjacent typed route",
    )
    accepted = accept_graph_revision(current, proposed)
    assert accepted.graph_revision == "G1"
    assert [rel.id for rel in accepted.relations] == ["g-obs", "g-adj"]

    dropped = SemanticGoalGraph(
        id=current.id,
        request_id=current.request_id,
        objective=current.objective,
        variables=list(current.variables),
        relations=[],
        graph_revision="G1",
        revision_history=({"from_revision": "G0", "to_revision": "G1", "reason": "drop"},),
    )
    try:
        accept_graph_revision(current, dropped)
    except ValueError as exc:
        assert "dropped accepted obligation" in str(exc)
    else:
        raise AssertionError("accept_graph_revision must reject dropped obligations")


def test_explore_attempt_records_candidate_action_on_engine_path() -> None:
    graph = SemanticGoalGraph(
        id="g-rec",
        request_id="req-rec",
        objective="record explore action",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
        ],
        relations=[SemanticRelationGoal("g-obs", "host", "observed", "process", required=True)],
    )
    plan = LogicalPlan(
        id="plan-rec",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s1",
                operation_id="op1",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-obs",),
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op1", "mock", ("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("process",),
            output_value_bindings={"object": ("image",)},
        ),
    )
    state, _adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op1": [{"image": "/bin/sh"}]},
    )
    # The production triad writes next_action_reason onto the executed step.
    # Recover it from semantic analysis route/attempt records when present.
    actions = state.semantic_analysis.get("step_actions", [])
    assert actions
    assert any("candidate" in str(item.get("next_action_reason", "")).casefold() for item in actions)
    assert state.candidate_sets["process"].candidates
    assert state.stopping_decision != StoppingDecision.STOP_ANSWERED


def test_first_row_is_not_a_verified_singular_bind() -> None:
    graph = SemanticGoalGraph(
        id="g-first",
        request_id="req-first",
        objective="two hosts stay candidates",
        variables=[
            SemanticVariable("user", "person", "alice"),
            SemanticVariable("host", "host"),
        ],
        relations=[SemanticRelationGoal("g-host", "user", "observed", "host", required=True)],
    )
    plan = LogicalPlan(
        id="plan-first",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s1",
                operation_id="op-host",
                input_bindings={"subject": "user"},
                output_bindings={"object": "host"},
                advances_goal_ids=("g-host",),
                mode="EXPLORE",
            ),
        ],
    )
    operations = (
        ProviderOperation(
            "op-host", "mock", ("scope",),
            input_entity_kinds=("person",),
            output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)},
        ),
    )
    state, _adapter = _run_plan(
        graph=graph,
        plan=plan,
        operations=operations,
        rows_by_op={"op-host": [{"host": "h-1"}, {"host": "h-2"}]},
        outcome_contract=FactualAnswerContract(slots=("host",), cardinality={"host": "singular"}),
    )
    cset = state.candidate_sets.get("host")
    if cset is None:
        assert state.semantic_analysis.get("needs_user_decision")
        return
    assert cset.selected_binding is None
    assert all(c.status != "VERIFIED_BINDING" for c in cset.candidates)
    assert state.stopping_decision != StoppingDecision.STOP_ANSWERED
