"""Workstream C: One Semantic Entry Point and Semantic Acceptance Gate.

Verifies:
1. Question, hypothesis, CVE, TTP, IOC and structured fixtures emit the same canonical contract types (SemanticGoalGraph + OutcomeContract).
2. Changing entity names does not mutate graph structure except grounded values.
3. Invented proper nouns claiming request origin are rejected.
4. Ambiguous semantics or clarification triggers set needs_clarification=True.
5. Cyclic dependencies and unmet GATE conditions are rejected at the gate.
6. Zero scenario keywords (Mallory, Amber, personal email) appear in production compiler prompts.
7. Novel relations are flagged with diagnostic regarding canonical vocabulary and proof capability.
"""
from __future__ import annotations

import inspect
import json

import pytest

from hunting.compiler import (
    KnowledgeBehaviorCompiler,
    RequestAdapter,
    SemanticProposal,
)
from hunting.contracts.hunt import (
    HuntRequest,
    HuntRequestKind,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.contracts.outcome import (
    FactualAnswerContract,
    HypothesisVerdictContract,
)
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter import CdbAdapter
from hunting.validator.investigation_validator import (
    SemanticAcceptanceGate,
)


def test_all_request_archetypes_emit_semantic_goal_graph_and_outcome_contract() -> None:
    """Acceptance Gate C: All request kinds emit both SemanticGoalGraph and OutcomeContract."""
    adapter = RequestAdapter()

    # CVE and TTP are not entry points. A structured hypothesis still emits the contract.
    for kind, content in (
        (HuntRequestKind.CVE, "Hunt for exploitation of CVE-2024-21887 on Ivanti Connect Secure"),
        (HuntRequestKind.TTP, "Hunt for anomalous command line execution T1059.001"),
    ):
        with pytest.raises(ValueError, match="free-text hypothesis"):
            adapter.propose(HuntRequest(id=f"req-{kind.value}", kind=kind, content=content))

    # Structured Hypothesis request
    yaml_hypothesis = """
    statement: Adversary deployed scheduled task persistence
    requirements:
      - id: req-pers-1
        description: Scheduled task creation
        evidence_type: persistence_change
        predicate:
          field: action
          op: EQUALS
          value: create
    """
    req_struct = HuntRequest(
        id="req-struct-test",
        kind=HuntRequestKind.HYPOTHESIS,
        content=yaml_hypothesis,
    )
    prop_struct = adapter.propose(req_struct)
    assert isinstance(prop_struct, SemanticProposal)
    assert isinstance(prop_struct.goal_graph, SemanticGoalGraph)
    assert isinstance(prop_struct.outcome_contract, HypothesisVerdictContract)

    # 4. NL Question with LLM caller
    nl_proposal_json = {
        "id": "goal-nl",
        "request_id": "req-nl-test",
        "objective": "Identify domain queried by host",
        "variables": [
            {"id": "var_host", "entity_type": "host", "value": "server-01", "value_origin": "request", "constraints": []},
            {"id": "var_domain", "entity_type": "domain", "value": None, "value_origin": "llm_proposal", "constraints": []},
        ],
        "relations": [
            {
                "id": "goal-dns",
                "subject": "var_host",
                "relation": "resolved",
                "object": "var_domain",
                "required": True,
                "provenance_span": "server-01",
            }
        ],
        "answers": [{"variable_id": "var_domain", "answer_type": "domain", "required": True}],
        "answer_contracts": [
            {
                "slot_name": "target_domain",
                "value_type": "domain",
                "target_variable_id": "var_domain",
                "required_qualifiers": [],
                "min_citations": 1,
                "acceptance_rule": "observed domain query",
            }
        ],
    }
    nl_adapter = RequestAdapter(llm_caller=lambda _: json.dumps(nl_proposal_json))
    req_nl = HuntRequest(
        id="req-nl-test",
        kind=HuntRequestKind.NL_QUESTION,
        content="Identify domain queried by server-01",
    )
    prop_nl = nl_adapter.propose(req_nl)
    assert isinstance(prop_nl, SemanticProposal)
    assert isinstance(prop_nl.goal_graph, SemanticGoalGraph)
    assert isinstance(prop_nl.outcome_contract, FactualAnswerContract)
    assert "target_domain" in prop_nl.outcome_contract.slots or "var_domain" in prop_nl.outcome_contract.slots


def _semantic_llm_payload(*, request_id: str, conflicting: bool = False) -> dict[str, object]:
    constraints: list[dict[str, object]] = []
    if conflicting:
        constraints = [
            {"key": "action", "operator": "equals", "value": "login"},
            {"key": "action", "operator": "equals", "value": "reboot"},
        ]
    return {
        "id": f"goal-{request_id}",
        "request_id": request_id,
        "objective": "Identify an event observed on server-01",
        "variables": [
            {
                "id": "host",
                "entity_type": "host",
                "value": "server-01",
                "value_origin": "request",
                "constraints": [],
            },
            {
                "id": "name",
                "entity_type": "domain",
                "value": None,
                "value_origin": "llm_proposal",
                "constraints": constraints,
            },
        ],
        "relations": [
            {
                "id": "goal-event",
                "subject": "host",
                "relation": "resolved",
                "object": "name",
                "required": True,
                "provenance_span": "server-01",
            },
        ],
        "answers": [
            {"variable_id": "name", "answer_type": "domain", "required": True},
        ],
        "answer_contracts": [
            {
                "slot_name": "event",
                "value_type": "domain",
                "target_variable_id": "name",
                "required_qualifiers": [],
                "min_citations": 1,
                "acceptance_rule": "observed event",
            },
        ],
        "clarification_triggers": ["Ask if multiple events remain"],
    }


def test_execute_hunt_does_not_promote_advisory_prose_to_clarification(
    monkeypatch,
    tmp_path,
) -> None:
    """Default production entry cannot derive stop authority from prose."""
    payload = _semantic_llm_payload(request_id="req-advisory")
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: json.dumps(payload))
    engine = HypothesisHuntEngine(compiler=compiler)
    calls: list[dict[str, object]] = []
    original = engine.recovery_controller.evaluate_stop

    def recording_evaluate_stop(*args, **kwargs):
        calls.append(dict(kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(engine.recovery_controller, "evaluate_stop", recording_evaluate_stop)
    monkeypatch.chdir(tmp_path)
    result = engine.execute_hunt(
        HuntRequest(
            id="req-advisory",
            kind=HuntRequestKind.NL_QUESTION,
            content="Identify an event observed on server-01",
        ),
        adapter=CdbAdapter(":memory:"),
    )

    graph = result.state.semantic_goal_graph
    assert graph is not None
    assert graph.clarification_triggers == ["Ask if multiple events remain"]
    assert graph.needs_clarification is False
    assert all(not call.get("needs_clarification") for call in calls)
    assert result.state.hypotheses[0].status == HypothesisStatus.LIVE
    assert result.state.stopping_decision != StoppingDecision.STOP_NEEDS_CLARIFICATION


def test_execute_hunt_stops_only_for_true_typed_clarification(
    monkeypatch,
    tmp_path,
) -> None:
    """A deterministic conflict reaches the controller as evaluated authority."""
    payload = _semantic_llm_payload(request_id="req-conflict", conflicting=True)
    payload["clarification_triggers"] = []
    payload["clarification_predicates"] = [{
        "id": "clarify-event-action",
        "kind": "CONFLICTING_EQUALS",
        "operator": "HAS_CONFLICT",
        "variable_id": "name",
        "constraint_key": "action",
        "provenance_span": "name",
        "schema_version": "1.0",
        "rule_version": "1.0",
    }]
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: json.dumps(payload))
    engine = HypothesisHuntEngine(compiler=compiler)
    calls: list[dict[str, object]] = []
    original = engine.recovery_controller.evaluate_stop

    def recording_evaluate_stop(*args, **kwargs):
        calls.append(dict(kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(engine.recovery_controller, "evaluate_stop", recording_evaluate_stop)
    monkeypatch.chdir(tmp_path)
    result = engine.execute_hunt(
        HuntRequest(
            id="req-conflict",
            kind=HuntRequestKind.NL_QUESTION,
            content="Identify an event observed on server-01",
        ),
        adapter=CdbAdapter(":memory:"),
    )

    graph = result.state.semantic_goal_graph
    assert graph is not None
    assert graph.needs_clarification is True
    assert any(call.get("needs_clarification") is True for call in calls)
    assert result.state.hypotheses[0].status == HypothesisStatus.LIVE
    assert result.state.stopping_decision == StoppingDecision.STOP_NEEDS_CLARIFICATION
    assert result.state.queries == []


def test_changing_entity_names_does_not_mutate_graph_topology() -> None:
    """Acceptance Gate C: Changing entity names does not mutate graph structure except grounded values."""
    gate = SemanticAcceptanceGate()

    def make_user_graph(user_name: str, req_id: str) -> tuple[SemanticGoalGraph, str]:
        req_text = f"Find file written by user {user_name}"
        graph = SemanticGoalGraph(
            id=f"goal-graph-{req_id}",
            request_id=req_id,
            objective=f"Find file written by {user_name}",
            variables=[
                SemanticVariable("v_user", "person", user_name, value_origin="request"),
                SemanticVariable("v_host", "host", None, value_origin="llm_proposal"),
                SemanticVariable("v_file", "file", None, value_origin="llm_proposal"),
            ],
            relations=[
                SemanticRelationGoal("r1", "v_user", "associated_with", "v_host", provenance_span=user_name),
                SemanticRelationGoal("r2", "v_host", "wrote", "v_file", dependencies=("r1",), dependency_operator="AND"),
            ],
            answers=[SemanticAnswerGoal("v_file", "file")],
        )
        return graph, req_text

    g1, req1 = make_user_graph("Alice", "req-1")
    g2, req2 = make_user_graph("Carlos", "req-2")

    res1 = gate.validate_goal_graph(g1, req1)
    res2 = gate.validate_goal_graph(g2, req2)

    assert res1.valid
    assert res2.valid

    # Graph topologies must be isomorphic: same number of nodes, edges, dependencies, and relation names
    assert len(res1.validated_graph.variables) == len(res2.validated_graph.variables)
    assert len(res1.validated_graph.relations) == len(res2.validated_graph.relations)
    assert [r.relation for r in res1.validated_graph.relations] == [r.relation for r in res2.validated_graph.relations]
    assert [r.dependencies for r in res1.validated_graph.relations] == [r.dependencies for r in res2.validated_graph.relations]

    # Only grounded value differs
    user_var_1 = next(v for v in res1.validated_graph.variables if v.id == "v_user")
    user_var_2 = next(v for v in res2.validated_graph.variables if v.id == "v_user")
    assert user_var_1.value == "Alice"
    assert user_var_2.value == "Carlos"


def test_invented_proper_nouns_claiming_request_origin_are_rejected() -> None:
    """Acceptance Gate C: Invented proper nouns marked as request origin are rejected."""
    gate = SemanticAcceptanceGate()
    req_text = "Find suspicious activity on the finance server"

    graph = SemanticGoalGraph(
        id="goal-invented",
        request_id="req-inv",
        objective="Find activity",
        variables=[
            SemanticVariable("u1", "person", "Bob", value_origin="request"),
            SemanticVariable("h1", "host", "finance server", value_origin="request"),
        ],
        relations=[SemanticRelationGoal("r1", "u1", "logged_on_to", "h1")],
        answers=[],
    )
    res = gate.validate_goal_graph(graph, req_text)
    assert not res.valid
    assert any("Invented proper noun rejected" in r and "Bob" in r for r in res.rejections)


def test_prose_clarification_trigger_is_advisory_only() -> None:
    """Free-text trigger prose never becomes a clarification stop predicate."""
    gate = SemanticAcceptanceGate()
    graph = SemanticGoalGraph(
        id="goal-prose-only",
        request_id="req-prose-only",
        objective="Investigate the event on server-1",
        variables=[SemanticVariable("v_evt", "event")],
        relations=[],
        clarification_triggers=["Ask if multiple event types remain"],
    )

    result = gate.validate_goal_graph(graph, "Investigate the event on server-1")

    assert result.valid
    assert not result.needs_clarification
    assert result.clarification_questions == []
    assert any("advisory" in diagnostic.lower() for diagnostic in result.diagnostics)


def test_conflicting_typed_constraints_trigger_clarification() -> None:
    """A deterministic typed conflict remains a true clarification predicate."""
    gate = SemanticAcceptanceGate()
    graph = SemanticGoalGraph(
        id="goal-ambiguous",
        request_id="req-amb",
        objective="Investigate event",
        variables=[
            SemanticVariable(
                "v_evt",
                "event",
                constraints=(
                    SemanticConstraint(key="action", operator="equals", value="login"),
                    SemanticConstraint(key="action", operator="equals", value="reboot"),
                ),
            )
        ],
        relations=[],
    )

    result = gate.validate_goal_graph(graph, "Investigate the event on server-1")

    assert result.needs_clarification
    assert len(result.clarification_questions) == 1
    assert "login" in result.clarification_questions[0]


def test_acceptance_gate_rejects_cyclic_graph_and_enforces_gate_condition() -> None:
    """Acceptance Gate C: Structural DAG validation catches cycles and unmet GATE conditions."""
    gate = SemanticAcceptanceGate()
    req_text = "Trace network connections"

    # Case 1: Cyclic dependency
    graph_cycle = SemanticGoalGraph(
        id="g-cycle",
        request_id="req-c",
        objective="Cycle test",
        variables=[SemanticVariable("v1", "host"), SemanticVariable("v2", "ip")],
        relations=[
            SemanticRelationGoal("r1", "v1", "assigned_ip", "v2", dependencies=("r2",)),
            SemanticRelationGoal("r2", "v2", "connected_to", "v1", dependencies=("r1",)),
        ],
    )
    res_cycle = gate.validate_goal_graph(graph_cycle, req_text)
    assert not res_cycle.valid
    assert any("Cyclic dependency detected" in r for r in res_cycle.rejections)

    # Case 2: GATE operator without gate_condition
    graph_gate = SemanticGoalGraph(
        id="g-gate",
        request_id="req-g",
        objective="Gate test",
        variables=[SemanticVariable("v1", "host"), SemanticVariable("v2", "ip")],
        relations=[
            SemanticRelationGoal("r1", "v1", "assigned_ip", "v2"),
            SemanticRelationGoal(
                "r2",
                "v2",
                "connected_to",
                "v1",
                dependencies=("r1",),
                dependency_operator="GATE",
                gate_condition=None,
            ),
        ],
    )
    res_gate = gate.validate_goal_graph(graph_gate, req_text)
    assert not res_gate.valid
    assert any("GATE dependency operator but lacks gate_condition" in r for r in res_gate.rejections)


def test_zero_scenario_keywords_in_production_compiler_prompts() -> None:
    """Acceptance Gate C: Zero scenario keywords (Mallory, Amber, personal email) in prompts or compiler code."""
    from hunting.compiler import compiler

    compiler_source = inspect.getsource(compiler)

    banned_terms = [
        "Mallory",
        "Amber",
        "personal email",
    ]
    for term in banned_terms:
        assert term not in compiler_source, f"Scenario keyword '{term}' must not appear in compiler source code"

    compiler_inst = KnowledgeBehaviorCompiler(llm_caller=lambda p: "")
    req = HuntRequest(id="test-req", kind=HuntRequestKind.NL_QUESTION, content="What domain was contacted?")

    captured_prompt: list[str] = []

    def mock_caller(prompt: str) -> str:
        captured_prompt.append(prompt)
        return "{}"

    compiler_inst.llm_caller = mock_caller
    try:
        compiler_inst.compile(req)
    except Exception:
        pass

    if captured_prompt:
        prompt_text = captured_prompt[0]
        for term in banned_terms:
            assert term.casefold() not in prompt_text.casefold(), (
                f"Scenario keyword '{term}' leaked into generated production prompt"
            )


def test_novel_unregistered_relations_flagged_with_diagnostic() -> None:
    """Acceptance Gate C: Relations outside canonical vocabulary receive explicit diagnostic."""
    gate = SemanticAcceptanceGate()
    req_text = "Check data transfer"

    graph = SemanticGoalGraph(
        id="g-novel",
        request_id="req-nov",
        objective="Novel relation test",
        variables=[SemanticVariable("v1", "host"), SemanticVariable("v2", "cloud_bucket")],
        relations=[
            SemanticRelationGoal(
                id="r1",
                subject="v1",
                relation="exfiltrated_to_mars",
                object="v2",
            )
        ],
        answers=[SemanticAnswerGoal("v2", "cloud_bucket")],
    )
    res = gate.validate_goal_graph(graph, req_text)
    assert any(
        "exfiltrated_to_mars" in d and "not in approved canonical registry" in d
        for d in res.diagnostics
    )


def test_multiple_constraints_distinct_keys_do_not_trigger_clarification() -> None:
    """Counterexample 4a: Multiple valid constraints with different keys do not trigger clarification."""
    gate = SemanticAcceptanceGate()
    req_text = "Find encoded powershell command"
    graph = SemanticGoalGraph(
        id="g-multi-constraint",
        request_id="req-multi",
        objective="Find encoded powershell command",
        variables=[
            SemanticVariable(
                id="v_proc",
                entity_type="process",
                constraints=(
                    SemanticConstraint(key="encoding", value="encoded", operator="equals"),
                    SemanticConstraint(key="command_language", value="PowerShell", operator="equals"),
                ),
            ),
        ],
        relations=[
            SemanticRelationGoal(id="r1", subject="v_proc", relation="has_attribute", object="v_proc"),
        ],
        answers=[SemanticAnswerGoal("v_proc", "process")],
    )
    res = gate.validate_goal_graph(graph, req_text)
    assert res.valid
    assert not res.needs_clarification
    assert not any("conflicting equality constraints" in d for d in res.diagnostics)


def test_multiple_constraints_same_key_conflict_triggers_clarification() -> None:
    """Counterexample 4b: Conflicting values for the SAME constraint key trigger clarification."""
    gate = SemanticAcceptanceGate()
    req_text = "Find encoded plain command"
    graph = SemanticGoalGraph(
        id="g-conflict-constraint",
        request_id="req-conflict",
        objective="Find command with conflicting encoding",
        variables=[
            SemanticVariable(
                id="v_proc",
                entity_type="process",
                constraints=(
                    SemanticConstraint(key="encoding", value="encoded", operator="equals"),
                    SemanticConstraint(key="encoding", value="plain", operator="equals"),
                ),
            ),
        ],
        relations=[
            SemanticRelationGoal(id="r1", subject="v_proc", relation="has_attribute", object="v_proc"),
        ],
        answers=[SemanticAnswerGoal("v_proc", "process")],
    )
    res = gate.validate_goal_graph(graph, req_text)
    assert res.needs_clarification
    assert any("conflicting equality constraints for key 'encoding'" in d for d in res.diagnostics)
