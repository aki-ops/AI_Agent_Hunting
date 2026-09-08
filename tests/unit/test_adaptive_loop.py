"""Tests for Phase A: Adaptive loop, bounded iteration, and fallback."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, HuntRequest, HuntRequestKind
from hunting.contracts.hunt_spec import Anchor, AnswerContract, HuntSpec, SearchTerm
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticHuntIntent,
    SubjectEntity,
)
from hunting.engine import HypothesisHuntEngine
from hunting.planner.adaptive import AdaptiveDecision, AdaptiveOperationPlanner


def test_adaptive_decision_properties_and_to_dict():
    decision = AdaptiveDecision(
        operation_id="inventory_search",
        reason="Testing reason",
        required_fields=("ProductVersion",),
        ready_for_answer=False,
        search_terms=("Tor Browser",),
    )
    assert decision.operation == "inventory_search"
    assert decision.operation_id == "inventory_search"
    assert decision.search_terms == ("Tor Browser",)
    assert decision.required_fields == ("ProductVersion",)
    d = decision.to_dict()
    assert d["operation"] == "inventory_search"
    assert d["operation_id"] == "inventory_search"
    assert d["search_terms"] == ["Tor Browser"]
    assert d["required_fields"] == ["ProductVersion"]
    assert d["ready_for_answer"] is False


def test_adaptive_planner_respects_attempted_operations():
    spec = HuntSpec(
        question="Find version",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="op1", semantic_intents=("software_version",)),
        SimpleNamespace(id="op2", semantic_intents=("software_version",)),
        SimpleNamespace(id="search_text"),
    ))
    planner = AdaptiveOperationPlanner()

    # Iteration 1: chooses op1
    d1 = planner.choose(spec, descriptor, attempted_operations=[])
    assert d1.operation_id == "op1"

    # Iteration 2: op1 was attempted, chooses op2
    d2 = planner.choose(spec, descriptor, attempted_operations=["op1"])
    assert d2.operation_id == "op2"

    # Iteration 3: both attempted, falls back to search_text
    d3 = planner.choose(spec, descriptor, attempted_operations=["op1", "op2"])
    assert d3.operation_id == "search_text"

    # Iteration 4: all attempted, reports no more operations
    d4 = planner.choose(spec, descriptor, attempted_operations=["op1", "op2", "search_text"])
    assert d4.operation_id is None
    assert d4.ready_for_answer is False


def test_engine_adaptive_loop_bounded_to_two_iterations():
    """Engine executes at most 2 adaptive loop iterations if required fields are missing."""
    engine = HypothesisHuntEngine()

    scope = ProviderScope(provider_id="mock_splunk", scope_id="main", native_partition={"index": "test"})
    adapter = MagicMock()
    adapter.scope = scope
    adapter.provider_id = "splunk"
    adapter.get_capability_descriptor.return_value = SimpleNamespace(operations=(SimpleNamespace(id="search_text"),))

    descriptor = SimpleNamespace(
        operations=(
            SimpleNamespace(id="search_text"),
            SimpleNamespace(id="find_file_version", semantic_intents=("software_version",)),
            SimpleNamespace(id="find_process_version", semantic_intents=("software_version",)),
        )
    )
    adapter.get_versioned_descriptor.return_value = descriptor

    executed_ops: list[str] = []

    def mock_execute_query(**kwargs):
        op = kwargs.get("operation_id")
        executed_ops.append(op)
        if op == "search_text":
            return QueryResult(
                query_id=kwargs.get("query_id", "q1"),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                rows=[{"host": "wrk-amber", "user": "amber", "timestamp": "2026-09-02T10:00:00Z"}],
                complete=True,
            )
        elif op == "find_file_version":
            # Returns data without ProductVersion
            return QueryResult(
                query_id=kwargs.get("query_id", "q2"),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                rows=[{"host": "wrk-amber", "Path": r"C:\Tor\firefox.exe", "timestamp": "2026-09-02T10:05:00Z"}],
                complete=True,
            )
        elif op == "find_process_version":
            # Returns data still without ProductVersion
            return QueryResult(
                query_id=kwargs.get("query_id", "q3"),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                rows=[{"host": "wrk-amber", "Image": "firefox.exe", "timestamp": "2026-09-02T10:10:00Z"}],
                complete=True,
            )
        return QueryResult(query_id="q0", outcome=QueryOutcome.ROWS, executed_ok=True, rows=[], complete=True)

    adapter.execute_query.side_effect = mock_execute_query

    req = HuntRequest(
        id="test-adaptive-hunt",
        kind=HuntRequestKind.NL_QUESTION,
        content="What version of Tor was installed on wrk-amber?",
    )

    intent = SemanticHuntIntent(
        original_request=req.content,
        question=req.content,
        subject=SubjectEntity(type="host", value="wrk-amber"),
        requested_object=RequestedObject(type="software_version"),
        behavior="installed Tor",
    )

    # Force compiler to return our spec
    spec = HuntSpec(
        question=req.content,
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        anchors=[Anchor(value="wrk-amber", kind="host")],
        search_terms=[SearchTerm(value="Tor Browser")],
    )

    from hunting.contracts.hunt import EvidenceRequirementV4, Hypothesis
    hyp = Hypothesis(id="h1", statement="Tor installed", requirements=["r1"])
    req1 = EvidenceRequirementV4(id="r1", description="Tor version", evidence_type="file_modification")

    obj = HuntObjective(
        request_id=req.id,
        statement=req.content,
        time_window="2026-09-01T00:00:00Z/2026-09-08T00:00:00Z",
        semantic_intent=intent,
        answer_spec={"mode": "lookup", "answer_type": "software_version", "required_fields": ["ProductVersion"]},
        hunt_spec=spec,
    )
    engine.compiler.compile = MagicMock(return_value=(obj, [hyp], [req1]))

    result = engine.execute_hunt(req, adapter=adapter)

    # Check that adaptive queries were executed at most 2 times
    adaptive_ops = [op for op in executed_ops if op in ("find_file_version", "find_process_version")]
    assert len(adaptive_ops) == 2
    assert adaptive_ops == ["find_file_version", "find_process_version"]

    # Since ProductVersion was never returned in evidence rows, answer status must be PARTIAL, PARTIALLY_SUPPORTED, INCONCLUSIVE, or NOT_FOUND (never false ANSWERED)
    assert result.account.answer["status"] in ("PARTIAL", "PARTIALLY_SUPPORTED", "INCONCLUSIVE", "NOT_FOUND")


def test_engine_adaptive_loop_stops_early_when_evidence_found():
    """Engine stops adaptive loop early if a query returns the required fields."""
    engine = HypothesisHuntEngine()

    scope = ProviderScope(provider_id="mock_splunk", scope_id="main", native_partition={"index": "test"})
    adapter = MagicMock()
    adapter.scope = scope
    adapter.provider_id = "splunk"
    adapter.get_capability_descriptor.return_value = SimpleNamespace(operations=(SimpleNamespace(id="search_text"),))

    descriptor = SimpleNamespace(
        operations=(
            SimpleNamespace(id="search_text"),
            SimpleNamespace(id="find_file_version", semantic_intents=("software_version",)),
            SimpleNamespace(id="find_process_version", semantic_intents=("software_version",)),
        )
    )
    adapter.get_versioned_descriptor.return_value = descriptor

    executed_ops: list[str] = []

    def mock_execute_query(**kwargs):
        op = kwargs.get("operation_id")
        executed_ops.append(op)
        if op == "search_text":
            return QueryResult(
                query_id=kwargs.get("query_id", "q1"),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                rows=[{"host": "wrk-amber", "user": "amber", "timestamp": "2026-09-02T10:00:00Z"}],
                complete=True,
            )
        elif op == "find_file_version":
            # Returns data WITH ProductVersion on the first adaptive query
            return QueryResult(
                query_id=kwargs.get("query_id", "q2"),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                rows=[{"host": "wrk-amber", "Path": r"C:\Tor\firefox.exe", "ProductVersion": "13.5.2", "timestamp": "2026-09-02T10:05:00Z"}],
                complete=True,
            )
        elif op == "find_process_version":
            return QueryResult(
                query_id=kwargs.get("query_id", "q3"),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                rows=[{"host": "wrk-amber", "Image": "firefox.exe", "timestamp": "2026-09-02T10:10:00Z"}],
                complete=True,
            )
        return QueryResult(query_id="q0", outcome=QueryOutcome.ROWS, executed_ok=True, rows=[], complete=True)

    adapter.execute_query.side_effect = mock_execute_query

    req = HuntRequest(
        id="test-adaptive-hunt-success",
        kind=HuntRequestKind.NL_QUESTION,
        content="What version of Tor was installed on wrk-amber?",
    )

    intent = SemanticHuntIntent(
        original_request=req.content,
        question=req.content,
        subject=SubjectEntity(type="host", value="wrk-amber"),
        requested_object=RequestedObject(type="software_version"),
        behavior="installed Tor",
    )

    spec = HuntSpec(
        question=req.content,
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        anchors=[Anchor(value="wrk-amber", kind="host")],
        search_terms=[SearchTerm(value="Tor Browser")],
    )

    from hunting.contracts.hunt import EvidenceRequirementV4, Hypothesis
    hyp = Hypothesis(id="h1", statement="Tor installed", requirements=["r1"])
    req1 = EvidenceRequirementV4(id="r1", description="Tor version", evidence_type="file_modification")

    obj = HuntObjective(
        request_id=req.id,
        statement=req.content,
        time_window="2026-09-01T00:00:00Z/2026-09-08T00:00:00Z",
        semantic_intent=intent,
        answer_spec={"mode": "lookup", "answer_type": "software_version", "required_fields": ["ProductVersion"]},
        hunt_spec=spec,
    )
    engine.compiler.compile = MagicMock(return_value=(obj, [hyp], [req1]))

    result = engine.execute_hunt(req, adapter=adapter)

    # Must only execute find_file_version and NOT find_process_version because required field ProductVersion was found!
    adaptive_ops = [op for op in executed_ops if op in ("find_file_version", "find_process_version")]
    assert adaptive_ops == ["find_file_version"]
    assert result.account.answer["status"] == "ANSWERED"
    assert result.account.answer["value"] == "13.5.2"
