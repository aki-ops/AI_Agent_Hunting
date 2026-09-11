"""Unit tests verifying fail-fast behavior on LLM timeouts and prevention of fabricated reports."""
from unittest.mock import MagicMock

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import (
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.controller.cost import LLMUsageTracker
from hunting.engine import HypothesisHuntEngine
from hunting.m2_abduction.provider import (
    LLMTimeoutError,
    create_llm_caller,
)
from hunting.reporter.builder import build_final_hunt_account


def test_create_llm_caller_raises_timeout_error():
    """Verify create_llm_caller immediately raises LLMTimeoutError instead of returning empty JSON."""
    mock_provider = MagicMock()
    mock_provider.call_raw.side_effect = LLMTimeoutError("LLM API request timed out after 30s")
    tracker = LLMUsageTracker()

    caller = create_llm_caller(mock_provider, tracker=tracker, component="compiler")
    with pytest.raises(LLMTimeoutError, match="timed out"):
        caller("Test prompt")


def test_compiler_raises_on_llm_timeout():
    """Verify compiler.compile() raises LLMTimeoutError when LLM caller times out."""
    def timeout_caller(prompt: str) -> str:
        raise LLMTimeoutError("Read timed out from gateway")

    compiler = KnowledgeBehaviorCompiler(llm_caller=timeout_caller)
    req = HuntRequest(
        id="hunt-timeout-test",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker exploited web application on www.example.com",
    )

    with pytest.raises(LLMTimeoutError, match="timed out"):
        compiler.compile(req)


def test_engine_raises_on_llm_timeout():
    """Verify HypothesisHuntEngine.execute_hunt() raises on LLM timeout and aborts."""
    def timeout_caller(prompt: str) -> str:
        raise LLMTimeoutError("Socket connection timed out after 120s")

    compiler = KnowledgeBehaviorCompiler(llm_caller=timeout_caller)
    engine = HypothesisHuntEngine(compiler=compiler)

    req = HuntRequest(
        id="hunt-engine-timeout",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Free text hypothesis requiring LLM compilation",
    )

    with pytest.raises(LLMTimeoutError, match="timed out"):
        engine.execute_hunt(req)


def test_builder_never_claims_not_found_when_no_queries_run():
    """Verify builder refuses to claim NOT_FOUND in telemetry when execution was halted before search."""
    obj = HuntObjective(
        request_id="req-halted",
        statement="What is the domain that was visited?",
        answer_spec={"mode": "lookup", "answer_type": "domain"},
    )
    state = HuntState(
        objective=obj,
        hypotheses=[
            Hypothesis(
                id="h1",
                statement="Insufficient hypothesis",
                status=HypothesisStatus.INSUFFICIENTLY_SPECIFIED,
            )
        ],
        requirements=[],
        stopping_decision=StoppingDecision.STOP_INSUFFICIENT,
    )

    account = build_final_hunt_account(state)
    assert account.answer.get("status") != "NOT_FOUND"
    assert account.answer.get("status") == "INCONCLUSIVE"
    assert account.answer.get("reason") in ("EXECUTION_HALTED_BEFORE_SEARCH", "NO_VERIFIED_ANSWER_CANDIDATE")
