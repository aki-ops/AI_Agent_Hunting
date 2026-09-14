"""Tests for v9 Workstream H: LLM Scheduling, Token Economics, and Reservation Architecture.

Gate H Acceptance Criteria:
- CLI, tracker, SearchEnvelope, and HuntBudgetLedger read one authoritative LLMBudgetPolicy (zero drift).
- Every call has phase, reason, payload size, tokens, latency, and validation status.
- Optional source profiling cannot consume reserved proof/recovery capacity.
- Malformed or truncated output cannot mutate graph/state.
- Reports use actual provider usage when available and label estimates.
"""
from __future__ import annotations

import json

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    StoppingDecision,
)
from hunting.contracts.search_envelope import BudgetEnvelope
from hunting.controller.cost import (
    LLMBudgetExhaustedError,
    LLMBudgetPolicy,
    LLMPhase,
    LLMReservationStarvationError,
    LLMTruncatedResponseError,
    LLMUsageTracker,
)
from hunting.controller.models import HuntBudgetLedger
from hunting.m2_abduction.provider import ApiLLMConfig, create_llm_caller
from hunting.reporter.renderer import render_analyst_report


class DummyProvider:
    """Mock provider allowing explicit control over response and usage metadata."""

    def __init__(
        self,
        response_text: str = "{}",
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        finish_reason: str | None = None,
        exception: Exception | None = None,
    ) -> None:
        self.response_text = response_text
        self.last_usage = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        } if (prompt_tokens is not None or completion_tokens is not None) else {}
        self.last_finish_reason = finish_reason
        self.last_attempt_count = 1
        self.config = ApiLLMConfig(model="mock-model", max_tokens=2000)
        self.exception = exception

    def call_raw(self, prompt: str, system_instruction: str | None = None) -> str:
        if self.exception:
            raise self.exception
        return self.response_text


# =============================================================================
# H1: Shared Configuration & Elimination of Drift
# =============================================================================

def test_h1_shared_configuration_eliminates_drift() -> None:
    """CLI, tracker, SearchEnvelope, and HuntBudgetLedger read one authoritative LLMBudgetPolicy."""
    default_policy = LLMBudgetPolicy()
    assert default_policy.max_total_calls == 5, "Authoritative default max_calls must be 5"
    assert default_policy.max_total_tokens == 15000

    # 1. LLMUsageTracker reads policy
    tracker = LLMUsageTracker(policy=default_policy)
    assert tracker.max_calls == 5
    assert tracker.max_total_tokens == 15000

    # 2. BudgetEnvelope reads policy
    envelope = BudgetEnvelope.from_policy(default_policy)
    assert envelope.max_llm_calls == 5
    assert envelope.max_llm_tokens == 15000

    # 3. HuntBudgetLedger reads policy
    ledger = HuntBudgetLedger(policy=default_policy)
    assert ledger.max_llm_calls == 5

    # 4. Custom policy propagates uniformly
    custom_policy = LLMBudgetPolicy(max_total_calls=8, max_total_tokens=25000, model_name="gpt-4o")
    custom_tracker = LLMUsageTracker(policy=custom_policy)
    custom_envelope = BudgetEnvelope.from_policy(custom_policy)
    custom_ledger = HuntBudgetLedger(policy=custom_policy)

    assert custom_tracker.max_calls == 8
    assert custom_envelope.max_llm_calls == 8
    assert custom_ledger.max_llm_calls == 8
    assert custom_tracker.model_name == "gpt-4o"


# =============================================================================
# H2: Global Reservation Scheduler
# =============================================================================

def test_h2_global_reservation_optional_calls_cannot_starve_mandatory_capacity() -> None:
    """Optional source profiling (C2) cannot consume reserved proof/recovery capacity."""
    # Policy with 3 total calls: C1 (2 reserved) + C1V (1 reserved) = 3 reserved.
    # Optional calls have 0 unreserved capacity and must be rejected!
    tight_policy = LLMBudgetPolicy(max_total_calls=3)
    tracker = LLMUsageTracker(policy=tight_policy)

    assert tracker.reserved_mandatory_capacity() == 3, "Initially 2 for C1 + 1 for C1V"
    assert tracker.remaining_calls == 3

    # Attempting optional C2 source profiling must be rejected by reservation scheduler
    can_run, reason = tracker.can_schedule(LLMPhase.C2_SOURCE_PROFILER)
    assert not can_run, "Optional C2 must not run when remaining capacity is reserved for mandatory operations"
    assert "reserved" in reason.lower()

    with pytest.raises(LLMReservationStarvationError):
        tracker.preflight("Test prompt", component="source_profiler", phase=LLMPhase.C2_SOURCE_PROFILER)

    # However, mandatory C1 (compiler) CAN run because it is mandatory
    can_c1, _ = tracker.can_schedule(LLMPhase.C1_COMPILER)
    assert can_c1, "Mandatory C1 compiler must be authorized to use reserved capacity"

    # Now simulate successful C1 compiler call
    tracker.record_call(
        component="compiler",
        prompt="Initial prompt",
        response='{"variables": [], "relations": []}',
        status="SUCCESS",
        validation_status="VALID",
        phase=LLMPhase.C1_COMPILER,
    )

    # Since C1 succeeded on first call, repair is no longer needed: C1 reservation drops to 0!
    # Remaining reserved is only C1V (1 call). Remaining total calls is 2.
    assert tracker.reserved_mandatory_capacity() == 1
    assert tracker.remaining_calls == 2

    # Now unreserved capacity is 2 - 1 = 1, so optional C2 CAN run now!
    can_c2_now, _ = tracker.can_schedule(LLMPhase.C2_SOURCE_PROFILER)
    assert can_c2_now, "Optional C2 can schedule once mandatory C1 capacity is released"


def test_h2_disabled_phase_c6_rejection() -> None:
    """Touchpoint C6 (Narrative generation) is disabled (max_calls=0) and rejected immediately."""
    tracker = LLMUsageTracker()
    can_run, reason = tracker.can_schedule(LLMPhase.C6_NARRATIVE)
    assert not can_run
    assert "disabled" in reason.lower()

    with pytest.raises(LLMBudgetExhaustedError):
        tracker.preflight("Generate narrative", component="narrative", phase=LLMPhase.C6_NARRATIVE)


def test_h2_c1_compiler_mandatory_plus_repair() -> None:
    """C1 enforces 1 mandatory call + at most 1 repair on validation failure."""
    calls: list[str] = []

    valid_goal_graph_json = json.dumps({
        "id": "goal-graph-1",
        "objective": "Did alice log on to workstation-1?",
        "variables": [
            {"id": "user", "entity_type": "user", "value": "alice"},
            {"id": "host", "entity_type": "host", "value": "workstation-1"},
        ],
        "relations": [
            {"id": "rel-1", "subject": "user", "relation": "logged_on_to", "object": "host", "required": True},
        ],
        "qualifiers": [],
        "answers": [{"variable_id": "host", "answer_type": "value", "required": True}],
        "answer_contracts": [],
        "assumptions": [],
        "uncertainties": [],
        "forbidden_inferences": [],
        "clarification_triggers": [],
    })

    def mock_llm_caller(prompt: str, reason: str = "", phase: str = "") -> str:
        calls.append(reason or prompt)
        if len(calls) == 1:
            # Call 1: Return invalid schema (missing relations)
            return '{"variables": [{"id": "user", "entity_type": "user"}]}'
        # Call 2: Return valid goal graph JSON
        return valid_goal_graph_json

    compiler = KnowledgeBehaviorCompiler(llm_caller=mock_llm_caller)
    req = HuntRequest(id="hunt-repair-1", kind=HuntRequestKind.NL_QUESTION, content="Did alice log on to workstation-1?")

    obj, hypos, reqs = compiler.compile(req)

    assert len(calls) == 2, "Compiler must attempt exactly 1 repair call following validation failure"
    assert compiler.llm_calls_made == 2
    assert obj.semantic_goal_graph is not None
    assert len(obj.semantic_goal_graph.relations) == 1
    assert compiler.last_compile_trace.get("repair_attempted") is True
    assert compiler.last_compile_trace.get("validation_result") == "VALID"


# =============================================================================
# Gate H: Malformed and Truncated Output Integrity
# =============================================================================

def test_gate_h_malformed_and_truncated_output_cannot_mutate_graph_or_state() -> None:
    """Truncated (finish_reason == 'length') or malformed JSON is rejected and cannot mutate graph/state."""
    tracker = LLMUsageTracker()

    # 1. Truncated output by length ceiling
    truncated_provider = DummyProvider(
        response_text='{"variables": [{"id": "user"',
        finish_reason="LENGTH",
    )
    caller = create_llm_caller(truncated_provider, tracker=tracker, component="compiler")

    with pytest.raises(LLMTruncatedResponseError) as exc_info:
        caller("Compile request")
    assert "truncated" in str(exc_info.value).lower()

    # Check tracker recorded FAILED status with TRUNCATED validation
    assert tracker.call_count == 1
    assert tracker.calls[0].status == "FAILED"
    assert tracker.calls[0].validation_status == "TRUNCATED"

    # 2. Unclosed malformed JSON
    malformed_provider = DummyProvider(
        response_text='{"variables": [{"id": "v1"}',  # unclosed JSON
        finish_reason="STOP",
    )
    caller_malformed = create_llm_caller(malformed_provider, tracker=tracker, component="source_profiler")

    with pytest.raises(Exception):
        caller_malformed("Profile request")

    assert tracker.call_count == 2
    assert tracker.calls[1].status == "FAILED"
    assert tracker.calls[1].validation_status == "MALFORMED"


# =============================================================================
# Gate H: Reporting Transparency & Token Estimation Labeling
# =============================================================================

def test_gate_h_call_metadata_and_estimation_labeling() -> None:
    """Every call records phase, reason, payload size, tokens, latency, validation status, and is_estimate."""
    tracker = LLMUsageTracker()

    # Call 1: With actual provider tokens
    provider_actual = DummyProvider(
        response_text='{"status": "ok"}',
        prompt_tokens=150,
        completion_tokens=45,
    )
    caller_actual = create_llm_caller(provider_actual, tracker=tracker, component="compiler")
    caller_actual("Test prompt 1", reason="semantic_compilation")

    rec1 = tracker.calls[0]
    assert rec1.phase == LLMPhase.C1_COMPILER.value
    assert rec1.reason == "semantic_compilation"
    assert rec1.prompt_tokens == 150
    assert rec1.completion_tokens == 45
    assert rec1.total_tokens == 195
    assert rec1.is_estimate is False, "Actual provider usage metadata must be labeled is_estimate=False"
    assert rec1.validation_status == "VALID"
    assert rec1.payload_size > 0

    # Call 2: Without provider tokens (character estimate fallback)
    provider_est = DummyProvider(
        response_text='{"result": "estimated"}',
        prompt_tokens=None,
        completion_tokens=None,
    )
    caller_est = create_llm_caller(provider_est, tracker=tracker, component="planner")
    caller_est("A longer test prompt 2 for character estimation", reason="query_planning")

    rec2 = tracker.calls[1]
    assert rec2.phase == LLMPhase.C3_QUERY_GEN.value
    assert rec2.is_estimate is True, "Missing provider tokens must be labeled is_estimate=True"

    # Export dictionary audit
    ledger_dict = tracker.to_dict()
    assert ledger_dict["token_accounting_mode"] == "HYBRID"
    assert ledger_dict["calls_made"] == 2

    # Render into analyst report and verify labels
    obj = HuntObjective("req-1", statement="Investigate user")
    account = FinalHuntAccount(
        request_id="req-1",
        objective=obj,
        hypotheses=[],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_ANSWERED,
        llm_usage=ledger_dict,
    )

    rendered = render_analyst_report(account)
    assert "## 5. Cost" in rendered
    assert "LLM Touchpoint Trace" in rendered
    assert "Token accounting mode: `HYBRID`" in rendered
    assert "`C1_COMPILER`" in rendered
    assert "`C3_QUERY_GEN`" in rendered
