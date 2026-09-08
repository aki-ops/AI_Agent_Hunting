"""Tests for Phase B: LLM-driven Adaptive Planner, Observability, and Resilient Fallback."""
from __future__ import annotations

import json
from types import SimpleNamespace

from hunting.contracts.hunt_spec import AnswerContract, HuntSpec, SearchTerm
from hunting.controller.cost import LLMUsageTracker
from hunting.m2_abduction.provider import LLMTimeoutError
from hunting.planner.adaptive import (
    AdaptiveOperationPlanner,
    _contains_native_query,
)


def test_native_query_detection():
    assert _contains_native_query("index=botsv2 sourcetype=XmlWinEventLog") is True
    assert _contains_native_query("| stats count by host") is True
    assert _contains_native_query("SELECT * FROM events WHERE id = 1") is True
    assert _contains_native_query("search_text") is False
    assert _contains_native_query("find_file_version") is False


def test_llm_operation_not_in_descriptor_retries_and_falls_back():
    """When LLM suggests an operation not in capability descriptor, retry 1 time, then fallback to search_text."""
    spec = HuntSpec(
        question="What version of Tor was installed?",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        search_terms=[SearchTerm(value="Tor Browser")],
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="search_text"),
        SimpleNamespace(id="find_installed_software"),
    ))

    calls: list[str] = []

    def mock_llm(prompt: str) -> str:
        calls.append(prompt)
        # Returns hallucinated operation 'execute_custom_spl' which is NOT in descriptor
        return json.dumps({
            "operation": "execute_custom_spl",
            "search_terms": ["Tor Browser"],
            "reason": "Looking for tor browser",
        })

    planner = AdaptiveOperationPlanner(llm_generator=mock_llm)
    decision = planner.choose(spec, descriptor)

    # Must have called LLM twice: initial prompt + 1 retry
    assert len(calls) == 2
    # Second call should be the retry prompt with available operations
    assert "available_operations" in calls[1] or "select_operation_retry" in calls[1]

    # After retry also fails, must fall back to search_text with terms from question/spec
    assert decision.operation_id == "search_text"
    assert "Tor Browser" in decision.search_terms
    assert "FALLBACK" in decision.validation_result
    assert decision.prompt_hash != ""
    assert len(planner.audit_logs) >= 2
    assert planner.audit_logs[-1]["selected_operation"] == "search_text"
    assert planner.audit_logs[-1]["phase"] == "adaptive_planner"


def test_llm_direct_spl_or_sql_rejected_and_falls_back():
    """When LLM returns raw SPL or SQL statements, reject immediately, retry, and fallback to search_text."""
    spec = HuntSpec(
        question="What version of Tor was installed?",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        search_terms=[SearchTerm(value="Tor Browser")],
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="search_text"),
        SimpleNamespace(id="find_installed_software"),
    ))

    calls: list[str] = []

    def mock_llm(prompt: str) -> str:
        calls.append(prompt)
        # Returns raw SPL syntax
        return json.dumps({
            "operation": "index=botsv2 | stats count by host",
            "search_terms": ["index=botsv2 sourcetype=XmlWinEventLog"],
            "reason": "Direct SPL injection attempt",
        })

    planner = AdaptiveOperationPlanner(llm_generator=mock_llm)
    decision = planner.choose(spec, descriptor)

    # Must retry once then fallback
    assert len(calls) == 2
    assert decision.operation_id == "search_text"
    assert "FALLBACK" in decision.validation_result
    assert "REJECTED_NATIVE_QUERY" in decision.reason or "REJECTED_NATIVE_QUERY" in decision.validation_result


def test_llm_malformed_json_retries_and_falls_back():
    """When LLM returns malformed JSON, retry 1 time with shorter prompt, then fallback."""
    spec = HuntSpec(
        question="Find Tor version",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        search_terms=[SearchTerm(value="Tor Browser")],
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="search_text"),
        SimpleNamespace(id="find_file_version"),
    ))

    calls: list[str] = []

    def mock_llm(prompt: str) -> str:
        calls.append(prompt)
        # Broken JSON
        return "I think you should use find_file_version for Tor: { broken json..."

    planner = AdaptiveOperationPlanner(llm_generator=mock_llm)
    decision = planner.choose(spec, descriptor)

    assert len(calls) == 2
    assert decision.operation_id == "search_text"
    assert "FALLBACK" in decision.validation_result
    assert "MALFORMED_JSON" in decision.reason or "MALFORMED_JSON" in decision.validation_result


def test_llm_timeout_falls_back_safely_without_hanging():
    """When LLM times out, fall back safely immediately without retry hanging, logging the timeout."""
    spec = HuntSpec(
        question="What version of Tor was installed on wrk-amber?",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        search_terms=[SearchTerm(value="Tor Browser")],
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="search_text"),
        SimpleNamespace(id="find_file_version"),
    ))

    calls: list[str] = []

    def mock_llm_timeout(prompt: str) -> str:
        calls.append(prompt)
        raise LLMTimeoutError("LLM API request timed out after 30s")

    planner = AdaptiveOperationPlanner(llm_generator=mock_llm_timeout)
    decision = planner.choose(spec, descriptor)

    # Should not retry repeatedly on timeout
    assert len(calls) == 1
    assert decision.operation_id == "search_text"
    assert "Tor Browser" in decision.search_terms
    assert "TIMEOUT" in decision.validation_result or "TIMEOUT" in decision.reason
    assert any(log["validation_result"].startswith("TIMEOUT") for log in planner.audit_logs)


def test_llm_success_selection_recorded_in_observability():
    """When LLM returns a valid operation from descriptor, it is accepted and logged."""
    spec = HuntSpec(
        question="What version of Tor was installed?",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
        search_terms=[SearchTerm(value="Tor Browser")],
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="search_text"),
        SimpleNamespace(id="find_file_version"),
    ))

    def mock_llm(prompt: str) -> str:
        return json.dumps({
            "operation": "find_file_version",
            "required_fields": ["ProductVersion", "FileVersion"],
            "search_terms": ["Tor Browser", "firefox.exe"],
            "reason": "find_file_version searches executable headers for software versions",
        })

    planner = AdaptiveOperationPlanner(llm_generator=mock_llm)
    decision = planner.choose(spec, descriptor)

    assert decision.operation_id == "find_file_version"
    assert decision.required_fields == ("ProductVersion", "FileVersion")
    assert decision.search_terms == ("Tor Browser", "firefox.exe")
    assert decision.validation_result == "VALID"
    assert decision.prompt_hash != ""

    assert len(planner.audit_logs) == 1
    log = planner.audit_logs[0]
    assert log["phase"] == "adaptive_planner"
    assert log["selected_operation"] == "find_file_version"
    assert log["validation_result"] == "VALID"
    assert log["prompt_hash"] == decision.prompt_hash


def test_llm_usage_tracker_observability_and_cost():
    """LLMUsageTracker records phase, prompt_hash, validation_result, and token/cost."""
    tracker = LLMUsageTracker(max_calls=4, model_name="gemini-2.5-flash")

    rec1 = tracker.record_call(
        component="compiler",
        prompt="Compile natural language threat hunt query: What version of Tor was installed?",
        response='{"normalized_claim": "Tor installed", "entities": []}',
        duration_ms=120.5,
        actual_prompt_tokens=25,
        actual_completion_tokens=15,
        prompt_hash="hash-comp-01",
        validation_result="VALID",
        selected_operation="semantic_compilation",
    )
    assert rec1.component == "compiler"
    assert rec1.prompt_hash == "hash-comp-01"
    assert rec1.cost_usd > 0

    rec2 = tracker.record_call(
        component="adaptive_planner",
        prompt='{"task": "select_semantic_hunt_operation", "available_operations": ["find_file_version"]}',
        response='{"operation": "find_file_version", "search_terms": ["Tor Browser"]}',
        duration_ms=85.2,
        actual_prompt_tokens=30,
        actual_completion_tokens=12,
        prompt_hash="hash-adapt-02",
        validation_result="VALID",
        selected_operation="find_file_version",
        search_terms=["Tor Browser"],
    )
    assert rec2.component == "adaptive_planner"
    assert rec2.prompt_hash == "hash-adapt-02"
    assert rec2.selected_operation == "find_file_version"
    assert rec2.search_terms == ["Tor Browser"]

    rec3 = tracker.record_call(
        component="evaluator",
        prompt="Evaluate evidence cards against hypothesis",
        response='{"answer": {"status": "ANSWERED", "value": "13.5.2"}}',
        duration_ms=150.0,
        actual_prompt_tokens=50,
        actual_completion_tokens=20,
        prompt_hash="hash-eval-03",
        validation_result="VALID",
        selected_operation="evaluate_cards",
    )
    assert rec3.component == "evaluator"
    assert tracker.call_count == 3
    assert tracker.total_tokens == (25 + 15 + 30 + 12 + 50 + 20)

    summary = tracker.to_dict()
    assert summary["calls_made"] == 3
    assert len(summary["calls"]) == 3
    components = [c["component"] for c in summary["calls"]]
    assert components == ["compiler", "adaptive_planner", "evaluator"]
    assert summary["calls"][1]["prompt_hash"] == "hash-adapt-02"
    assert summary["calls"][1]["selected_operation"] == "find_file_version"
