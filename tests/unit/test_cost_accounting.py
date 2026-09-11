import json

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.entities import Domain, Host
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    is_entity_compatible_with_requirement,
)
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, LogicalQueryPlan
from hunting.controller.cost import LLMUsageTracker, get_model_pricing
from hunting.m2_abduction.provider import LLMProvider, create_llm_caller
from hunting.planner.compiler import SplunkQueryCompiler


class MockLLMProvider(LLMProvider):
    def __init__(self, model: str = "gemini-2.5-flash"):
        self.config = type("Config", (), {"model": model})()

    def generate(self, prompt_context: dict) -> str:
        return '{"result": "mock_response_text_with_content"}'

    def call_raw(self, prompt: str, system_instruction: str | None = None) -> str:
        return '{"result": "mock_call_raw_response_content"}'


class FailingLLMProvider(LLMProvider):
    def __init__(self) -> None:
        self.config = type("Config", (), {"model": "gemini-2.5-flash", "max_tokens": 50})()
        self.last_attempt_count = 2

    def call_raw(self, prompt: str, system_instruction: str | None = None) -> str:
        raise RuntimeError("gateway unavailable")

    def generate(self, prompt_context: dict) -> str:
        raise RuntimeError("gateway unavailable")


def test_model_pricing_lookup():
    gemini_price = get_model_pricing("gemini-2.5-flash")
    assert gemini_price["prompt"] == 0.075 / 1_000_000
    assert gemini_price["completion"] == 0.30 / 1_000_000

    gpt4o_price = get_model_pricing("gpt-4o")
    assert gpt4o_price["prompt"] == 2.50 / 1_000_000
    assert gpt4o_price["completion"] == 10.00 / 1_000_000

    stub_price = get_model_pricing("stub")
    assert stub_price["prompt"] == 0.0
    assert stub_price["completion"] == 0.0


def test_cost_accounting_gemini():
    tracker = LLMUsageTracker(max_calls=3, model_name="gemini-2.5-flash")
    rec = tracker.record_call(
        component="compiler",
        prompt="A" * 4000,   # ~1000 tokens
        response="B" * 2000, # ~500 tokens
        duration_ms=120.0,
    )
    assert rec.estimated_prompt_tokens == 1000
    assert rec.estimated_completion_tokens == 500
    assert rec.model == "gemini-2.5-flash"
    assert rec.cost_usd > 0
    assert tracker.estimated_cost_usd == rec.cost_usd

    dict_repr = tracker.to_dict()
    assert dict_repr["model"] == "gemini-2.5-flash"
    assert dict_repr["estimated_cost_usd"] > 0
    assert dict_repr["calls_made"] == 1


def test_cost_budget_ceiling():
    tracker = LLMUsageTracker(max_calls=2, model_name="gpt-4o")
    tracker.record_call("comp1", "prompt1", "resp1")
    tracker.record_call("comp2", "prompt2", "resp2")
    assert tracker.is_exhausted

    with pytest.raises(RuntimeError, match="maximum 2 LLM calls per hunt exceeded"):
        tracker.record_call("comp3", "prompt3", "resp3")


def test_llm_preflight_rejects_oversized_prompt_before_provider_call():
    tracker = LLMUsageTracker(max_calls=3, max_total_tokens=100, model_name="gpt-4o")
    with pytest.raises(RuntimeError, match="preflight rejected"):
        tracker.preflight("x" * 401, expected_completion_tokens=10, component="compiler")
    assert tracker.call_count == 0
    assert tracker.total_tokens == 0


def test_create_llm_caller_preflights_before_call():
    provider = MockLLMProvider(model="gemini-2.5-flash")
    provider.config.max_tokens = 50
    tracker = LLMUsageTracker(max_calls=3, max_total_tokens=100, model_name="gemini-2.5-flash")
    caller = create_llm_caller(provider, tracker, component="compiler")

    with pytest.raises(RuntimeError, match="preflight rejected"):
        caller("x" * 401)
    assert tracker.call_count == 0


def test_create_llm_caller_tracked():
    provider = MockLLMProvider(model="gemini-2.5-flash")
    tracker = LLMUsageTracker(max_calls=3, model_name="gemini-2.5-flash")
    caller = create_llm_caller(provider, tracker, component="evaluator")

    response = caller("Evaluate this evidence against hypothesis")
    assert "mock_call_raw_response_content" in response
    assert tracker.call_count == 1
    assert tracker.estimated_cost_usd > 0
    assert tracker.calls[0].component == "evaluator"
    assert tracker.calls[0].model == "gemini-2.5-flash"


def test_failed_llm_call_and_physical_attempts_are_accounted():
    provider = FailingLLMProvider()
    tracker = LLMUsageTracker(max_calls=3, model_name="gemini-2.5-flash")
    caller = create_llm_caller(provider, tracker, component="source_profiler")

    assert caller("profile this source") == "{}"
    assert tracker.call_count == 1
    assert tracker.is_exhausted is False
    assert tracker.calls[0].status == "FAILED"
    assert tracker.calls[0].physical_attempts == 2
    assert tracker.calls[0].error == "gateway unavailable"


def test_splunk_compiler_domain_filter():
    compiler = SplunkQueryCompiler()
    plan = LogicalQueryPlan(
        id="lqp-test-web",
        requirement_id="req-web_request",
        provider="splunk",
        scope="splunk_botsv1",
        data_sources=[{"index": "botsv1", "sourcetype": "stream:http"}],
        filters=[{"field": "site", "op": "CONTAINS", "value": "imreallynotbatman.com"}],
        fields=["timestamp", "host", "uri"],
        entity=Host(name="we1149srv"),
        time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
        constraints={"domain": "www.imreallynotbatman.com"},
        limit=50,
        is_targeted=True,
    )

    nqp = compiler.compile(plan)
    assert nqp is not None
    spl = nqp.native_query
    assert "host=\"we1149srv\"" in spl
    assert "site=\"*imreallynotbatman.com*\"" in spl
    assert "eval site=coalesce(site, cs_host)" in spl
    assert "like(lower(site), \"%imreallynotbatman.com%\")" in spl
    assert "cs_host" in spl


def test_entity_requirement_compatibility():
    dom = Domain(name="www.imreallynotbatman.com")
    host = Host(name="we1149srv")

    # Domain compatibility
    assert is_entity_compatible_with_requirement(dom, EvidenceRequirement.WEB_REQUEST) is True
    assert is_entity_compatible_with_requirement(dom, EvidenceRequirement.DNS_ACTIVITY) is True
    assert is_entity_compatible_with_requirement(dom, EvidenceRequirement.NETWORK_CONNECTION) is True
    assert is_entity_compatible_with_requirement(dom, EvidenceRequirement.PROCESS_ANCESTRY) is False
    assert is_entity_compatible_with_requirement(dom, EvidenceRequirement.FILE_MODIFICATION) is False
    assert is_entity_compatible_with_requirement(dom, EvidenceRequirement.PERSISTENCE_CHANGE) is False

    # Host compatibility
    assert is_entity_compatible_with_requirement(host, EvidenceRequirement.PROCESS_ANCESTRY) is True
    assert is_entity_compatible_with_requirement(host, EvidenceRequirement.FILE_MODIFICATION) is True
    assert is_entity_compatible_with_requirement(host, EvidenceRequirement.WEB_REQUEST) is True

    # Expectation post_init contract
    with pytest.raises(ValueError, match="is incompatible with requirement"):
        Expectation(
            id="exp-bad",
            owner_explanation_id="hypo-1",
            evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
            predicted_observation="Process audit",
            entity_ref=dom,
            field_predicate=None,
            provider_scope_id="scope-1",
            time_window="2016-08-01/2016-08-29",
            falsification_condition="none",
        )


def test_splunk_compiler_no_domain_pollution_in_endpoint_queries():
    compiler = SplunkQueryCompiler()
    # Plan for process_ancestry with domain in constraints and filters
    plan = LogicalQueryPlan(
        id="lqp-proc",
        requirement_id="req-process_ancestry",
        provider="splunk",
        scope="splunk_botsv1",
        data_sources=[{"index": "botsv1", "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"}],
        filters=[{"field": "site", "op": "CONTAINS", "value": "imreallynotbatman.com"}],
        fields=["timestamp", "host", "image", "cmdline"],
        entity=Host(name="we1149srv"),
        time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
        constraints={"domain": "www.imreallynotbatman.com"},
        limit=50,
        is_targeted=True,
    )

    nqp = compiler.compile(plan)
    assert nqp is not None
    spl = nqp.native_query

    # Must contain endpoint targets
    assert 'host="we1149srv"' in spl
    assert "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" in spl
    assert "*EventID>1<*" in spl

    # MUST NOT contain domain string pollution or domain filter clauses!
    assert "imreallynotbatman" not in spl
    assert "eval site=coalesce" not in spl
    assert 'site="' not in spl
    assert "like(lower(site)" not in spl


def test_compiler_llm_decomposition_active():
    mock_decomp = json.dumps({
        "id": "claim-graph-hunt-test-decomp",
        "request_id": "hunt-test-decomp",
        "objective": "Determine whether the web application was compromised",
        "answer_contract": {
            "mode": "hunt",
            "answer_type": "compromise",
            "required_fields": [],
            "question": "Was the web application compromised?",
        },
        "claims": [
            {
                "id": "hypo-web-attack",
                "claim_type": "behaviour",
                "subject": "web_application:requested",
                "predicate": "compromised",
                "object_or_value": None,
                "value_type": "compromise",
                "provenance": "request",
                "source_request_id": "hunt-test-decomp",
                "dependencies": [],
                "evidence_requirements": [],
                "observation_requirements": [
                    {"id": "req-web-http", "fact_kind": "web_request", "required_fields": ["uri"], "field_roles": [], "completeness_required": False},
                    {"id": "req-web-proc", "fact_kind": "process_ancestry", "required_fields": ["parent_process", "process_name"], "field_roles": [], "completeness_required": False},
                ],
                "acceptance_rule": {"min_observations": 1, "required_fields": [], "requires_query_complete": False, "value_must_match": None},
                "refutation_rule": None,
                "optional": False,
                "is_prerequisite": False,
                "reason": "The request asks whether compromise occurred",
            },
            {
                "id": "hypo-web-benign",
                "claim_type": "controlled_absence",
                "subject": "web_application:requested",
                "predicate": "matches_baseline",
                "object_or_value": None,
                "value_type": "baseline",
                "provenance": "request",
                "source_request_id": "hunt-test-decomp",
                "dependencies": [],
                "evidence_requirements": [],
                "observation_requirements": [{"id": "req-web-baseline", "fact_kind": "scope_records", "required_fields": [], "field_roles": [], "completeness_required": True}],
                "acceptance_rule": {"min_observations": 1, "required_fields": [], "requires_query_complete": True, "value_must_match": None},
                "refutation_rule": None,
                "optional": False,
                "is_prerequisite": False,
                "reason": "A complete baseline is needed to support the benign alternative",
            },
        ],
        "metadata": {"requirement_search_hints": {"req-web-http": ["www.imreallynotbatman.com"]}},
    })

    def mock_caller(prompt: str) -> str:
        return f"```json\n{mock_decomp}\n```"

    compiler = KnowledgeBehaviorCompiler(llm_caller=mock_caller)
    req = HuntRequest(
        id="hunt-test-decomp",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised web www.imreallynotbatman.com",
    )

    obj, hypos, reqs = compiler.compile(req)
    assert compiler.llm_calls_made == 1
    assert len(hypos) == 2
    # Ensure Domain is NOT injected into request.entities
    assert not any(isinstance(e, Domain) for e in req.entities)

    # Semantic compilation preserves fixture search hints but does not invent
    # a field predicate; capability binding owns that later translation.
    web_r = next(r for r in reqs if r.evidence_type == "web_request")
    assert web_r.predicate is None
    assert web_r.search_hints == ["www.imreallynotbatman.com"]


def test_web_request_fact_classification_with_domain():
    """Verify HTTP events containing domain/site are classified as web_request, not dns_activity."""
    from hunting.contracts.cells import ProviderScope
    from hunting.contracts.observations import EpistemicType, Observation
    from hunting.evidence.facts import extract_facts

    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"}, scope_id="scope-splunk")
    obs = Observation(
        id="obs-http-01",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2016-08-10T22:22:26Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="stream:http",
        fields={
            "uri": "/joomla/index.php",
            "site": "imreallynotbatman.com",
            "domain": "imreallynotbatman.com",
            "http_method": "POST",
            "destination_ip": "192.168.250.70",
            "dest_ip": "192.168.250.70",
            "host": "splunk-02",
        },
        entities=[Host(name="splunk-02"), Domain(name="imreallynotbatman.com")],
    )

    facts = extract_facts(obs)
    assert len(facts) >= 1
    web_fact = next((f for f in facts if f.fact_type == "web_request"), None)
    assert web_fact is not None, f"Expected web_request fact, got {[f.fact_type for f in facts]}"
    assert web_fact.primary_entity == Domain(name="imreallynotbatman.com")
    assert not any(f.fact_type == "dns_activity" for f in facts)


def test_outcome_guard_prevents_false_contradiction():
    """Verify that FinalHuntAccount.outcome returns INCONCLUSIVE or UNKNOWN instead of CONTRADICTED when gaps exist."""
    from hunting.contracts.coverage import CoverageBound
    from hunting.contracts.hunt import FinalHuntAccount, HuntObjective, HuntOutcome, Hypothesis, StoppingDecision

    hypo = Hypothesis(
        id="hypo-attack",
        statement="Attacker compromised web www.imreallynotbatman.com",
    )
    obj = HuntObjective(request_id="req-gap", statement="Investigate web compromise", time_window="2016-08-01/2016-08-29")

    # Case 1: Attack hypo is in unknown list (telemetry gap)
    account_gap = FinalHuntAccount(
        request_id="req-gap",
        objective=obj,
        hypotheses=[hypo],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=["hypo-attack"],
        unreachable=[],
        residuals=["residual-telemetry-gap"],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_BOUNDED,
    )
    assert account_gap.outcome == HuntOutcome.UNKNOWN
    assert account_gap.outcome != HuntOutcome.CONTRADICTED

    # Case 2: One attack hypo contradicted, but residuals/unknowns remain
    account_partial = FinalHuntAccount(
        request_id="req-partial",
        objective=obj,
        hypotheses=[hypo],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=["hypo-attack"],
        unknown=[],
        unreachable=[],
        residuals=["residual-untested-scope"],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_BOUNDED,
    )
    assert account_partial.outcome == HuntOutcome.INCONCLUSIVE
    assert account_partial.outcome != HuntOutcome.CONTRADICTED
