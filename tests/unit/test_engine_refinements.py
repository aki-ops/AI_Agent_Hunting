from unittest.mock import MagicMock, patch
from urllib.error import URLError

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import Account, Domain, Host, IPAddress
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    TestStatus,
)
from hunting.contracts.hunt import (
    EvidenceAssessment,
    EvidenceCard,
    EvidenceRequirementV4,
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    LogicalQueryPlan,
    NativeQueryPlan,
    QueryPlan,
    RequirementStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.controller.controller import CanonicalActionController
from hunting.controller.cost import LLMUsageTracker
from hunting.controller.models import HuntAction
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.m2_abduction.provider import create_llm_caller
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter
from hunting.planner.compiler import SplunkQueryCompiler
from hunting.planner.planner import CanonicalQueryPlanner
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_final_hunt_account


def _web_chain_requirement() -> EvidenceRequirementV4:
    """Typed requirement used by correlation tests; no statement parsing."""
    return EvidenceRequirementV4(
        id="req-web-chain",
        description="Web activity associated with the tested attack chain",
        evidence_type="web_request",
    )


def test_1_requirement_status_lifecycle():
    from hunting.m2_abduction.provider import StubSemanticCompiler
    compiler = KnowledgeBehaviorCompiler(llm_caller=StubSemanticCompiler(scenario="web"))
    req_hunt = HuntRequest(
        id="req-hunt-1",
        kind=HuntRequestKind.NL_QUESTION,
        content="Attacker compromised web www.imreallynotbatman.com",
    )
    _, _, requirements = compiler.compile(req_hunt)
    assert len(requirements) > 0
    for req in requirements:
        assert req.status == RequirementStatus.DEFINED

    planner = CanonicalQueryPlanner()
    scope = planner.registry["cdb_sqlite"].scopes[0]
    proc_req = next((r for r in requirements if r.evidence_type in ("process_ancestry", "process")), requirements[0])
    plan, diag = planner.plan_query(
        proc_req,
        Host(name="we1149srv"),
        scope,
        "NOW-7d/NOW",
    )
    assert plan is not None
    assert proc_req.status == RequirementStatus.PLANNED


def test_2_host_correlation_and_reporting_separation():
    c1 = EvidenceCard(
        id="ec_proc",
        fingerprint="fp_proc",
        fact_type="process_execution",
        entity_summary={"hosts": ["we1149srv"]},
    )
    c2 = EvidenceCard(
        id="ec_web",
        fingerprint="fp_web",
        fact_type="web_request",
        entity_summary={"hosts": ["splunk-02"]},
    )
    state = HuntState(
        objective=HuntObjective(request_id="req-1", statement="Attacker compromised web server"),
        evidence_cards=[c1, c2],
    )
    account = build_final_hunt_account(state)
    md = render_final_hunt_account(account)

    assert "we1149srv" in md
    assert "splunk-02" in md
    assert "Compromised Target Host(s):** `we1149srv`" in md
    assert "splunk-02" not in md.split("Compromised Target Host(s):")[1].split("\n")[0]
    assert "Telemetry Capture / Sensor Host(s):** `splunk-02`" in md


def test_3_uncorrelated_evidence_controller_eval():
    controller = CanonicalActionController()
    h = Hypothesis(
        id="H1",
        statement="Attacker compromised web server",
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-web-chain"],
    )
    c_web = EvidenceCard(
        id="ec_web",
        fingerprint="fp_web",
        fact_type="web_request",
        entity_summary={"ips": ["10.0.0.99"]},
    )
    c_proc = EvidenceCard(
        id="ec_proc",
        fingerprint="fp_proc",
        fact_type="process_execution",
        entity_summary={"hosts": ["finance-desktop"]},
    )
    c_file = EvidenceCard(
        id="ec_file",
        fingerprint="fp_file",
        fact_type="file_modification",
        entity_summary={"hosts": ["finance-desktop"]},
    )
    state = HuntState(
        hypotheses=[h],
        requirements=[_web_chain_requirement()],
        evidence_cards=[c_web, c_proc, c_file],
    )
    controller.evaluate_stopping(state)
    assert h.status == HypothesisStatus.WEAKENED


def test_4_controller_state_authority():
    controller = CanonicalActionController()
    state = HuntState()
    cell = Cell(
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"}),
        entity=Host(name="SRV-01"),
        state=CellState.UNEXPLORED,
        time_bucket="2026-09-05/P1D",
    )

    controller.add_cell(state, cell)
    assert len(state.cells) == 1

    controller.transition_cell_state(state, cell, CellState.EXPLORED)
    assert cell.state == CellState.EXPLORED

    qp = QueryPlan(
        id="q1",
        requirement_id="req1",
        provider_id="splunk",
        scope_id="botsv1",
        operation_id="search",
    )
    qr = QueryResult(
        query_id="q1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        execution_time_ms=12.5,
        row_count=5,
        rows=[{"a": 1}],
        complete=True,
    )
    controller.record_query_execution(state, qp, qr)
    assert len(state.queries) == 1
    assert len(state.query_results) == 1
    assert state.query_count == 1

    exp = Expectation(
        id="exp1",
        owner_explanation_id="H1",
        evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
        predicted_observation="cmd execution",
        entity_ref=Host(name="SRV-01"),
        field_predicate=None,
        provider_scope_id=None,
        time_window="2026-09-05/P1D",
        falsification_condition="no processes",
    )
    controller.update_expectation_status(state, exp, TestStatus.CONFIRMED)
    assert exp.test_status == TestStatus.CONFIRMED

    req = EvidenceRequirementV4(
        id="req1",
        description="test",
        evidence_type="process_ancestry",
        status=RequirementStatus.DEFINED,
    )
    controller.update_requirement_status(state, req, RequirementStatus.EXECUTED)
    assert req.status == RequirementStatus.EXECUTED

    dec = StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
    controller.set_stopping_decision(state, dec)
    assert state.stopping_decision == StoppingDecision.STOP_EXHAUSTED_BY_BUDGET


def test_5_pivot_action_selection():
    controller = CanonicalActionController()
    state = HuntState()
    assert controller.select_action(state) == HuntAction.STOP
    assert controller.select_action(state, has_pivot_candidates=True) == HuntAction.PIVOT
    assert controller.select_action(state, has_untested_expectations=True) == HuntAction.TEST


def test_6_llm_network_exception_resilience():
    mock_provider = MagicMock()
    mock_provider.call_raw.side_effect = URLError("Splunk connection refused")
    tracker = LLMUsageTracker()

    caller = create_llm_caller(mock_provider, tracker=tracker)
    resp = caller("Hello")
    assert resp == "{}"


def test_7_evaluator_batch_llm_validation():
    mock_caller = MagicMock()
    mock_caller.return_value = '{"evaluations": [{"card_id": "ec_1", "hypothesis_evaluations": [{"hypothesis_id": "H1", "polarity": 1, "relevance": 0.9, "rationale": "Matched"}, {"hypothesis_id": "H_GHOST", "polarity": 1, "relevance": 0.8, "rationale": "Ghost"}]}, {"card_id": "ec_unknown", "hypothesis_evaluations": [{"hypothesis_id": "H1", "polarity": 1, "relevance": 0.5, "rationale": "Fake"}]}]}'
    evaluator = EvidenceEvaluator(llm_caller=mock_caller)
    c1 = EvidenceCard(id="ec_1", fingerprint="fp1", fact_type="process_execution")
    c2 = EvidenceCard(id="ec_2", fingerprint="fp2", fact_type="file_modification")
    h1 = Hypothesis(id="H1", statement="Test hypothesis")

    result = evaluator._batch_llm_evaluate([c1, c2], [h1])
    assert result is not None
    assert "ec_unknown" not in result
    assert "ec_1" in result
    assert "ec_2" in result
    assert result["ec_1"] == ["H1"]
    assert result["ec_2"] == []


def test_8_token_usage_metadata_accounting():
    tracker = LLMUsageTracker()
    tracker.record_call(
        component="compiler",
        prompt="1234567890",
        response="1234567890",
        actual_prompt_tokens=105,
        actual_completion_tokens=45,
    )
    assert tracker.total_prompt_tokens == 105
    assert tracker.total_completion_tokens == 45
    assert tracker.call_count == 1


def test_9_splunk_adapter_native_query_param():
    adapter = SplunkLiveAdapter(splunk_url="http://127.0.0.1:8089", auth=("admin", "pass"))
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": [{"_time": "2026-09-05T00:00:00", "dest": "10.0.0.1"}]}
        mock_post.return_value = mock_resp

        res = adapter.execute_query(
            operation_id="custom_operation",
            entity=None,
            window="2026-02-01T00:00:00Z/P1D",
            native_query="search index=botsv1 sourcetype=iis site=*batman*",
        )
        assert res.executed_ok is True
        assert mock_post.call_args[1]["data"]["search"] == "search index=botsv1 sourcetype=iis site=*batman*"


def test_10_wildcard_cell_state_post_execution():
    engine = HypothesisHuntEngine()
    mock_adapter = MagicMock()
    mock_adapter.scope = ProviderScope(provider_id="cdb_sqlite", native_partition={"table": "events"})
    mock_adapter.last_query_text = "SELECT * FROM events"
    mock_adapter.execute_query.return_value = QueryResult(
        query_id="q_test",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        execution_time_ms=10.0,
        row_count=1,
        rows=[{"dest_ip": "192.168.1.50"}],
        complete=True,
    )
    req = HuntRequest(
        id="req-hunt-cve",
        kind=HuntRequestKind.CVE,
        content="CVE-2024-21887 Ivanti Connect Secure Command Injection",
    )
    result = engine.execute_hunt(req, adapter=mock_adapter, time_window="2026-02-01T00:00:00Z/P1D")
    wildcard_cells = [c for c in result.state.cells if c.is_wildcard]
    assert len(wildcard_cells) > 0
    for wc in wildcard_cells:
        assert wc.state == CellState.EXPLORED


def test_11_cross_host_disjoint_evidence_weakens_compromise_hypothesis():
    controller = CanonicalActionController()
    h = Hypothesis(
        id="H1",
        statement="Attacker compromised web server",
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-web-chain"],
    )
    # Disjoint host evidence: web on web-a, endpoint on endpoint-b
    c_web = EvidenceCard(
        id="ec_web",
        fingerprint="fp_web",
        fact_type="web_request",
        entity_summary={"hosts": ["web-a"]},
    )
    c_proc = EvidenceCard(
        id="ec_proc",
        fingerprint="fp_proc",
        fact_type="process_execution",
        entity_summary={"hosts": ["endpoint-b"]},
    )
    c_file = EvidenceCard(
        id="ec_file",
        fingerprint="fp_file",
        fact_type="file_modification",
        entity_summary={"hosts": ["endpoint-b"]},
    )
    state = HuntState(
        hypotheses=[h],
        requirements=[_web_chain_requirement()],
        evidence_cards=[c_web, c_proc, c_file],
    )
    dec = controller.evaluate_stopping(state)
    assert h.status == HypothesisStatus.WEAKENED
    assert dec != StoppingDecision.STOP_RESOLVED

    # Correlated host evidence: web on web-a with dest IP pointing to endpoint-b
    c_web_corr = EvidenceCard(
        id="ec_web_corr",
        fingerprint="fp_web_corr",
        fact_type="web_request",
        entity_summary={"hosts": ["web-a"], "destination_ips": ["192.168.1.50"]},
    )
    c_proc_corr = EvidenceCard(
        id="ec_proc_corr",
        fingerprint="fp_proc_corr",
        fact_type="process_execution",
        entity_summary={"hosts": ["endpoint-b"], "ips": ["192.168.1.50"]},
    )
    h_corr = Hypothesis(
        id="H2",
        statement="Attacker compromised web server",
        status=HypothesisStatus.SUPPORTED,
    )
    exp_corr = Expectation(
        id="exp_corr_1",
        owner_explanation_id="H2",
        evidence_requirement=EvidenceRequirement.WEB_REQUEST,
        predicted_observation="web traffic",
        entity_ref=Host(name="web-a"),
        field_predicate=None,
        provider_scope_id="botsv1",
        time_window="2026-09-05/P1D",
        falsification_condition="none",
        test_status=TestStatus.CONFIRMED,
    )
    state_corr = HuntState(
        hypotheses=[h_corr],
        expectations=[exp_corr],
        evidence_cards=[c_web_corr, c_proc_corr, c_file],
    )
    dec_corr = controller.evaluate_stopping(state_corr)
    assert h_corr.status == HypothesisStatus.SUPPORTED
    assert dec_corr == StoppingDecision.STOP_RESOLVED


def test_12_pivot_candidate_generation_and_execution():
    from hunting.m2_abduction.provider import StubSemanticCompiler
    engine = HypothesisHuntEngine(compiler=KnowledgeBehaviorCompiler(llm_caller=StubSemanticCompiler(scenario="web")))
    mock_adapter = MagicMock()
    mock_adapter.scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})
    mock_adapter.last_query_text = "search index=botsv1"

    # Return rows with non-system user, external IP, and domain
    mock_adapter.execute_query.return_value = QueryResult(
        query_id="q_pivot_test",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        execution_time_ms=10.0,
        row_count=1,
        rows=[{
            "host": "srv-01",
            "user": "compromised_admin",
            "destination_ip": "198.51.100.25",
            "domain": "malicious-c2.example.com",
            "file_path": "C:\\malware.exe",
            "image": "cmd.exe",
            "cmdline": "cmd.exe /c malware.exe",
            "site": "www.imreallynotbatman.com",
        }],
        complete=True,
    )
    req = HuntRequest(
        id="req-hunt-pivot",
        kind=HuntRequestKind.NL_QUESTION,
        content="Attacker compromised web server",
    )
    res = engine.execute_hunt(req, adapter=mock_adapter, time_window="2026-02-01T00:00:00Z/P1D")
    cell_entities = [c.entity for c in res.state.cells if not c.is_wildcard]
    has_user = any(isinstance(e, Account) and e.username == "compromised_admin" for e in cell_entities)
    has_ip = any(isinstance(e, IPAddress) and e.address == "198.51.100.25" for e in cell_entities)
    has_domain = any(isinstance(e, Domain) and e.name == "malicious-c2.example.com" for e in cell_entities)
    assert has_user or has_ip or has_domain


def test_13_complete_state_authority_methods():
    controller = CanonicalActionController()
    state = HuntState()

    # 1. advance_turn
    t = controller.advance_turn(state)
    assert t == 1
    assert state.turn == 1

    # 2. add_expectation
    exp = Expectation(
        id="exp-auth-1",
        owner_explanation_id="H1",
        evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
        predicted_observation="cmd execution",
        entity_ref=Host(name="srv-1"),
        field_predicate=None,
        provider_scope_id=None,
        time_window="2026-09-05/P1D",
        falsification_condition="none",
    )
    controller.add_expectation(state, exp)
    assert len(state.expectations) == 1
    controller.add_expectation(state, exp)
    assert len(state.expectations) == 1

    # 3. add_observation
    obs = Observation(
        id="obs-1",
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"}),
        cell_id="2026-09-05/P1D",
        timestamp="2026-09-05T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="event",
        fields={"host": "srv-1"},
    )
    controller.add_observation(state, obs)
    assert len(state.observations) == 1

    # 4. set_evidence_cards
    card = EvidenceCard(id="ec-1", fingerprint="fp1", fact_type="process_execution")
    controller.set_evidence_cards(state, [card])
    assert len(state.evidence_cards) == 1
    assert state.evidence_cards[0].id == "ec-1"

    # 5. add_logical_query_plan & add_native_query_plan
    lqp = LogicalQueryPlan(
        id="lqp-1",
        requirement_id="req-1",
        provider="splunk",
        scope="botsv1",
        data_sources=[],
        filters=[],
        fields=[],
        entity=None,
        time_window="2026-09-05/P1D",
        constraints={},
    )
    nqp = NativeQueryPlan(
        id="nqp-1",
        logical_plan_id="lqp-1",
        provider="splunk",
        native_query="search index=botsv1",
        time_range=("", ""),
    )
    controller.add_logical_query_plan(state, lqp)
    controller.add_native_query_plan(state, nqp)
    assert len(state.logical_query_plans) == 1
    assert len(state.native_query_plans) == 1

    # 6. add_evidence_assessment
    assessment = EvidenceAssessment(
        card_id="ec-1",
        compatible_hypotheses=["H1"],
        confidence=0.9,
        reason="Matched process execution",
    )
    controller.add_evidence_assessment(state, assessment)
    assert len(state.evidence_assessments) == 1


def test_14_llm_query_compilation_and_execution_fidelity():
    planner = CanonicalQueryPlanner()
    custom_spl = "search index=botsv1 sourcetype=iis site=*batman* uri=*cmd.aspx*"
    planner.llm_generator = lambda p: custom_spl
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})

    req = EvidenceRequirementV4(
        id="req-custom-c2",
        description="detect webshell custom activity",
        evidence_type="custom_webshell_telemetry",
    )
    plan, diag = planner.plan_query(
        req,
        Host(name="splunk-02"),
        scope,
        "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
    )
    assert plan is not None
    assert plan.parameters.get("query") == custom_spl

    lqp, _ = planner.plan_logical_query(
        req,
        Host(name="splunk-02"),
        scope,
        "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
        custom_constraints={"custom_query": plan.parameters.get("query")},
    )
    assert lqp is not None
    assert lqp.constraints.get("custom_query") == custom_spl

    compiler = SplunkQueryCompiler(default_index="botsv1")
    nqp = compiler.compile(lqp)
    assert nqp is not None
    assert custom_spl in nqp.native_query

    mock_adapter = MagicMock()
    mock_adapter.scope = scope
    mock_adapter.last_query_text = ""
    mock_adapter.execute_query = MagicMock(return_value=QueryResult(
        query_id="q1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        execution_time_ms=5.0,
        row_count=1,
        rows=[{"host": "splunk-02"}],
        complete=True,
    ))

    engine = HypothesisHuntEngine(planner=planner)
    req_hunt = HuntRequest(
        id="req-hunt-llm",
        kind=HuntRequestKind.NL_QUESTION,
        content="Detect webshell custom activity",
    )
    res = engine.execute_hunt(req_hunt, adapter=mock_adapter, time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z")
    assert res.state is not None
    if mock_adapter.execute_query.called:
        calls = mock_adapter.execute_query.call_args_list
        has_native = any("native_query" in call.kwargs for call in calls)
        assert has_native or len(res.state.native_query_plans) > 0


def test_15_temporal_correlation_boundary():
    """Verify that multi-stage compromise evidence separated by days degrades to WEAKENED."""
    controller = CanonicalActionController()
    h = Hypothesis(
        id="H-comp",
        statement="Attacker compromised web server",
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-web-chain"],
    )
    # Web request on 2026-02-01
    c_web = EvidenceCard(
        id="c-web",
        fingerprint="fp-web",
        fact_type="web_request",
        entity_summary={"hosts": ["splunk-02"]},
        time_summary={"earliest": "2026-02-01T10:00:00Z", "latest": "2026-02-01T10:05:00Z"},
    )
    # Process execution 14 days later on 2026-02-15
    c_proc = EvidenceCard(
        id="c-proc",
        fingerprint="fp-proc",
        fact_type="process_execution",
        entity_summary={"hosts": ["splunk-02"]},
        time_summary={"earliest": "2026-02-15T12:00:00Z", "latest": "2026-02-15T12:05:00Z"},
    )
    c_file = EvidenceCard(
        id="c-file",
        fingerprint="fp-file",
        fact_type="file_modification",
        entity_summary={"hosts": ["splunk-02"]},
        time_summary={"earliest": "2026-02-15T12:06:00Z", "latest": "2026-02-15T12:10:00Z"},
    )
    state = HuntState(
        hypotheses=[h],
        requirements=[_web_chain_requirement()],
        evidence_cards=[c_web, c_proc, c_file],
    )
    controller.evaluate_stopping(state)
    assert h.status == HypothesisStatus.WEAKENED


def test_16_multi_stage_host_colocation_enforcement():
    """Verify web compromise requires web, process, and file to be co-located on the same host."""
    controller = CanonicalActionController()
    h = Hypothesis(
        id="H-comp",
        statement="Attacker compromised web server",
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-web-chain"],
    )
    # Web on host-A, Proc on host-A, File on host-B (disjoint file modification)
    c_web = EvidenceCard(
        id="c-web",
        fingerprint="fp-web",
        fact_type="web_request",
        entity_summary={"hosts": ["host-a"]},
        time_summary={"earliest": "2026-02-01T10:00:00Z"},
    )
    c_proc = EvidenceCard(
        id="c-proc",
        fingerprint="fp-proc",
        fact_type="process_execution",
        entity_summary={"hosts": ["host-a"]},
        time_summary={"earliest": "2026-02-01T10:05:00Z"},
    )
    c_file_disjoint = EvidenceCard(
        id="c-file",
        fingerprint="fp-file",
        fact_type="file_modification",
        entity_summary={"hosts": ["host-b"]},
        time_summary={"earliest": "2026-02-01T10:06:00Z"},
    )
    state_disjoint = HuntState(
        hypotheses=[h],
        requirements=[_web_chain_requirement()],
        evidence_cards=[c_web, c_proc, c_file_disjoint],
    )
    controller.evaluate_stopping(state_disjoint)
    assert h.status == HypothesisStatus.WEAKENED

    # When all 3 are co-located on host-A
    h_ok = Hypothesis(
        id="H-comp-ok",
        statement="Attacker compromised web server",
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-web-chain"],
    )
    c_file_colocated = EvidenceCard(
        id="c-file-2",
        fingerprint="fp-file-2",
        fact_type="file_modification",
        entity_summary={"hosts": ["host-a"]},
        time_summary={"earliest": "2026-02-01T10:06:00Z"},
    )
    state_ok = HuntState(
        hypotheses=[h_ok],
        requirements=[_web_chain_requirement()],
        evidence_cards=[c_web, c_proc, c_file_colocated],
    )
    controller.evaluate_stopping(state_ok)
    assert h_ok.status == HypothesisStatus.SUPPORTED


def test_17_pivot_guardrails_bounds_and_reasons():
    """Verify that unconfirmed sweep rows do not trigger pivots, and MAX_PIVOTS is bounded."""
    from hunting.m2_abduction.provider import StubSemanticCompiler
    engine = HypothesisHuntEngine(compiler=KnowledgeBehaviorCompiler(llm_caller=StubSemanticCompiler(scenario="web")))
    req_hunt = HuntRequest(
        id="req-hunt-pivot-guard",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised web www.imreallynotbatman.com",
    )
    # Mock adapter returning 5 distinct users and IPs, but expectation is NOT confirmed
    mock_adapter = MagicMock()
    mock_adapter.scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})
    mock_adapter.execute_query = MagicMock(return_value=QueryResult(
        query_id="q1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        execution_time_ms=5.0,
        row_count=5,
        rows=[
            {"user": f"attacker_{i}", "destination_ip": f"198.51.100.{i}", "domain": f"c2-{i}.evil.com"}
            for i in range(5)
        ],
        complete=True,
    ))
    res = engine.execute_hunt(req_hunt, adapter=mock_adapter, time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z")
    # Because rows did not match expectation predicates (none confirmed), no pivot explosion occurred
    pivot_cells = [c for c in res.state.cells if isinstance(c.entity, (Account, IPAddress))]
    assert len(pivot_cells) <= 3


def test_18_llm_structured_query_parsing_and_cdb_execution():
    """Verify structured LLM query generation with markdown fences and CDB execution."""
    from hunting.planner.planner import parse_llm_query_output
    raw_markdown = "```json\n{\n  \"field\": \"cmdline\",\n  \"op\": \"CONTAINS\",\n  \"value\": \"powershell -enc\"\n}\n```"
    parsed = parse_llm_query_output(raw_markdown)
    assert parsed.get("field") == "cmdline"
    assert parsed.get("value") == "powershell -enc"

    # Test CDB native query execution with custom operation
    from hunting.m5_adapter.cdb_adapter import CdbAdapter
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "id": "e1",
            "timestamp": "2026-02-01T10:00:00Z",
            "host": "host-1",
            "cmdline": "powershell -enc JAB4ACAAPQA...",
            "native_type": "process",
        },
        {
            "id": "e2",
            "timestamp": "2026-02-01T10:01:00Z",
            "host": "host-1",
            "cmdline": "notepad.exe",
            "native_type": "process",
        }
    ])
    qr = adapter.execute_query(
        operation_id="custom_operation",
        entity=Host(name="host-1"),
        window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        native_query="SELECT * FROM events WHERE cmdline LIKE '%powershell%'",
    )
    assert qr.executed_ok
    assert len(qr.rows) == 1
    assert "powershell" in qr.rows[0]["cmdline"]


def test_19_cost_accounting_deduplication_at_refine():
    """Verify that REFINE with a tracked caller increments call count by exactly 1."""
    mock_provider = MagicMock()
    mock_provider.call_raw = MagicMock(return_value='{"evaluations": [{"card_id": "c1", "compatible_hypotheses": ["H1"]}]}')
    mock_provider.config.model = "test-model"
    mock_provider.last_usage = {"prompt_tokens": 50, "completion_tokens": 20}

    tracker = LLMUsageTracker(model_name="test-model")
    caller = create_llm_caller(mock_provider, tracker=tracker, component="evaluator")
    evaluator = EvidenceEvaluator(llm_caller=caller)

    engine = HypothesisHuntEngine(evaluator=evaluator, llm_tracker=tracker)
    h = Hypothesis(id="H1", statement="Test Hypothesis", status=HypothesisStatus.LIVE)
    card = EvidenceCard(id="c1", fingerprint="fp1", fact_type="unknown_telemetry")
    state = HuntState(hypotheses=[h], evidence_cards=[card])

    # Run REFINE action logic
    calls_before = len(engine.llm_tracker.calls)
    compat_map = engine.evaluator._batch_llm_evaluate([card], state.hypotheses)
    engine.budget_ledger.record_llm_call()
    if len(engine.llm_tracker.calls) == calls_before and not engine.llm_tracker.is_exhausted:
        engine.llm_tracker.record_call(
            component="evaluator_refine",
            prompt="Cards: 1, Hypotheses: 1",
            response=str(compat_map),
        )

    # Assert exactly ONE call was recorded in tracker, not two!
    assert tracker.call_count == 1

