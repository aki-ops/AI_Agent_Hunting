"""Unit tests for Semantic Entry Point and Threat Hunting Engine Hardening.

Verifies the 8 core epistemic invariants:
1. Person name with dot or space does not become a domain entity or domain constraint.
2. Request without explicit domain does not fabricate "amber.turing" domain.
3. Web server host (e.g. jabbah) is never assigned as a user endpoint for a person.
4. Splunk adapter parses _raw JSON array queries into normalized scalar query and IP fields.
5. Query traceability ensures query report records and query_results.jsonl share identical native_query.
6. Evaluator refuses NOT_FOUND when identity is unresolved, enforcing INCONCLUSIVE (IDENTITY_UNRESOLVED).
7. Hypotheses for website browsing claims are never classified as benign_baseline.
8. Report renders query rationale (purpose, reason, result, impact) for all executed queries.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from hunting.compiler.compiler import (
    KnowledgeBehaviorCompiler,
    parse_and_validate_semantic_intent,
)
from hunting.contracts.hunt import (
    EvidenceCard,
    EvidenceRequirementV4,
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    QueryPlan,
    QueryResult,
    StoppingDecision,
)
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticHuntIntent,
    SubjectEntity,
)
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.m2_abduction.provider import StubSemanticCompiler
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter
from hunting.planner.planner import CanonicalQueryPlanner
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_analyst_report


def test_1_person_with_dot_not_treated_as_domain():
    """1. Person name 'Amber Turing' or 'amber.turing' is never classified as a domain."""
    raw_response = {
        "semantic_intent": {
            "original_request": "amber.turing visited example.com",
            "question": "What domain did amber.turing visit?",
            "subject": {"type": "person", "value": "amber.turing"},
            "requested_object": {"type": "website_domain", "role": "answer"},
            "behavior": "web browsing",
            "evidence_requirements": [
                {
                    "semantic_intent": "identity_binding",
                    "required_fields": ["user", "host"],
                    "necessity": "CRITICAL",
                    "description": "Resolve amber.turing to endpoint",
                },
                {
                    "semantic_intent": "web_navigation",
                    "required_fields": ["site", "uri"],
                    "necessity": "CRITICAL",
                    "description": "Web requests to example.com",
                },
            ],
            "required_correlations": ["person_to_endpoint"],
            "assumptions": [],
            "uncertainties": [],
        },
        "hypotheses": [
            {
                "id": "hyp-1",
                "statement": "amber.turing visited example.com",
                "class": "unclassified",
                "assumptions": [],
                "requirements": ["req-id", "req-web"],
            }
        ],
        "requirements": [
            {
                "id": "req-id",
                "semantic_intent": "identity_binding",
                "necessity": "CRITICAL",
                "search_hints": ["amber.turing"],
                "falsification_condition": "No user record",
                "description": "User identity lookup",
                "source_refs": ["LOGON"],
            },
            {
                "id": "req-web",
                "semantic_intent": "web_navigation",
                "necessity": "CRITICAL",
                "search_hints": ["example.com"],
                "falsification_condition": "No web record",
                "description": "Web request inspection",
                "source_refs": ["WEB"],
            },
        ],
    }

    hypos, reqs, intent = parse_and_validate_semantic_intent(raw_response, "amber.turing visited example.com")
    assert intent.subject.type == "person"
    assert intent.subject.value == "amber.turing"
    assert intent.requested_object.type == "website_domain"

    # Verify planner does not turn "amber.turing" into domain constraint on identity requirement
    planner = CanonicalQueryPlanner()
    id_req = next(r for r in reqs if r.id == "req-id")
    from hunting.contracts.cells import ProviderScope
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv2"})
    lqp, diag = planner.plan_logical_query(
        requirement=id_req,
        entity=None,
        scope=scope,
        time_window="2026-01-01T00:00:00Z/P1D",
    )
    assert lqp is not None
    assert "domain" not in lqp.constraints


def test_2_request_without_domain_does_not_fabricate_domain():
    """2. Request 'Amber Turing visited the competitor website' does not fabricate amber.turing domain."""
    stub = StubSemanticCompiler(scenario="amber")
    compiler = KnowledgeBehaviorCompiler(llm_caller=stub)
    req = HuntRequest(
        id="hunt-amber-no-domain",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Amber Turing visited the competitor website",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    assert obj.semantic_intent is not None
    assert obj.semantic_intent.subject.type == "person"
    assert obj.semantic_intent.subject.value == "Amber Turing"

    # Invariant: No requirement has "amber.turing" as domain search hint
    for r in requirements:
        assert "amber.turing" not in r.search_hints
        if r.predicate:
            assert r.predicate.value != "amber.turing"


def test_3_web_server_never_assigned_as_user_endpoint():
    """3. A web server host (jabbah, we1149srv) is never bound as a user endpoint for a person."""
    engine = HypothesisHuntEngine()
    state = HuntState(
        objective=HuntObjective(
            request_id="hunt-person-test",
            statement="Amber Turing investigation",
            semantic_intent=SemanticHuntIntent(
                original_request="Amber Turing visited site",
                question="What site did Amber Turing visit?",
                subject=SubjectEntity(type="person", value="Amber Turing"),
                requested_object=RequestedObject(type="website_domain"),
                behavior="web browsing",
            ),
        ),
        identity_resolved=False,
    )

    # Simulate sweep rows containing web server IIS traffic from jabbah
    fake_rows = [
        {
            "host": "jabbah",
            "user": "Amber Turing",
            "native_type": "iis",
            "c_ip": "192.168.1.100",
        },
        {
            "host": "we1149srv",
            "user": "Amber Turing",
            "native_type": "stream:http",
            "client_ip": "192.168.1.101",
        },
    ]

    engine._evaluate_identity_linkage(state, fake_rows)

    # Invariant: Must remain unresolved because both hosts are web servers
    assert state.identity_resolved is False
    assert state.identity_mapping.get("endpoint") != "jabbah"
    assert state.identity_mapping.get("endpoint") != "we1149srv"
    assert state.identity_mapping.get("reason") == "IDENTITY_UNRESOLVED"


def test_4_splunk_adapter_parses_raw_json_array_queries():
    """4. Splunk adapter correctly parses _raw JSON array queries into scalar query string and normalized IPs."""
    adapter = SplunkLiveAdapter(index="botsv2")
    raw_event_payload = json.dumps({
        "query": ["52.116.31.116.in-addr.arpa"],
        "src_ip": "10.0.1.50",
        "dest_ip": "10.0.1.1",
        "name": ["dns.froth.ly"],
    })

    fake_raw_results = [
        {
            "_time": "2026-09-01T12:00:00Z",
            "host": "dns-server-01",
            "sourcetype": "stream:dns",
            "_raw": raw_event_payload,
        }
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"results": fake_raw_results}

    with patch("requests.post", return_value=mock_resp):
        qr = adapter.execute_query(
            operation_id="splunk_search_dns",
            entity=None,
            window="2026-09-01T12:00:00Z/P1D",
            native_query="search index=botsv2 sourcetype=stream:dns",
        )

    assert len(qr.rows) == 1
    row = qr.rows[0]
    assert row["query"] == "52.116.31.116.in-addr.arpa"
    assert row["source_ip"] == "10.0.1.50"
    assert row["client_ip"] == "10.0.1.50"
    assert row["destination_ip"] == "10.0.1.1"
    assert row["site"] == "dns.froth.ly"


def test_5_query_report_and_results_share_identical_native_query():
    """5. Query report records and query_results.jsonl share identical native_query sourced from QueryResult."""
    native_spl = "search index=botsv2 host=wrk-amber sourcetype=stream:http | head 101"
    qr = QueryResult(
        query_id="qp-web-01",
        outcome="ROWS",
        executed_ok=True,
        complete=True,
        rows=[{"host": "wrk-amber", "site": "example.com"}],
        native_query=native_spl,
    )

    req = EvidenceRequirementV4(
        id="req-web",
        description="Web traffic from Amber workstation",
        evidence_type="web_request",
        falsification_condition="No web traffic",
        semantic_intent="web_navigation",
    )

    hypo = Hypothesis(
        id="hyp-1",
        statement="Amber visited site",
        status=HypothesisStatus.LIVE,
        requirements=["req-web"],
    )

    qplan = QueryPlan(
        id="qp-web-01",
        requirement_id="req-web",
        provider_id="splunk",
        scope_id="botsv2",
        operation_id="splunk_search",
    )

    state = HuntState(
        objective=HuntObjective(request_id="hunt-trace"),
        hypotheses=[hypo],
        requirements=[req],
        queries=[qplan],
        query_results=[qr],
    )

    account = build_final_hunt_account(state)
    assert len(account.queries) == 1
    query_record = account.queries[0]

    # Invariant: Must strictly match qr.native_query
    assert query_record["native_query"] == native_spl
    assert query_record["query_id"] == qr.query_id
    assert query_record["semantic_intent"] == "web_navigation"
    assert query_record["rows_count"] == 1
    assert query_record["complete"] is True


def test_6_evaluator_refuses_not_found_when_identity_unresolved():
    """6. Evaluator strictly refuses NOT_FOUND when identity is unresolved, returning INCONCLUSIVE."""
    evaluator = EvidenceEvaluator()
    evaluator.llm_caller = lambda prompt: json.dumps({
        "answer": {
            "status": "NOT_FOUND",
            "value": None,
            "explanation": "Did not find any domains",
            "card_ids": [],
        }
    })

    cards = [
        EvidenceCard(
            id="card-1",
            fingerprint="fp1",
            fact_type="web_request",
            summary="Web activity on perimeter",
            representative_observation_ids=["obs-1"],
        )
    ]
    hypos = [Hypothesis(id="h1", statement="Amber visited site", status=HypothesisStatus.LIVE)]

    result = evaluator.analyze_batch(
        cards=cards,
        hypotheses=hypos,
        question="What site did Amber visit?",
        identity_resolved=False,
        identity_required=True,
    )

    # Invariant: Epistemic guard downgrades to INCONCLUSIVE with IDENTITY_UNRESOLVED
    assert result["answer"]["status"] == "INCONCLUSIVE"
    assert result["answer"]["reason"] == "IDENTITY_UNRESOLVED"


def test_7_browsing_hypothesis_never_benign_baseline():
    """7. Hypothesis for website browsing is never classified as benign_baseline."""
    data = {
        "semantic_intent": {
            "original_request": "Amber Turing visited a competitor website",
            "question": "Did Amber Turing visit the website?",
            "subject": {"type": "person", "value": "Amber Turing"},
            "requested_object": {"type": "website_domain", "role": "answer"},
            "behavior": "visited competitor website",
            "evidence_requirements": [],
            "required_correlations": [],
            "assumptions": [],
            "uncertainties": [],
        },
        "hypotheses": [
            {
                "id": "hypo-browse",
                "statement": "Amber Turing visited the website for competitive research",
                "class": "benign_baseline",
                "assumptions": [],
                "requirements": ["req-browse"],
            }
        ],
        "requirements": [
            {
                "id": "req-browse",
                "semantic_intent": "web_navigation",
                "necessity": "CRITICAL",
                "search_hints": [],
                "falsification_condition": "No web visits",
                "description": "Web navigation audit",
                "source_refs": ["AUDIT"],
            }
        ],
    }

    hypos, _, _ = parse_and_validate_semantic_intent(data, "Amber Turing visited a competitor website")
    assert len(hypos) == 1
    # Invariant: benign_baseline is overridden for browsing statements
    assert hypos[0].hypothesis_class != "benign_baseline"
    assert hypos[0].hypothesis_class == "unclassified"


def test_8_report_renders_query_rationale_and_impact():
    """8. Report renders query rationale (purpose, reason, result, impact) for executed queries."""
    state = HuntState(
        objective=HuntObjective(
            request_id="hunt-rationale-test",
            statement="Investigate Amber Turing activity",
            semantic_intent=SemanticHuntIntent(
                original_request="Investigate Amber Turing activity",
                question="What site was visited?",
                subject=SubjectEntity(type="person", value="Amber Turing"),
                requested_object=RequestedObject(type="website_domain"),
                behavior="web navigation",
                required_correlations=["person_to_endpoint", "endpoint_to_traffic"],
            ),
        ),
        hypotheses=[Hypothesis(id="hyp-amber-1", statement="Amber visited site", status=HypothesisStatus.SUPPORTED)],
        evidence_cards=[],
        queries=[
            QueryPlan(
                id="qp-amber-ident",
                requirement_id="req-amber-id",
                provider_id="splunk",
                scope_id="botsv2",
                operation_id="splunk_search",
            )
        ],
        query_results=[
            QueryResult(
                query_id="qp-amber-ident",
                outcome="ROWS",
                executed_ok=True,
                complete=True,
                rows=[{"user": "Amber Turing", "host": "wrk-amber"}],
                native_query="search index=botsv2 sourcetype=WinEventLog:Security user=*Turing* | head 101",
            )
        ],
        requirements=[
            EvidenceRequirementV4(
                id="req-amber-id",
                description="Resolve Amber Turing to active workstation",
                evidence_type="authentication_activity",
                semantic_intent="identity_binding",
                falsification_condition="No user logon records",
            )
        ],
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )
    account = build_final_hunt_account(state)
    report = render_analyst_report(account)

    assert "## 4. Queries used" in report
    assert "### `qp-amber-ident` — `req-amber-id`" in report
    assert "**Purpose:** Resolve Amber Turing to active workstation" in report
    assert "**Semantic Reason:** `identity_binding`" in report
    assert "**Result:** 1 rows returned; complete=True" in report
    assert "**Hypothesis Impact:** Targets `hyp-amber-1`" in report
    assert "search index=botsv2 sourcetype=WinEventLog:Security user=*Turing*" in report
