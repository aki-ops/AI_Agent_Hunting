"""Sizing is not evidence. Behavior matches stay candidates until a comparator holds."""
from __future__ import annotations

from hunting.contracts.proof_contract import ProofContract, ProofContractStatus
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import SemanticRelationGoal
from hunting.evidence.behavior_comparator import benign_citation
from hunting.evidence.proof_engine import ProofEngine
from hunting.planner.sizing import escalation_for, measure_sizing, refute_allowed


def _visit_query() -> tuple[SemanticRelationGoal, ProviderOperation, QueryResult]:
    goal = SemanticRelationGoal(
        id="goal-visited",
        subject="var_host",
        relation="visited",
        object="var_dom",
        goal_class="behavior",
    )
    operation = ProviderOperation(
        id="op-proxy",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("visited",),
        proof_mode="relation_observable",
    )
    result = QueryResult(
        query_id="q-web-proxy-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"host": "wrk-finance-1", "site": "malicious-c2.com", "http_method": "POST", "uri": "/beacon"}],
        row_count=1,
    )
    return goal, operation, result


def test_sizing_is_separate_from_proof_and_selects_strategy():
    small = measure_sizing(match_count=2, distinct_entities=2, scope_size=3, expected_magnitude="small")
    assert small.kind == "SIZING"
    assert small.coverage_ratio == 2 / 3
    assert small.strategy == "enumerate"
    wide = measure_sizing(match_count=40, distinct_entities=12, scope_size=20, expected_magnitude="small")
    assert wide.strategy == "require_comparator"
    assert escalation_for(wide, "small")


def test_refute_requires_coverage_and_rejects_a_bad_index():
    assert refute_allowed(executed_ok=True, complete=True, coverage_ratio=0.9, min_coverage=0.8) is True
    assert refute_allowed(executed_ok=True, complete=True, coverage_ratio=0.2, min_coverage=0.8) is False
    assert refute_allowed(
        executed_ok=True, complete=True, coverage_ratio=1.0, min_coverage=0.8, index_mismatch=True,
    ) is False
    goal = SemanticRelationGoal(id="goal-visited", subject="var_host", relation="visited", object="var_dom")
    operation = ProviderOperation(
        id="op-proxy", provider_id="splunk", scope_ids=("main",),
        guaranteed_relations=("visited",), proof_mode="relation_observable",
    )
    empty = QueryResult(
        query_id="q-empty", outcome=QueryOutcome.ROWS, executed_ok=True, complete=True, rows=[], row_count=0,
    )
    contract = ProofContract(
        contract_id="proof-web-visit-licensed-v1",
        version="1.0",
        relation="visited",
        required_entity_roles=("endpoint",),
        required_value_roles=("domain",),
        negative_evidence_licensed=True,
        status=ProofContractStatus.APPROVED,
    )
    blocked = ProofEngine().evaluate(
        goal=goal,
        operation=operation,
        query_result=empty,
        contract=contract,
        min_coverage_to_refute=0.8,
        coverage_ratio=0.1,
    )
    assert blocked.verdict == "PROOF_GAP"
    assert "refute_blocked_insufficient_coverage" in blocked.reason_codes


def test_behavior_match_is_candidate_until_first_seen():
    goal, operation, result = _visit_query()
    engine = ProofEngine()
    candidate = engine.evaluate(
        goal=goal,
        operation=operation,
        query_result=result,
        bindings={"var_host": "wrk-finance-1"},
    )
    assert candidate.verified is False
    assert candidate.verdict == "RETRIEVAL_ONLY"
    assert "behavior_predicate_match_is_candidate" in candidate.reason_codes
    proved = engine.evaluate(
        goal=goal,
        operation=operation,
        query_result=result,
        bindings={"var_host": "wrk-finance-1"},
        comparator={"first_seen": True},
    )
    assert proved.verdict == "PROVEN"


def test_known_benign_hit_is_a_citation_not_a_benign_verdict():
    citation = benign_citation("svc-backup", ("svc-backup", "svc-monitor"))
    assert citation == "known-benign:svc-backup"
    goal, operation, result = _visit_query()
    proof = ProofEngine().evaluate(
        goal=goal,
        operation=operation,
        query_result=result,
        bindings={"var_host": "wrk-finance-1"},
        comparator={"baseline_deviation": False, "first_seen": False, "rare": False},
    )
    assert proof.verdict != "PROVEN"
    assert "BENIGN" not in proof.verdict
