"""Unit tests for Workstream F: Central ProofEngine & Executable Proof Authority.

Acceptance Gate F:
1. Unrelated-row counterexample remains PROOF_GAP.
2. Role-swapped account/host evidence is rejected.
3. Co-occurrence without directional action is retrieval-only.
4. Generic file creation does not prove encryption.
5. Verified goals contain contract/evaluator/query/observation citations.
6. Bounded negative evidence licensing.
"""


from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.proof_contract import (
    ProofContract,
    ProofContractStatus,
)
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import SemanticRelationGoal
from hunting.evidence.proof_engine import ProofEngine


def _make_obs(obs_id: str, fields: dict) -> Observation:
    return Observation(
        id=obs_id,
        provider_scope=ProviderScope(
            provider_id="splunk",
            native_partition={"index": "main"},
            scope_id="scope-1",
        ),
        cell_id="cell-1",
        timestamp="2026-09-14T00:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields=fields,
        raw_event=fields,
    )


def test_unrelated_row_execution_remains_proof_gap():
    """Gate F1: Operation declares relation_observable, but rows are unrelated."""
    goal = SemanticRelationGoal(id="goal-visited", subject="var_host", relation="visited", object="var_dom")
    op = ProviderOperation(
        id="op-visited",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("visited",),
        proof_mode="relation_observable",
    )
    res = QueryResult(
        query_id="q-unrelated",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"bogus_col": "xyz", "random_num": "42"}],
        row_count=1,
    )

    engine = ProofEngine()
    proof_res = engine.evaluate(goal=goal, operation=op, query_result=res)

    assert not proof_res.verified
    assert proof_res.verdict == "PROOF_GAP"
    assert "non_conforming_rows" in proof_res.reason_codes
    assert "domain" in proof_res.missing_obligations or "endpoint" in proof_res.missing_obligations


def test_role_swapped_account_host_evidence_rejected():
    """Gate F2: Role-swapped evidence (e.g. host bound to user role or vice versa) is rejected."""
    goal = SemanticRelationGoal(id="goal-logon", subject="var_user", relation="logged_on_to", object="var_host")
    op = ProviderOperation(
        id="op-logon",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("logged_on_to",),
        proof_mode="relation_observable",
    )
    # The row has dest_ip / host in user role and username in host role
    res = QueryResult(
        query_id="q-swapped",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"query": "admin", "dest_ip": "10.0.0.1"}],  # Incompatible roles according to ROLE_INCOMPATIBLE_FIELDS
        row_count=1,
    )

    engine = ProofEngine()
    proof_res = engine.evaluate(goal=goal, operation=op, query_result=res)

    assert not proof_res.verified
    assert proof_res.verdict == "PROOF_GAP"


def test_cooccurrence_without_directional_action_is_retrieval_only():
    """Gate F3: Co-occurrence without directional action / proof_mode='retrieval_only' cannot prove."""
    goal = SemanticRelationGoal(id="goal-visited", subject="var_host", relation="visited", object="var_dom")
    op = ProviderOperation(
        id="op-passive-dns",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("visited",),
        proof_mode="retrieval_only",  # Retrieval only!
    )
    res = QueryResult(
        query_id="q-cooccur",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"host": "wrk-123", "domain": "example.com"}],
        row_count=1,
    )

    engine = ProofEngine()
    proof_res = engine.evaluate(goal=goal, operation=op, query_result=res)

    assert not proof_res.verified
    assert proof_res.verdict == "RETRIEVAL_ONLY"
    assert "operation_retrieval_only" in proof_res.reason_codes


def test_generic_file_creation_does_not_prove_encryption():
    """Gate F4: Generic file creation (EventCode 11) without encryption proof cannot prove ransomware."""
    goal = SemanticRelationGoal(
        id="goal-encrypt",
        subject="var_ransomware",
        relation="ransomware_encrypted_file",
        object="var_file",
    )
    op = ProviderOperation(
        id="op-file-events",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("ransomware_encrypted_file",),
        proof_mode="relation_observable",
    )
    # Generic Sysmon EventCode 11 without cipher / ransom_note / encryption action
    res = QueryResult(
        query_id="q-file-create",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"EventCode": "11", "TargetFilename": "C:\\Users\\Alice\\doc.txt", "host": "wrk-1"}],
        row_count=1,
    )

    contract = ProofContract(
        contract_id="proof-ransomware-v1",
        version="1.0",
        relation="ransomware_encrypted_file",
        required_entity_roles=("source_artifact",),
        required_value_roles=("target_artifact",),
        status=ProofContractStatus.APPROVED,
    )

    engine = ProofEngine()
    proof_res = engine.evaluate(goal=goal, operation=op, query_result=res, contract=contract)

    assert not proof_res.verified
    assert proof_res.verdict == "PROOF_GAP"
    assert "generic_file_creation_not_encryption" in proof_res.reason_codes


def test_verified_goal_contains_complete_citations_and_fields():
    """Gate F5: Verified goal contains exact contract, evaluator, query/obs citations, and cited fields."""
    goal = SemanticRelationGoal(id="goal-visited", subject="var_host", relation="visited", object="var_dom")
    op = ProviderOperation(
        id="op-proxy",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("visited",),
        proof_mode="relation_observable",
    )
    res = QueryResult(
        query_id="q-web-proxy-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"host": "wrk-finance-1", "site": "malicious-c2.com", "http_method": "POST", "uri": "/beacon"}],
        row_count=1,
    )

    engine = ProofEngine()
    proof_res = engine.evaluate(
        goal=goal,
        operation=op,
        query_result=res,
        bindings={"var_host": "wrk-finance-1"},
    )

    assert proof_res.verified
    assert proof_res.verdict == "PROVEN"
    assert proof_res.contract_id == "proof-web-visit-v1"
    assert proof_res.evaluator_id == "evaluate_observed_relation"
    assert "q-web-proxy-1" in proof_res.citations[0]
    assert proof_res.subject_binding == "wrk-finance-1"
    assert proof_res.object_binding == "malicious-c2.com"
    assert len(proof_res.cited_fields) >= 2


def test_negative_evidence_licensed_absence():
    """Gate F6: Complete empty query on contract with negative evidence license proves absence."""
    goal = SemanticRelationGoal(id="goal-visited", subject="var_host", relation="visited", object="var_dom")
    op = ProviderOperation(
        id="op-proxy",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("visited",),
        proof_mode="relation_observable",
    )
    res = QueryResult(
        query_id="q-empty-scan",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[],
        row_count=0,
    )

    # Without negative license: remains PROOF_GAP
    engine = ProofEngine()
    res_unlicensed = engine.evaluate(goal=goal, operation=op, query_result=res)
    assert not res_unlicensed.verified
    assert res_unlicensed.verdict == "PROOF_GAP"

    # With negative license: proves absence (REFUTED)
    licensed_contract = ProofContract(
        contract_id="proof-web-visit-licensed-v1",
        version="1.0",
        relation="visited",
        required_entity_roles=("endpoint",),
        required_value_roles=("domain",),
        negative_evidence_licensed=True,
        status=ProofContractStatus.APPROVED,
    )
    res_licensed = engine.evaluate(goal=goal, operation=op, query_result=res, contract=licensed_contract)
    assert res_licensed.verified
    assert res_licensed.verdict == "REFUTED"
    assert "negative_evidence_licensed_absence" in res_licensed.reason_codes
