"""Workstream A: Failing regression counterexamples for authority boundaries.

Covers:
1. visited(endpoint, domain) receives only a file_path row and must not verify.
2. A complete non-empty query with relation_observable metadata but no conforming proof remains PROOF_GAP.
8. A novel relation can be explored but not proven.
"""
from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.proof_contract import ProofContract, ProofContractStatus
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.evidence.relation_verifier import verify_relation_proof_contract
from hunting.m1_ledger.ledger import ObservationLedger


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


def test_visited_endpoint_domain_with_file_path_row_must_not_verify():
    """Counterexample 1: visited(endpoint, domain) receives only file_path.

    Must NOT verify because file_path does not fulfill domain_name or web visit semantics.
    """
    contract = ProofContract(
        contract_id="proof-endpoint-visited-domain-v1",
        version="1.0",
        relation="visited",
        required_entity_roles=("endpoint",),
        required_value_roles=("domain",),
        status=ProofContractStatus.APPROVED,
    )
    # Telemetry only contains host and file_path, completely lacking domain/site/url
    obs = _make_obs(
        "obs-1",
        {"host": "wrk-123", "file_path": "C:\\Windows\\System32\\notepad.exe"},
    )
    ledger = ObservationLedger()
    ledger.add_observation(obs)

    result = verify_relation_proof_contract(
        proof_contract=contract,
        observations=[obs],
        ledger=ledger,
        expected_bindings={"endpoint": "wrk-123", "domain": "evil.com"},
    )
    assert not result.verified, "Must reject visited relation when only file_path is provided"
    assert "domain" in str(result.violations) or "Missing required role" in str(result.violations)


def test_relation_observable_metadata_without_conforming_proof_remains_proof_gap():
    """Counterexample 2: Complete non-empty query with relation_observable metadata.

    Even if operation declares proof_mode='relation_observable', if the observation
    rows fail the proof contract (e.g. role incompatibility or missing directional fields),
    it must remain PROOF_GAP (unverified).
    """
    contract = ProofContract(
        contract_id="proof-user-logged-on-v1",
        version="1.0",
        relation="logged_on_to",
        required_entity_roles=("user",),
        required_value_roles=("endpoint",),
        status=ProofContractStatus.APPROVED,
    )
    operation = ProviderOperation(
        id="op-auth-events",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("logged_on_to",),
        proof_mode="relation_observable",
        native_field_bindings={"user": ("query",), "endpoint": ("dest_ip",)},  # Incompatible roles!
    )
    query_result = QueryResult(
        query_id="q-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"query": "SELECT 1", "dest_ip": "10.0.0.1"}],
    )
    obs = _make_obs(
        "obs-query-mismatch",
        {"query": "SELECT 1", "dest_ip": "10.0.0.1"},
    )
    ledger = ObservationLedger()
    assert operation.proof_mode == "relation_observable"
    assert query_result.executed_ok

    # Validate capability conformance fails due to native field incompatibility
    is_conformant, diag = contract.validate_capability_conformance(
        relation="logged_on_to",
        input_roles={"user": "query"},
        output_roles={"endpoint": "dest_ip"},
    )
    assert not is_conformant, "Capability conformance must reject incompatible native fields"

    # Verification must fail
    res = verify_relation_proof_contract(
        proof_contract=contract,
        observations=[obs],
        ledger=ledger,
        expected_bindings={"user": "alice", "endpoint": "host-1"},
    )
    assert not res.verified, "Metadata alone cannot grant proof authority"


def test_novel_relation_can_be_explored_but_not_proven():
    """Counterexample 8: Novel relation can be explored but not proven.

    If a relation is not in the approved ProofContract registry, it can be
    probed or explored with proof_mode='retrieval_only', but never 'proof_capable'.
    """
    draft_contract = ProofContract(
        contract_id="proof-custom-exfiltration-v1",
        version="0.1",
        relation="novel_custom_exfiltration",
        required_entity_roles=("endpoint",),
        required_value_roles=("cloud_bucket",),
        status=ProofContractStatus.DRAFT,  # DRAFT, not APPROVED
    )
    assert not draft_contract.is_approved

    obs = _make_obs(
        "obs-novel-1",
        {"endpoint": "host-xyz", "cloud_bucket": "s3://my-bucket"},
    )
    ledger = ObservationLedger()
    ledger.add_observation(obs)

    res = verify_relation_proof_contract(
        proof_contract=draft_contract,
        observations=[obs],
        ledger=ledger,
    )
    assert not res.verified, "Novel unapproved relation must not be proven"
    assert "DRAFT" in res.diagnostic or "not APPROVED" in str(res.violations)


def test_engine_metadata_shortcut_must_not_grant_supported_without_proof_engine():
    """Counterexample: In engine.py, base_relation_proven must not treat metadata as proof.

    If an execution returned unrelated rows for an operation with proof_mode='relation_observable',
    the goal status must remain PROOF_GAP / UNPROVEN, NEVER 'SUPPORTED'.
    """
    from types import SimpleNamespace

    from hunting.contracts.semantic_graph import SemanticRelationGoal

    goal = SemanticRelationGoal(id="goal-visited", subject="var_host", relation="visited", object="var_dom")

    # Operation claims relation_observable, but rows are completely unrelated (e.g. process data)
    op = ProviderOperation(
        id="op-bogus-visited",
        provider_id="splunk",
        scope_ids=("main",),
        guaranteed_relations=("visited",),
        proof_mode="relation_observable",
    )
    mock_exec = SimpleNamespace(
        step_id="step-1",
        operation_id="op-bogus-visited",
        result=QueryResult(
            query_id="q-1",
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=[{"bogus_field": "123"}],
            row_count=1,
        ),
        outputs={"object": "123"},
        query_id="q-1",
    )

    # In v9, this must be PROOF_GAP / UNPROVEN, NOT SUPPORTED
    from hunting.evidence.proof_engine import ProofEngine
    # The following assertion requires ProofEngine to evaluate the execution:
    proof_engine = ProofEngine()
    proof_res = proof_engine.evaluate(
        goal=goal,
        operation=op,
        query_result=mock_exec.result,
        observations=[],
    )
    assert not proof_res.verified, "ProofEngine must reject execution with non-conforming rows"

