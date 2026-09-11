"""Unit tests for Phase 6: Evidence Verification, Generic ProofContract Verification, and Stopping Taxonomy.

Covers:
- 9-state stopping taxonomy (ANSWER_PROVED, BOUNDED_NOT_FOUND, NEEDS_DISAMBIGUATION,
  COVERAGE_EXHAUSTED, BUDGET_EXHAUSTED, BACKEND_DEGRADED, SAFETY_QUARANTINE,
  VALIDATION_FAILED, ABORTED_BY_USER)
- FinalHuntAccount stopping_taxonomy_state persistence
- Gate verification 1: DNS lookup does not prove person visited domain
- Gate verification 2: Generic file creation does not prove ransomware encryption
- Gate verification 3: Correct answer value with false/uncited evidence fails verification
- Generic ProofContract evaluation against ledger-backed observations
"""
from __future__ import annotations

from types import SimpleNamespace

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    CoverageBound,
    FinalHuntAccount,
    HuntObjective,
    HuntOutcome,
    Hypothesis,
    StoppingDecision,
    StoppingTaxonomyState,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.proof_contract import ProofContract, ProofContractStatus
from hunting.evidence.answer_verifier import verify_answer
from hunting.evidence.relation_verifier import RelationVerifier, verify_relation_proof_contract
from hunting.m1_ledger.ledger import ObservationLedger


def _make_obs(
    obs_id: str,
    native_type: str = "sysmon",
    fields: dict | None = None,
    raw_event: dict | None = None,
) -> Observation:
    scope = ProviderScope(provider_id="splunk", scope_id="main", native_partition="default")
    return Observation(
        id=obs_id,
        provider_scope=scope,
        cell_id="test_cell",
        timestamp="2026-08-18T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type=native_type,
        fields=fields or {},
        raw_event=raw_event or {},
    )


def test_stopping_taxonomy_nine_states_and_decision_mapping() -> None:
    """Verify all 9 canonical stopping taxonomy states and StoppingDecision conversions."""
    states = {s.value for s in StoppingTaxonomyState}
    assert states == {
        "ANSWER_PROVED",
        "BOUNDED_NOT_FOUND",
        "NEEDS_DISAMBIGUATION",
        "COVERAGE_EXHAUSTED",
        "BUDGET_EXHAUSTED",
        "BACKEND_DEGRADED",
        "SAFETY_QUARANTINE",
        "VALIDATION_FAILED",
        "ABORTED_BY_USER",
    }

    assert StoppingDecision.STOP_RESOLVED.to_taxonomy_state() == StoppingTaxonomyState.ANSWER_PROVED
    assert StoppingDecision.STOP_BOUNDED.to_taxonomy_state() == StoppingTaxonomyState.BOUNDED_NOT_FOUND
    assert StoppingDecision.STOP_REFUTED.to_taxonomy_state() == StoppingTaxonomyState.BOUNDED_NOT_FOUND
    assert StoppingDecision.STOP_NEEDS_USER_DECISION.to_taxonomy_state() == StoppingTaxonomyState.NEEDS_DISAMBIGUATION
    assert StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED.to_taxonomy_state() == StoppingTaxonomyState.NEEDS_DISAMBIGUATION
    assert StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP.to_taxonomy_state() == StoppingTaxonomyState.COVERAGE_EXHAUSTED
    assert StoppingDecision.STOP_UNSUPPORTED.to_taxonomy_state() == StoppingTaxonomyState.COVERAGE_EXHAUSTED
    assert StoppingDecision.STOP_UNSUPPORTED_CAPABILITY.to_taxonomy_state() == StoppingTaxonomyState.COVERAGE_EXHAUSTED
    assert StoppingDecision.STOP_INSUFFICIENT.to_taxonomy_state() == StoppingTaxonomyState.COVERAGE_EXHAUSTED
    assert StoppingDecision.STOP_EXHAUSTED_BY_BUDGET.to_taxonomy_state() == StoppingTaxonomyState.BUDGET_EXHAUSTED
    assert StoppingDecision.STOP_BUDGET_EXHAUSTED.to_taxonomy_state() == StoppingTaxonomyState.BUDGET_EXHAUSTED
    assert StoppingDecision.STOP_UNREACHABLE.to_taxonomy_state() == StoppingTaxonomyState.BACKEND_DEGRADED


def test_final_hunt_account_persists_stopping_taxonomy_state() -> None:
    """Verify FinalHuntAccount computes and exposes stopping_taxonomy_state correctly."""
    obj = HuntObjective(request_id="req-1", statement="Find host")
    account = FinalHuntAccount(
        request_id="req-1",
        objective=obj,
        hypotheses=[Hypothesis(id="h1", statement="test hypo")],
        evidence_cards=[],
        queries=[],
        supporting=["h1"],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )
    assert account.taxonomy_state == StoppingTaxonomyState.ANSWER_PROVED
    assert account.outcome == HuntOutcome.SUPPORTED

    # Explicit override to SAFETY_QUARANTINE
    account_quarantine = FinalHuntAccount(
        request_id="req-2",
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
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP,
        stopping_taxonomy_state=StoppingTaxonomyState.SAFETY_QUARANTINE,
    )
    assert account_quarantine.taxonomy_state == StoppingTaxonomyState.SAFETY_QUARANTINE


def test_gate_dns_lookup_does_not_prove_person_visited_domain() -> None:
    """Gate verification: DNS resolution demonstrates domain lookup only; cannot prove web visit."""
    contract = ProofContract(
        contract_id="contract_person_visited_domain",
        version="1.0.0",
        relation="person_visited_domain",
        required_entity_roles=("user", "domain"),
        status=ProofContractStatus.APPROVED,
    )

    # Telemetry is strictly a DNS resolution record (stream:dns)
    dns_obs = _make_obs(
        "obs-dns-01",
        native_type="stream:dns",
        fields={"user": "Alice", "query": "evil-domain.com", "sourcetype": "stream:dns"},
    )

    ledger = ObservationLedger()
    ledger.add_observation(dns_obs)

    res = verify_relation_proof_contract(
        proof_contract=contract,
        observations=[dns_obs],
        ledger=ledger,
    )
    assert res.verified is False
    assert res.diagnostic == "dns_lookup_cannot_prove_web_visit"
    assert any("DNS lookup demonstrates host domain resolution only" in v for v in res.violations)


def test_gate_generic_file_creation_does_not_prove_ransomware_encryption() -> None:
    """Gate verification: generic file creation (EventCode 11) does not prove ransomware encryption."""
    contract = ProofContract(
        contract_id="contract_ransomware_encrypted_file",
        version="1.0.0",
        relation="ransomware_encrypted_file",
        required_entity_roles=("host", "file_path"),
        required_action_roles=("encrypt_action",),
        status=ProofContractStatus.APPROVED,
    )

    # Generic file create (e.g. Sysmon Event 11 without ransomware / crypto transition)
    create_obs = _make_obs(
        "obs-create-01",
        native_type="Sysmon",
        fields={"EventCode": "11", "host": "wrk-101", "TargetFilename": r"C:\Users\Alice\doc.docx", "action": "file_create"},
    )

    ledger = ObservationLedger()
    ledger.add_observation(create_obs)

    res = verify_relation_proof_contract(
        proof_contract=contract,
        observations=[create_obs],
        ledger=ledger,
    )
    assert res.verified is False
    assert res.diagnostic == "file_creation_does_not_prove_ransomware_encryption"
    assert any("Generic file creation does not prove ransomware encryption" in v for v in res.violations)


def test_gate_correct_answer_value_with_false_evidence_citation_fails_verification() -> None:
    """Gate verification: correct answer value with false or unrelated citation fails verification."""
    # The correct version is "12.0.1"
    # Case 1: Candidate cites card c_unrelated which contains an unrelated path and no version
    card_unrelated = SimpleNamespace(
        id="c_unrelated",
        field_summary={"Path": [r"C:\Windows\explorer.exe"], "Image": ["explorer.exe"]},
        representative_observation_ids=["obs-unrelated-1"],
    )

    res_fake_citation = verify_answer(
        answer={"status": "ANSWERED", "value": "12.0.1", "card_ids": ["c_unrelated"]},
        answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
        cards=[card_unrelated],
        query_complete=True,
    )
    # Verification MUST downgrade status; correct value does NOT save false citation!
    assert res_fake_citation["status"] != "ANSWERED"
    assert res_fake_citation["reason"] in ("ANSWER_VALUE_NOT_BOUND_TO_EVIDENCE", "REQUIRED_ANSWER_FIELDS_MISSING")

    # Case 2: Candidate cites valid card c_valid which actually observed "12.0.1"
    card_valid = SimpleNamespace(
        id="c_valid",
        field_summary={"ProductVersion": ["12.0.1"], "Path": [r"C:\Tor\firefox.exe"]},
        representative_observation_ids=["obs-valid-1"],
    )

    res_valid_citation = verify_answer(
        answer={"status": "ANSWERED", "value": "12.0.1", "card_ids": ["c_valid"]},
        answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
        cards=[card_valid],
        query_complete=True,
    )
    assert res_valid_citation["status"] == "ANSWERED"
    assert res_valid_citation["value"] == "12.0.1"


def test_proof_contract_verification_succeeds_with_valid_ledger_backed_observations() -> None:
    """Verify approved ProofContract succeeds when ledger-backed observations satisfy all roles."""
    contract = ProofContract(
        contract_id="contract_host_resolved_ip",
        version="1.0.0",
        relation="host_resolved_ip",
        required_entity_roles=("host", "ip"),
        status=ProofContractStatus.APPROVED,
    )

    valid_obs = _make_obs(
        "obs-host-ip-1",
        native_type="stream:dns",
        fields={"host": "WRK-ALICE", "dest_ip": "10.0.0.55"},
    )
    ledger = ObservationLedger()
    ledger.add_observation(valid_obs)

    verifier = RelationVerifier()
    res = verifier.verify_proof_contract(
        proof_contract=contract,
        observations=[valid_obs],
        ledger=ledger,
        expected_bindings={"host": "WRK-ALICE", "ip": "10.0.0.55"},
    )

    assert res.verified is True
    assert res.proof is not None
    assert res.proof.relation_type == "host_resolved_ip"
    assert "obs-host-ip-1" in res.proof.citations
    assert not res.violations


def test_proof_contract_unapproved_or_unbacked_fails_closed() -> None:
    """Verify unapproved contract or observation not in ledger fails closed."""
    # 1. Unapproved DRAFT contract
    draft_contract = ProofContract(
        contract_id="contract_draft_test",
        version="1.0.0",
        relation="novel_relation",
        required_entity_roles=("user",),
        status=ProofContractStatus.DRAFT,
    )
    obs = _make_obs("obs-01", fields={"user": "Alice"})
    ledger = ObservationLedger()
    ledger.add_observation(obs)

    res_draft = verify_relation_proof_contract(draft_contract, [obs], ledger=ledger)
    assert res_draft.verified is False
    assert "DRAFT" in res_draft.diagnostic

    # 2. Approved contract, but observation is NOT backed by ledger
    approved_contract = ProofContract(
        contract_id="contract_approved_test",
        version="1.0.0",
        relation="test_relation",
        required_entity_roles=("user",),
        status=ProofContractStatus.APPROVED,
    )
    unbacked_obs = _make_obs("obs-unbacked-999", fields={"user": "Alice"})
    res_unbacked = verify_relation_proof_contract(approved_contract, [unbacked_obs], ledger=ledger)
    assert res_unbacked.verified is False
    assert res_unbacked.diagnostic == "unbacked_observations"
