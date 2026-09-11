from __future__ import annotations

from hunting.contracts.bindings import (
    BindingDirectness,
    CandidateBinding,
    CandidateSet,
    ConfidenceClass,
)
from hunting.human_loop.clarification import (
    ClarificationController,
    DisambiguationAction,
    DisambiguationCheckpoint,
    DiscriminatorQuerySpec,
)


def test_candidate_binding_serialization_and_proof_validity() -> None:
    """Verify CandidateBinding attributes, serialization, and is_valid_proof property."""
    # A valid proof binding: relation contract present, facts cited, no contradictions, HIGH confidence, DIRECT
    valid_binding = CandidateBinding(
        value="MACLORY-AIR13",
        entity_type="host",
        supporting_fact_ids=("fact-logon-1",),
        relation_contract_id="contract-logged-on-to-v1",
        directness=BindingDirectness.DIRECT.value,
        contradictions=(),
        confidence_class=ConfidenceClass.HIGH.value,
    )
    assert valid_binding.is_valid_proof is True

    # Binding with contradictions is NOT valid proof
    contradicted = CandidateBinding(
        value="MACLORY-AIR13",
        entity_type="host",
        supporting_fact_ids=("fact-logon-1",),
        relation_contract_id="contract-logged-on-to-v1",
        contradictions=("fact-concurrent-logon-elsewhere",),
        confidence_class=ConfidenceClass.HIGH.value,
    )
    assert contradicted.is_valid_proof is False

    # Binding without contract ID is NOT valid proof
    no_contract = CandidateBinding(
        value="MACLORY-AIR13",
        entity_type="host",
        supporting_fact_ids=("fact-logon-1",),
        relation_contract_id="",
        confidence_class=ConfidenceClass.HIGH.value,
    )
    assert no_contract.is_valid_proof is False

    # Serialization test
    d = valid_binding.to_dict()
    restored = CandidateBinding.from_dict(d)
    assert restored.value == valid_binding.value
    assert restored.relation_contract_id == valid_binding.relation_contract_id
    assert restored.is_valid_proof is True


def test_gate_single_proof_supported_host_autobinds() -> None:
    """Gate 08: Exactly 1 valid proof-supported host auto-binds without user intervention."""
    cset = CandidateSet(variable_id="endpoint", entity_type="host")
    binding = CandidateBinding(
        value="WIN-SERVER-01",
        entity_type="host",
        supporting_fact_ids=("fact-proven-session",),
        relation_contract_id="contract-logged-on-to-v1",
        confidence_class=ConfidenceClass.HIGH.value,
    )
    cset.add_candidate(binding)

    assert cset.can_autobind is True
    assert cset.is_ambiguous is False

    resolved = cset.try_autobind()
    assert resolved is not None
    assert resolved.value == "WIN-SERVER-01"
    assert cset.resolution_status == "AUTO_BOUND"


def test_gate_host_containing_air_does_not_win_by_heuristic() -> None:
    """Gate 08: When 2 hosts exist, host containing 'air' does NOT win by substring heuristic."""
    cset = CandidateSet(variable_id="endpoint", entity_type="host")

    # Candidate 1: Contains 'air' in name
    cand_air = CandidateBinding(
        value="MACLORY-AIR13",
        entity_type="host",
        supporting_fact_ids=("fact-1",),
        relation_contract_id="contract-logged-on-to-v1",
        confidence_class=ConfidenceClass.HIGH.value,
    )
    # Candidate 2: Generic desktop host
    cand_desktop = CandidateBinding(
        value="DESKTOP-MALLORY",
        entity_type="host",
        supporting_fact_ids=("fact-2",),
        relation_contract_id="contract-logged-on-to-v1",
        confidence_class=ConfidenceClass.HIGH.value,
    )

    cset.add_candidate(cand_air)
    cset.add_candidate(cand_desktop)

    # Invariant: Must be flagged ambiguous, auto-binding strictly forbidden
    assert cset.is_ambiguous is True
    assert cset.can_autobind is False

    resolved = cset.try_autobind()
    assert resolved is None
    assert cset.resolution_status == "NEEDS_DISAMBIGUATION"
    assert cset.selected_binding is None


def test_gate_two_matching_hosts_trigger_discriminator_or_clarification() -> None:
    """Gate 08: 2 candidate hosts trigger discriminator query, then halt with checkpoint."""
    cset = CandidateSet(variable_id="endpoint", entity_type="host")
    cset.add_candidate(
        CandidateBinding(
            value="HOST-ALPHA",
            entity_type="host",
            supporting_fact_ids=("fact-10",),
            relation_contract_id="contract-1",
            confidence_class=ConfidenceClass.HIGH.value,
        )
    )
    cset.add_candidate(
        CandidateBinding(
            value="HOST-BETA",
            entity_type="host",
            supporting_fact_ids=("fact-11",),
            relation_contract_id="contract-1",
            confidence_class=ConfidenceClass.HIGH.value,
        )
    )

    controller = ClarificationController(interactive=False, max_discriminator_attempts=1)

    # First attempt: Synthesizes DISCRIMINATOR query action
    action, payload = controller.resolve_candidate_set(cset, request_id="req-test")
    assert action == DisambiguationAction.DISCRIMINATE
    assert isinstance(payload, DiscriminatorQuerySpec)
    assert payload.target_variable_id == "endpoint"
    assert "HOST-ALPHA" in payload.candidate_values
    assert "HOST-BETA" in payload.candidate_values

    # Second attempt (after discriminator exhausted without differentiating):
    # Non-interactive controller must halt with NEEDS_DISAMBIGUATION and emit checkpoint
    action2, payload2 = controller.resolve_candidate_set(cset, request_id="req-test")
    assert action2 == DisambiguationAction.NEEDS_DISAMBIGUATION
    assert isinstance(payload2, DisambiguationCheckpoint)
    assert payload2.status == "NEEDS_DISAMBIGUATION"
    assert payload2.resume_token != ""
    assert "HOST-ALPHA" in payload2.candidate_values
    assert "HOST-BETA" in payload2.candidate_values


def test_interactive_mode_emits_interactive_clarification_checkpoint() -> None:
    """Verify interactive mode renders CLARIFY_INTERACTIVE question."""
    cset = CandidateSet(variable_id="account", entity_type="account")
    cset.add_candidate(
        CandidateBinding("mallory.k", "account", ("f1",), "contract-acct", confidence_class=ConfidenceClass.HIGH.value)
    )
    cset.add_candidate(
        CandidateBinding("mkraeusen", "account", ("f2",), "contract-acct", confidence_class=ConfidenceClass.HIGH.value)
    )

    controller = ClarificationController(interactive=True, max_discriminator_attempts=0)
    action, payload = controller.resolve_candidate_set(cset, request_id="req-user")

    assert action == DisambiguationAction.CLARIFY_INTERACTIVE
    assert isinstance(payload, DisambiguationCheckpoint)
    assert "mallory.k" in payload.candidate_values
    assert "mkraeusen" in payload.candidate_values
