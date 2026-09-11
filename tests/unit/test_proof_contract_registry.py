"""Unit tests for Phase 1 ProofContract and ProofContractRegistry.

Guarantees:
1. LLM proposals alone NEVER grant proof authority.
2. Only human-reviewed and approved ProofContracts can promote an operation to PROOF_CAPABLE.
3. DNS query -> person or unapproved mappings fail closed to RETRIEVAL_CAPABLE.
4. Role swap and cooccurrence cannot manufacture proof.
"""
from __future__ import annotations

from hunting.capabilities.profile_cache import RuntimeCapabilityCache
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.proof_contract import (
    ProofContract,
    ProofContractStatus,
)
from hunting.contracts.source_profile import (
    SourceCapabilityProposal,
    TelemetryFieldProfile,
    TelemetrySourceProfile,
)
from hunting.registry.proof_contract_registry import (
    get_default_proof_contract_registry,
)


def _sample_profile() -> TelemetrySourceProfile:
    return TelemetrySourceProfile(
        source_id="src-audit-1",
        provider_id="splunk",
        partition_id="index-sec",
        native_type="wineventlog:security",
        fields=(
            TelemetryFieldProfile("f_user", "TargetUserName", "string", 0.9, ("Mallory",)),
            TelemetryFieldProfile("f_host", "ComputerName", "string", 0.9, ("MACLORY-AIR13",)),
            TelemetryFieldProfile("f_ip", "IpAddress", "string", 0.8, ("10.0.1.50",)),
            TelemetryFieldProfile("f_dns_query", "query", "string", 0.7, ("berkbeer.com",)),
        ),
    )


def test_default_registry_contains_canonical_contracts() -> None:
    registry = get_default_proof_contract_registry()
    approved = registry.list_approved()
    relations = {c.relation for c in approved}

    assert "observed_transition" in relations
    assert "associated_with" in relations
    assert "logged_on_to" in relations
    assert "visited" in relations
    assert "sent_email" in relations
    assert "executed_process" in relations
    assert "installed_on" in relations


def test_proof_contract_conformance_validation() -> None:
    contract = ProofContract(
        contract_id="proof-test-v1",
        version="1.0.0",
        relation="associated_with",
        required_entity_roles=("person",),
        required_value_roles=("endpoint",),
        status=ProofContractStatus.APPROVED,
    )

    # 1. Matching roles pass
    ok, reasons = contract.validate_capability_conformance(
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
    )
    assert ok is True
    assert not reasons

    # 2. Missing value role fails
    ok, reasons = contract.validate_capability_conformance(
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"other": "f_host"},
    )
    assert ok is False
    assert any("missing_value_roles:endpoint" in r for r in reasons)

    # 3. Mismatched relation fails
    ok, reasons = contract.validate_capability_conformance(
        relation="different_relation",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
    )
    assert ok is False
    assert any("relation_mismatch" in r for r in reasons)

    # 4. Draft or retired status fails
    draft_contract = ProofContract(
        contract_id="proof-draft-v1",
        version="1.0.0",
        relation="associated_with",
        required_entity_roles=("person",),
        required_value_roles=("endpoint",),
        status=ProofContractStatus.DRAFT,
    )
    ok, reasons = draft_contract.validate_capability_conformance(
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
    )
    assert ok is False
    assert "contract_proof-draft-v1_is_DRAFT" in reasons[0]


def test_materialize_promotes_to_proof_capable_only_with_approved_contract() -> None:
    profile = _sample_profile()
    validator = SourceMappingValidator()

    # Proposal matches canonical proof-person-endpoint-v1
    proposal = SourceCapabilityProposal(
        source_id="src-audit-1",
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
        proof_mode="relation_observable",
    )

    # With probe pending: status is CANDIDATE, proof_mode is retrieval_only
    cap_pending = validator.materialize(proposal, profile, probe_succeeded=False)
    assert cap_pending.status == "CANDIDATE"
    assert cap_pending.proof_mode == "retrieval_only"
    assert cap_pending.capability_level == "RETRIEVAL_CAPABLE"

    # With probe succeeded: status is VALIDATED, promoted to relation_observable (PROOF_CAPABLE)
    cap_validated = validator.materialize(proposal, profile, probe_succeeded=True)
    assert cap_validated.status == "VALIDATED"
    assert cap_validated.proof_mode == "relation_observable"
    assert cap_validated.capability_level == "PROOF_CAPABLE"
    assert cap_validated.proof_contract_id == "proof-person-endpoint-v1"


def test_dns_query_to_person_fails_closed_and_cannot_become_proof_capable() -> None:
    """Gate test: Proposal claiming DNS query -> person proves association fails closed."""
    profile = _sample_profile()
    validator = SourceMappingValidator()

    # An LLM proposes that DNS query proves person identity (invalid semantic authority)
    bad_proposal = SourceCapabilityProposal(
        source_id="src-audit-1",
        relation="associated_with",
        input_roles={"dns_query": "f_dns_query"},
        output_roles={"person": "f_user"},
        proof_mode="relation_observable",  # LLM tries to claim proof authority!
    )

    # Even if probe succeeds, validator MUST downgrade to retrieval_only!
    cap = validator.materialize(bad_proposal, profile, probe_succeeded=True)
    assert cap.status == "VALIDATED"
    assert cap.proof_mode == "retrieval_only"
    assert cap.capability_level == "RETRIEVAL_CAPABLE"
    assert cap.proof_contract_id is None
    assert any("missing_value_roles:endpoint" in d or "no_approved_proof_contract" in d for d in cap.diagnostics)


def test_unregistered_novel_relation_defaults_to_retrieval_only() -> None:
    """A novel relation not yet reviewed by human experts cannot assert proof."""
    profile = _sample_profile()
    validator = SourceMappingValidator()

    novel_proposal = SourceCapabilityProposal(
        source_id="src-audit-1",
        relation="novel_custom_ai_relation",
        input_roles={"user": "f_user"},
        output_roles={"host": "f_host"},
        proof_mode="relation_observable",
    )

    cap = validator.materialize(novel_proposal, profile, probe_succeeded=True)
    assert cap.proof_mode == "retrieval_only"
    assert cap.capability_level == "RETRIEVAL_CAPABLE"
    assert cap.proof_contract_id is None


def test_runtime_capability_cache_invalidation_dimensions() -> None:
    cache = RuntimeCapabilityCache()
    key1 = cache.key(
        "splunk",
        "idx-sec",
        "schema-123",
        "sig-abc",
        tenant_id="tenant-A",
        principal_digest="sec-analyst",
        proof_contract_id="proof-contract-v1",
        parser_version="v1",
    )
    key2 = cache.key(
        "splunk",
        "idx-sec",
        "schema-123",
        "sig-xyz",
        tenant_id="tenant-B",
        principal_digest="admin",
        proof_contract_id="proof-contract-v2",
        parser_version="v1",
    )

    profile = _sample_profile()
    validator = SourceMappingValidator()
    prop = SourceCapabilityProposal(
        source_id="src-audit-1",
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
    )
    cap = validator.materialize(prop, profile)

    cache.put(key1, [cap])
    cache.put(key2, [cap])

    assert cache.get(key1) is not None
    assert cache.get(key2) is not None

    # Invalidate contract-v1
    cache.invalidate_contract("proof-contract-v1")
    assert cache.get(key1) is None
    assert cache.get(key2) is not None

    # Invalidate admin permission
    cache.invalidate_permission("admin")
    assert cache.get(key2) is None
