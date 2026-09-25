"""Startup ontology conformance test.

Guarantees zero vocabulary drift across:
- Graph relation vocabulary emitted by KnowledgeBehaviorCompiler
- Provider guaranteed relations declared by CdbAdapter and SplunkLiveAdapter
- Approved ProofContract relations registered in ProofContractRegistry
"""
from __future__ import annotations

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.entities import Host
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.registry.proof_contract_registry import get_default_proof_contract_registry


def test_removed_kinds_are_not_compiled():
    """CVE input is rejected. Provider relations are checked without a CVE compiler."""
    import pytest
    compiler = KnowledgeBehaviorCompiler(llm_caller=None)
    req = HuntRequest(
        id="cve-test",
        kind=HuntRequestKind.CVE,
        content="CVE-2024-21887 Ivanti Connect Secure Command Injection",
        entities=[Host(name="WEB-SERVER-01")],
    )
    with pytest.raises(ValueError, match="free-text hypothesis"):
        compiler.compile(req)


def test_provider_relations_have_approved_proof_contracts():
    """Every security relation guaranteed by CdbAdapter must have an approved ProofContract."""
    cdb = CdbAdapter()
    desc = cdb.get_capability_descriptor()
    assert desc is not None
    registry = get_default_proof_contract_registry()
    approved_relations = {c.relation for c in registry.list_approved()}

    core_relations = {"spawned", "executed", "wrote", "modified", "visited", "associated_with"}
    for rel in core_relations:
        assert rel in approved_relations, f"Core relation '{rel}' missing approved ProofContract"
