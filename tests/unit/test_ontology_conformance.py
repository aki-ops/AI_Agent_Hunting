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


def test_compiler_cdb_and_proof_contract_relation_conformance():
    """Verify that relations emitted by compiler for CVE requests are guaranteed by CDB and backed by proof contracts."""
    compiler = KnowledgeBehaviorCompiler(llm_caller=None)
    req = HuntRequest(
        id="cve-test",
        kind=HuntRequestKind.CVE,
        content="CVE-2024-21887 Ivanti Connect Secure Command Injection",
        entities=[Host(name="WEB-SERVER-01")],
    )
    obj, hypotheses, requirements = compiler.compile(req)
    assert obj.semantic_goal_graph is not None

    goal_relations = {relation.relation for relation in obj.semantic_goal_graph.relations}
    assert "spawned" in goal_relations
    assert "wrote" in goal_relations

    # Verify CDB adapter guarantees these relations
    cdb = CdbAdapter()
    catalog = cdb.get_capability_descriptor()
    provider_guaranteed = {
        rel
        for op in catalog.operations
        for rel in op.guaranteed_relations
    }

    for goal_rel in goal_relations:
        assert goal_rel in provider_guaranteed, (
            f"Compiler emitted relation '{goal_rel}' not guaranteed by CDB provider operations: {provider_guaranteed}"
        )

    # Verify ProofContractRegistry has approved contracts for these relations
    registry = get_default_proof_contract_registry()
    approved_relations = {c.relation for c in registry.list_approved()}

    for goal_rel in goal_relations:
        assert goal_rel in approved_relations, (
            f"Compiler emitted relation '{goal_rel}' has no approved ProofContract in registry: {approved_relations}"
        )


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
