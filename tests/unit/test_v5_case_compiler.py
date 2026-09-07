"""Unit tests for v5 Semantic Case Compiler.

Verifies:
1. Free-text LLM compiler schema emits InvestigationCase (entities, claims, unknowns, relation paths).
2. Known CVE/TTP inputs compile deterministically with 0 LLM calls into InvestigationCase and InvestigationGraph.
3. Compiler output validator strictly rejects raw SPL syntax and vendor-specific telemetry terms.
4. Mandatory endpoint unknown insertion when subject is Person without proven host.
"""
from __future__ import annotations

import json

import pytest

from hunting.compiler.compiler import (
    KnowledgeBehaviorCompiler,
    parse_and_validate_semantic_intent,
    validate_compiler_output_integrity,
)
from hunting.contracts.case_graph import (
    InvestigationCase,
    NodeType,
    RelationType,
)
from hunting.contracts.hunt import (
    HuntRequest,
    HuntRequestKind,
)


def test_free_text_llm_compiler_emits_investigation_case():
    """Verify free-text compilation with LLM caller produces a valid InvestigationCase."""
    def stub_llm(prompt: str) -> str:
        return json.dumps({
            "semantic_intent": {
                "subject": {"type": "person", "value": "Amber Turing"},
                "requested_object": {"type": "domain", "role": "answer"},
                "behavior": "visited competitor beer website",
                "evidence_requirements": [
                    {
                        "semantic_intent": "web_navigation",
                        "required_fields": ["site", "uri"],
                        "necessity": "CRITICAL",
                        "description": "Find visited web domain",
                    }
                ],
            },
            "hypotheses": [
                {
                    "id": "hypo-1",
                    "statement": "Amber Turing accessed competitor website.",
                    "class": "unclassified",
                    "assumptions": ["Amber was logged on to a corporate endpoint"],
                    "requirements": ["req-1"],
                }
            ],
            "requirements": [
                {
                    "id": "req-1",
                    "semantic_intent": "web_navigation",
                    "necessity": "CRITICAL",
                    "search_hints": ["competitor-beer.com"],
                    "falsification_condition": "no matching web or proxy activity",
                    "description": "Identify web request from client IP",
                    "source_refs": ["USER_INPUT"],
                }
            ],
        })

    compiler = KnowledgeBehaviorCompiler(llm_caller=stub_llm)
    req = HuntRequest(
        id="hunt-amber-01",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Amber Turing visited a competitor website to find executive contact info.",
    )
    obj, hyps, reqs = compiler.compile(req)

    assert obj.case is not None
    assert isinstance(obj.case, InvestigationCase)
    assert obj.case_graph is not None

    # Invariant: Person subject MUST have mandatory endpoint unknown inserted
    unknown_types = [u.entity_type for u in obj.case.unknowns]
    assert NodeType.ENDPOINT in unknown_types
    assert NodeType.ACCOUNT in unknown_types
    assert NodeType.IP in unknown_types

    # Invariant: Case graph contains the causal chain
    assert len(obj.case.graph.edges) >= 4
    edges = list(obj.case.graph.edges.values())
    rel_types = [e.relation_type for e in edges]
    assert RelationType.OWNS in rel_types
    assert RelationType.LOGGED_ON_TO in rel_types
    assert RelationType.ASSIGNED_IP in rel_types
    assert RelationType.REQUESTED in rel_types


def test_deterministic_cve_compiles_to_case_with_zero_llm():
    """Verify known CVE-2024-21887 compiles deterministically into InvestigationCase with 0 LLM calls."""
    compiler = KnowledgeBehaviorCompiler(llm_caller=None)
    req = HuntRequest(
        id="hunt-cve-21887",
        kind=HuntRequestKind.CVE,
        content="Hunt for potential exploitation of CVE-2024-21887 on perimeter gateways",
    )
    obj, hyps, reqs = compiler.compile(req)

    assert compiler.llm_calls_made == 0
    assert obj.case is not None
    assert obj.case_graph is not None
    assert len(obj.case.graph.nodes) >= 3
    assert len(obj.case.graph.edges) >= 2

    # Edges: endpoint -> exploit proc -> webshell file
    edges = list(obj.case.graph.edges.values())
    rel_types = [e.relation_type for e in edges]
    assert RelationType.SPAWNED in rel_types
    assert RelationType.WROTE in rel_types

    # Unknowns must include exploit process and file
    unk_types = [u.entity_type for u in obj.case.unknowns]
    assert NodeType.PROCESS in unk_types
    assert NodeType.FILE in unk_types


def test_deterministic_ttp_compiles_to_case_with_zero_llm():
    """Verify MITRE TTP input compiles deterministically into InvestigationCase with 0 LLM calls."""
    compiler = KnowledgeBehaviorCompiler(llm_caller=None)
    req = HuntRequest(
        id="hunt-ttp-1059",
        kind=HuntRequestKind.TTP,
        content="Investigation of MITRE T1059 command and script execution",
    )
    obj, hyps, reqs = compiler.compile(req)

    assert compiler.llm_calls_made == 0
    assert obj.case is not None
    assert obj.case_graph is not None
    assert len(obj.case.graph.nodes) >= 2


def test_validator_rejects_raw_spl_syntax():
    """Verify compiler validator strictly rejects raw SPL syntax in LLM output."""
    bad_payload = {
        "semantic_intent": {
            "subject": {"type": "person", "value": "Amber"},
            "requested_object": {"type": "domain", "role": "answer"},
            "behavior": "search index=botsv2 sourcetype=stream:http | table _time, uri",
            "evidence_requirements": [],
        },
        "hypotheses": [],
        "requirements": [],
    }
    violations = validate_compiler_output_integrity(bad_payload)
    assert len(violations) >= 2
    assert any("Raw SPL syntax" in v for v in violations)

    with pytest.raises(ValueError, match="Compiler output validation failure"):
        parse_and_validate_semantic_intent(bad_payload)


def test_validator_rejects_vendor_specific_terms():
    """Verify compiler validator strictly rejects vendor-specific telemetry terms."""
    bad_payload = {
        "semantic_intent": {
            "subject": {"type": "endpoint", "value": "host01"},
            "requested_object": {"type": "event", "role": "answer"},
            "behavior": "sysmon EventCode 1 process execution",
            "evidence_requirements": [],
        },
        "hypotheses": [],
        "requirements": [],
    }
    violations = validate_compiler_output_integrity(bad_payload)
    assert any("Vendor-specific" in v and "sysmon" in v for v in violations)

    with pytest.raises(ValueError, match="Compiler output validation failure"):
        parse_and_validate_semantic_intent(bad_payload)
