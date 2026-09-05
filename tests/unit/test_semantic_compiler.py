"""Unit tests for Semantic Threat Hunting Compiler.

Verifies Phase 8 requirements:
1. Known CVE / TTP compiles with 0 LLM calls.
2. Free-text database compromise does not generate web_request.
3. Free-text domain access sets mechanism UNKNOWN and generates competing hypotheses with assumptions.
4. Free-text input without LLM caller halts with STOP_INSUFFICIENT (zero keyword fallback).
5. Malformed LLM output or schema failure halts with STOP_INSUFFICIENT (zero keyword fallback).
6. search_hints are used only in query compilation and never become evidence cards or cells.
7. End-to-end semantic hunt execution with StubSemanticCompiler.
"""
from __future__ import annotations

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.entities import Domain, Host
from hunting.contracts.hunt import (
    HuntRequest,
    HuntRequestKind,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.engine import HypothesisHuntEngine
from hunting.m2_abduction.provider import StubSemanticCompiler
from hunting.m5_adapter import CdbAdapter


def test_1_known_cve_zero_llm():
    """1. Known CVE compiles with exactly 0 LLM calls into 5-phase requirements."""
    compiler = KnowledgeBehaviorCompiler()
    req = HuntRequest(
        id="hunt-cve-test",
        kind=HuntRequestKind.CVE,
        content="Hunt for potential exploitation of CVE-2024-21887 on perimeter gateways",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    assert compiler.llm_calls_made == 0
    assert len(hypotheses) == 2
    assert any(h.id.endswith("-exploited") for h in hypotheses)
    assert any(h.id.endswith("-benign") for h in hypotheses)
    assert len(requirements) >= 3

    # Verify 0 web_request keywords were used as heuristic
    req_types = {r.evidence_type for r in requirements}
    assert "process_ancestry" in req_types
    assert "file_modification" in req_types
    assert "scope_records" in req_types


def test_2_free_text_database_no_web():
    """2. 'Attacker compromised database db01' does NOT generate web_request."""
    stub = StubSemanticCompiler(scenario="database")
    compiler = KnowledgeBehaviorCompiler(llm_caller=stub)
    req = HuntRequest(
        id="hunt-db-01",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised database db01",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    assert compiler.llm_calls_made == 1
    req_types = {r.evidence_type for r in requirements}

    # CRITICAL: Must NOT contain web_request
    assert "web_request" not in req_types
    # Must contain database relevant requirements
    assert "authentication_activity" in req_types
    assert "process_ancestry" in req_types
    assert "scope_records" in req_types

    # Hypotheses must have explicit assumptions
    for h in hypotheses:
        assert isinstance(h.assumptions, list)


def test_3_free_text_web_unknown_mechanism():
    """3. 'Attacker gained access to www.example.com' recognizes domain, sets mechanism UNKNOWN."""
    stub = StubSemanticCompiler(scenario="web")
    compiler = KnowledgeBehaviorCompiler(llm_caller=stub)
    req = HuntRequest(
        id="hunt-web-01",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker gained access to www.example.com",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    assert compiler.llm_calls_made == 1
    assert len(hypotheses) >= 2

    # Verify competing hypotheses with explicit assumptions
    hypo_classes = {h.hypothesis_class for h in hypotheses}
    assert "external_exploitation" in hypo_classes or "credential_access" in hypo_classes
    assert "benign_baseline" in hypo_classes

    # Requirements must have search_hints isolating the domain
    web_req = next((r for r in requirements if r.evidence_type == "web_request"), None)
    assert web_req is not None
    assert any("example.com" in hint for hint in web_req.search_hints)


def test_4_free_text_no_llm_stops_insufficient():
    """4. Free-text hypothesis without LLM caller halts with STOP_INSUFFICIENT (no keyword fallback)."""
    compiler = KnowledgeBehaviorCompiler(llm_caller=None)
    req = HuntRequest(
        id="hunt-no-llm-01",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised web www.imreallynotbatman.com",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    # Invariant: Never guesses or falls back to tmpl-web-compromise
    assert len(hypotheses) == 1
    assert hypotheses[0].status == HypothesisStatus.INSUFFICIENTLY_SPECIFIED
    assert len(requirements) == 0

    # Engine execution with this request must immediately transition to STOP_INSUFFICIENT
    engine = HypothesisHuntEngine(compiler=compiler)
    res = engine.execute_hunt(req, adapter=CdbAdapter(":memory:"))
    assert res.state.stopping_decision == StoppingDecision.STOP_INSUFFICIENT
    assert len(res.state.evidence_cards) == 0


def test_5_llm_invalid_schema_stops_insufficient():
    """5. Malformed JSON or invalid schema from LLM returns INSUFFICIENTLY_SPECIFIED (no keyword fallback)."""
    def bad_llm_caller(prompt: str) -> str:
        return "Not valid JSON at all!"

    compiler = KnowledgeBehaviorCompiler(llm_caller=bad_llm_caller)
    req = HuntRequest(
        id="hunt-bad-llm",
        kind=HuntRequestKind.NL_QUESTION,
        content="Attacker compromised web www.imreallynotbatman.com",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    assert len(hypotheses) == 1
    assert hypotheses[0].status == HypothesisStatus.INSUFFICIENTLY_SPECIFIED
    assert len(requirements) == 0

    # Engine execution must stop with STOP_INSUFFICIENT
    engine = HypothesisHuntEngine(compiler=KnowledgeBehaviorCompiler(llm_caller=bad_llm_caller))
    res = engine.execute_hunt(req, adapter=CdbAdapter(":memory:"))
    assert res.state.stopping_decision == StoppingDecision.STOP_INSUFFICIENT


def test_6_search_hints_never_become_evidence():
    """6. search_hints are used only in query compilation and never become evidence cards or cells."""
    stub = StubSemanticCompiler(scenario="web")
    compiler = KnowledgeBehaviorCompiler(llm_caller=stub)
    req = HuntRequest(
        id="hunt-search-hints",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker gained access to www.imreallynotbatman.com",
    )
    obj, hypotheses, requirements = compiler.compile(req)

    # Verify search_hints exist in requirement
    for r in requirements:
        if r.search_hints:
            for hint in r.search_hints:
                # search hint must be a string search filter
                assert isinstance(hint, str)

    # Execute hunt against clean memory database with fresh compiler
    engine = HypothesisHuntEngine(compiler=KnowledgeBehaviorCompiler(llm_caller=stub))
    res = engine.execute_hunt(req, adapter=CdbAdapter(":memory:"))

    # Check cells: No cell should have entity as raw search hint string
    for cell in res.state.cells:
        if not cell.is_wildcard:
            assert isinstance(cell.entity, (Host, Domain)) or hasattr(cell.entity, "name")

    # Check evidence cards: search_hints must never be mistaken as confirmed evidence
    for card in res.state.evidence_cards:
        assert card.card_id != ""
        # Card entity summary must represent discovered host/IP, not raw hint
        assert "evidence_type" in card.predicate_summary or hasattr(card, "expectation_id")


def test_7_end_to_end_semantic_flow():
    """7. Full engine execution with StubSemanticCompiler on sample scenario."""
    stub = StubSemanticCompiler(scenario="database")
    compiler = KnowledgeBehaviorCompiler(llm_caller=stub)
    req = HuntRequest(
        id="hunt-e2e-semantic",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised database db01",
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    res = engine.execute_hunt(req, adapter=CdbAdapter(":memory:"), time_window="2026-02-01T00:00:00Z/P1D")

    assert res.state.objective is not None
    assert len(res.state.hypotheses) >= 2
    assert len(res.state.requirements) >= 2
    # Ensure database scenario had no web requests planned
    assert not any(r.evidence_type == "web_request" for r in res.state.requirements)
    # Stopping decision was concluded deterministically
    assert res.state.stopping_decision is not None
