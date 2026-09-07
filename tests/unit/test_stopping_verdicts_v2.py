"""Unit tests for Phase 3: Stopping & Verdict Logic, causality, and budget exhaustion handling."""
from __future__ import annotations

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    EvidenceCard,
    EvidenceRequirementV4,
    HuntOutcome,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.controller.controller import CanonicalActionController
from hunting.controller.models import HuntBudgetLedger
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_final_hunt_account


def test_budget_exhaustion_never_emits_critical_finding_adversary_confirmed():
    """When budget is exhausted before full chain completion, outcome is INCONCLUSIVE_BUDGET_EXHAUSTED."""
    budget = HuntBudgetLedger(max_queries=1, query_count=1)
    controller = CanonicalActionController(budget_ledger=budget)

    hyp = Hypothesis(
        id="hyp-web",
        statement="Adversary compromised web server",
        status=HypothesisStatus.LIVE,
        requirements=["req-web", "req-proc"],
    )
    req_web = EvidenceRequirementV4(id="req-web", description="Web request", evidence_type="web_request")
    req_proc = EvidenceRequirementV4(id="req-proc", description="Process execution", evidence_type="process_execution")

    card_web = EvidenceCard(
        id="card-1",
        fingerprint="fp-web",
        fact_type="web_request",
        count=1,
        entity_summary={"hosts": ["we1149srv"]},
    )

    state = HuntState(
        hypotheses=[hyp],
        requirements=[req_web, req_proc],
        evidence_cards=[card_web],
    )

    decision = controller.evaluate_stopping(state)
    assert decision == StoppingDecision.STOP_EXHAUSTED_BY_BUDGET

    account = build_final_hunt_account(state)
    assert account.outcome == HuntOutcome.INCONCLUSIVE_BUDGET_EXHAUSTED

    report = render_final_hunt_account(account)
    # Critical invariant: MUST NOT emit "CRITICAL FINDING: Adversary Activity Confirmed"
    assert "CRITICAL FINDING: Adversary Activity Confirmed" not in report
    assert "INCONCLUSIVE_BUDGET_EXHAUSTED" in report
    assert "Investigation Budget Exhausted Before Completion" in report


def test_budget_exhaustion_with_supported_hypothesis_yields_supported_with_limitations():
    """When a hypothesis was supported before budget exhausted, outcome is SUPPORTED_WITH_LIMITATIONS."""
    budget = HuntBudgetLedger(max_queries=2, query_count=2)
    controller = CanonicalActionController(budget_ledger=budget)

    hyp = Hypothesis(
        id="hyp-rce",
        statement="Adversary executed remote code via web shell",
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-web", "req-proc", "req-file"],
    )
    req_web = EvidenceRequirementV4(id="req-web", description="Web request", evidence_type="web_request")
    req_proc = EvidenceRequirementV4(id="req-proc", description="Process execution", evidence_type="process_execution")
    req_file = EvidenceRequirementV4(id="req-file", description="File modification", evidence_type="file_modification")

    # Multi-stage verified on same host
    cards = [
        EvidenceCard(id="c1", fingerprint="fp1", fact_type="web_request", count=1, entity_summary={"hosts": ["we1149srv"]}, time_summary={"earliest": "2026-09-01T12:00:00Z"}),
        EvidenceCard(id="c2", fingerprint="fp2", fact_type="process_execution", count=1, entity_summary={"hosts": ["we1149srv"]}, time_summary={"earliest": "2026-09-01T12:02:00Z"}),
        EvidenceCard(id="c3", fingerprint="fp3", fact_type="file_modification", count=1, entity_summary={"hosts": ["we1149srv"]}, time_summary={"earliest": "2026-09-01T12:03:00Z"}),
    ]

    obs = [
        Observation(id="o1", provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "main"}), cell_id="c", timestamp="2026-09-01T12:00:00Z", epistemic_type=EpistemicType.OBSERVED, fields={"host": "we1149srv"}),
    ]

    state = HuntState(
        hypotheses=[hyp],
        requirements=[req_web, req_proc, req_file],
        evidence_cards=cards,
        observations=obs,
    )

    decision = controller.evaluate_stopping(state)
    assert decision == StoppingDecision.STOP_EXHAUSTED_BY_BUDGET

    account = build_final_hunt_account(state)
    assert account.outcome == HuntOutcome.SUPPORTED_WITH_LIMITATIONS

    report = render_final_hunt_account(account)
    assert "SUPPORTED_WITH_LIMITATIONS" in report
    assert "CRITICAL FINDING: Adversary Activity Confirmed" not in report


def test_web_requests_alone_yield_inconclusive_not_supported():
    """Web traffic alone cannot conclude compromise without server-side execution/file modification."""
    budget = HuntBudgetLedger(max_queries=10, query_count=1)
    controller = CanonicalActionController(budget_ledger=budget)

    hyp = Hypothesis(
        id="hyp-web",
        statement="Adversary compromised web server",
        status=HypothesisStatus.SUPPORTED,  # Candidate was tentatively supported by test
        requirements=["req-web"],
    )
    req_web = EvidenceRequirementV4(id="req-web", description="Web request", evidence_type="web_request")

    card_web = EvidenceCard(
        id="c-web",
        fingerprint="fp-web",
        fact_type="web_request",
        count=100,
        entity_summary={"hosts": ["we1149srv"]},
    )

    state = HuntState(
        hypotheses=[hyp],
        requirements=[req_web],
        evidence_cards=[card_web],
    )

    controller.evaluate_stopping(state)

    # Invariant: Guard weakened hypothesis because proc & file stages are absent!
    assert hyp.status == HypothesisStatus.WEAKENED
    account = build_final_hunt_account(state)
    assert account.outcome in (HuntOutcome.INCONCLUSIVE, HuntOutcome.NO_EVIDENCE_FOUND)
