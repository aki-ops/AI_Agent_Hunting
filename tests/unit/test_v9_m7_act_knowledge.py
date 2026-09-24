"""M7 production-path counterexamples: Act and Knowledge promotion."""
from __future__ import annotations

from pathlib import Path

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.contracts.lifecycle import KnowledgeCandidate, KnowledgeReuseEvent
from hunting.contracts.queries import ProviderOperation
from hunting.engine import HypothesisHuntEngine
from hunting.lifecycle.acts import (
    ActEmitter,
    KnowledgePromotionGate,
    KnowledgeProposalGate,
    KnowledgeReuseLedger,
)
from tests.unit.test_v9_m5_package_f0 import _approved_registry, _PackageAdapter
from tests.unit.test_v9_open_vocabulary_production import _vocab_mismatch_graph


def test_act_kinds_require_citations_and_reject_llm_owner():
    with pytest.raises(ValueError, match="unknown action kind"):
        ActEmitter.emit(
            action_id="a1", kind="email_case", source_run_id="run-1", actor="analyst",
            evidence_refs=("obs-1",), limitations=("n/a",),
        )
    with pytest.raises(ValueError, match="cited run evidence"):
        ActEmitter.emit(
            action_id="a2", kind="detection_candidate", source_run_id="run-1", actor="analyst",
            limitations=("draft",),
        )
    with pytest.raises(ValueError, match="LLM"):
        ActEmitter.emit(
            action_id="a3", kind="no_action", source_run_id="run-1", actor="llm",
            limitations=("none",),
        )
    item = ActEmitter.emit(
        action_id="a4", kind="telemetry_gap", source_run_id="run-1", actor="analyst",
        evidence_refs=("obs-1",), limitations=("retention unknown",),
    )
    assert item.kind == "telemetry_gap"
    for kind in (
        "detection_candidate",
        "response_recommendation",
        "follow_up_hunt",
        "content_defect",
        "no_action",
    ):
        emitted = ActEmitter.emit(
            action_id=f"a-{kind}", kind=kind, source_run_id="run-1", actor="analyst",
            evidence_refs=("obs-1",) if kind != "no_action" else (),
            limitations=("bounded control-plane act",),
        )
        assert emitted.kind == kind
        assert emitted.limitations


def test_llm_or_single_run_cannot_auto_promote_knowledge():
    candidate = KnowledgeProposalGate.propose(
        candidate_id="kc-1", kind="mapping", source_run_id="run-1", actor="analyst",
        evidence_refs=("obs-1",), required_tests=("positive",),
        scope={"provider": "mock"}, temporal_validity={"window": "P1D"},
    )
    with pytest.raises(ValueError):
        KnowledgeProposalGate.propose(
            candidate_id="kc-llm", kind="mapping", source_run_id="run-1", actor="llm",
            evidence_refs=("obs-1",), required_tests=("positive",),
            scope={"provider": "mock"}, temporal_validity={"window": "P1D"},
        )
    incident = KnowledgeCandidate(
        id="kc-inc", kind="mapping", source_run_id="run-1",
        evidence_refs=("obs-1",), required_tests=("positive",),
        scope={"provider": "mock"}, temporal_validity={"window": "P1D"},
        confidence_class="INCIDENT_CONCLUSION",
    )
    with pytest.raises(ValueError):
        KnowledgePromotionGate.promote(incident, reviewer="analyst", tests_passed=True)
    with pytest.raises(ValueError):
        KnowledgePromotionGate.promote(candidate, reviewer="llm", tests_passed=True)
    with pytest.raises(ValueError):
        KnowledgePromotionGate.promote(candidate, reviewer="analyst", tests_passed=True, role="analyst")
    event = KnowledgePromotionGate.promote(candidate, reviewer="reviewer", tests_passed=True)
    assert event["status"] == "approved"


def test_hunt_emits_no_action_and_reviewed_candidate_can_become_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    adapter = _PackageAdapter(
        "pkg_provider",
        [
            ProviderOperation(
                id="read_health",
                provider_id="pkg_provider",
                scope_ids=("scope",),
                input_entity_kinds=("sensor",),
                output_entity_kinds=("health",),
                output_fields=("sensor_status",),
            )
        ],
    )
    registry = _approved_registry()
    engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph()),
        configured_adapters=[adapter],
        content_registry=registry,
    )
    result = engine.execute_hunt(
        HuntRequest(
            id="req-m7",
            kind=HuntRequestKind.QUESTION,
            content="Which process ran on HOST-1?",
            provider_hints=("pkg_provider",),
        ),
        adapter=adapter,
    )
    assert result.account.action_items
    assert result.account.action_items[0].kind == "no_action"
    assert result.account.lifecycle_record is not None
    assert result.state.knowledge_candidates == []

    detection = engine.emit_action(
        result.state,
        action_id="act-detect",
        kind="detection_candidate",
        actor="analyst",
        evidence_refs=tuple(obs.id for obs in result.state.observations[:1]) or ("obs-run",),
        limitations=("not a production detection",),
        outcome_ref=result.account.request_id,
    )
    assert detection.kind == "detection_candidate"
    candidate = engine.propose_knowledge(
        result.state,
        candidate_id="kc-run",
        kind="package",
        actor="analyst",
        evidence_refs=detection.evidence_refs,
        required_tests=("positive", "negative"),
        scope={"provider": "pkg_provider"},
        temporal_validity={"window": "P1D"},
    )
    assert candidate.review_status == "PENDING_REVIEW"
    event = KnowledgePromotionGate.promote(candidate, reviewer="reviewer", tests_passed=True)
    assert event["status"] == "approved"
    registry.register_knowledge(candidate)
    stored = registry.promote_knowledge("kc-run", reviewer="reviewer", tests_passed=True)
    assert stored.review_status == "APPROVED"
    registry.invalidate_for_drift(schema_version="schema-2", reason="schema changed")
    stored = registry.get_knowledge("kc-run")
    assert stored is not None
    assert stored.review_status == "REVOKED"
    assert registry.reuse_ledger.approval_rate() > 0
    assert registry.reuse_ledger.regression_rate() > 0
    ledger = KnowledgeReuseLedger()
    ledger.record(KnowledgeReuseEvent(id="e1", kind="proposed", artifact_id="a"))
    ledger.record(KnowledgeReuseEvent(id="e2", kind="approved", artifact_id="a"))
    ledger.record(KnowledgeReuseEvent(id="e3", kind="reused", artifact_id="a"))
    assert ledger.approval_rate() > 0
    assert ledger.reuse_rate() > 0
    assert ledger.regression_rate() == 0
    with pytest.raises(ValueError):
        engine.propose_knowledge(
            result.state,
            candidate_id="kc-llm",
            kind="package",
            actor="llm",
            evidence_refs=("obs-1",),
            required_tests=("positive",),
            scope={"provider": "pkg_provider"},
            temporal_validity={"window": "P1D"},
        )
