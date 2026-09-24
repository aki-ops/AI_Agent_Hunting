import pytest

from hunting.contracts.lifecycle import (
    AnalystDecision,
    CapabilityArtifact,
    KnowledgeCandidate,
    LifecycleStatus,
)
from hunting.registry.content_registry import KnowledgePromotionGate, VersionedContentRegistry


def test_approved_capability_requires_tests_and_compiler():
    registry = VersionedContentRegistry()
    artifact = registry.register(CapabilityArtifact(
        id="artifact.process", version="1", owner="team",
        provider_compiler_ref="splunk.process.v1", fixtures=("positive", "negative"),
        limitations=("retrieval only",),
        completeness_contract={"coverage": "sample"},
    ))

    approved = registry.transition(artifact.id, artifact.version, LifecycleStatus.APPROVED)

    assert approved.executable is True
    assert registry.list(LifecycleStatus.APPROVED) == (approved,)


def test_approved_content_without_conformance_fixture_is_rejected():
    registry = VersionedContentRegistry()
    item = registry.register(CapabilityArtifact(
        id="artifact.unreviewed", version="1", owner="team",
        provider_compiler_ref="splunk.any.v1",
    ))

    with pytest.raises(ValueError, match="fixtures/tests"):
        registry.transition(item.id, item.version, LifecycleStatus.APPROVED)


def test_registering_approved_artifact_without_fixtures_is_rejected():
    registry = VersionedContentRegistry()
    with pytest.raises(ValueError, match="fixtures/tests"):
        registry.register(CapabilityArtifact(
            id="artifact.preapproved", version="1", owner="team",
            provider_compiler_ref="splunk.any.v1",
            status=LifecycleStatus.APPROVED,
        ))


def test_approved_artifact_without_fixtures_is_not_executable():
    artifact = CapabilityArtifact(
        id="artifact.no-fixture", version="1", owner="team",
        provider_compiler_ref="splunk.any.v1",
        status=LifecycleStatus.APPROVED,
    )
    assert artifact.executable is False


def test_llm_cannot_approve_content():
    registry = VersionedContentRegistry()
    item = registry.register(CapabilityArtifact(
        id="artifact.llm", version="1", owner="team",
        provider_compiler_ref="splunk.any.v1",
        fixtures=("positive", "negative"),
        limitations=("retrieval only",),
        completeness_contract={"coverage": "sample"},
    ))
    with pytest.raises(ValueError, match="LLM"):
        registry.transition(item.id, item.version, LifecycleStatus.APPROVED, actor="llm")


def test_proof_capable_artifact_requires_unrelated_row_and_role_swap():
    registry = VersionedContentRegistry()
    item = registry.register(CapabilityArtifact(
        id="artifact.proof", version="1", owner="team",
        provider_compiler_ref="splunk.proof.v1",
        fixtures=("positive", "negative"),
        limitations=("needs role-swap fixture",),
        completeness_contract={"proof_contract_id": "contract.visited.v1"},
    ))
    with pytest.raises(ValueError, match="unrelated_row"):
        registry.transition(item.id, item.version, LifecycleStatus.APPROVED)


def test_knowledge_promotion_requires_human_reviewer_and_tests():
    candidate = KnowledgeCandidate(
        id="kc-1", kind="mapping", source_run_id="run-1",
        evidence_refs=("obs-1",), required_tests=("fixture-1",),
    )

    with pytest.raises(ValueError):
        KnowledgePromotionGate.promote(candidate, reviewer=None, tests_passed=True)
    with pytest.raises(ValueError):
        KnowledgePromotionGate.promote(candidate, reviewer="analyst", tests_passed=False)

    event = KnowledgePromotionGate.promote(
        KnowledgeCandidate(
            id="kc-1", kind="mapping", source_run_id="run-1",
            evidence_refs=("obs-1",), required_tests=("fixture-1",),
            scope={"provider": "mock"}, temporal_validity={"window": "P1D"},
        ),
        reviewer="analyst", tests_passed=True,
    )
    assert event["status"] == "approved"


def test_drift_revokes_approved_capability_and_decision_is_serializable():
    registry = VersionedContentRegistry()
    registry.register(CapabilityArtifact(
        id="artifact.schema", version="1", owner="team",
        provider_compiler_ref="splunk.v1", schema_version="schema-1",
        fixtures=("fixture",), status=LifecycleStatus.APPROVED,
    ))
    changed = registry.invalidate_for_drift(schema_version="schema-2", reason="schema changed")

    assert changed[0].status == LifecycleStatus.REVOKED
    decision = AnalystDecision(
        id="decision-1", run_id="run-1", actor="analyst", decision="select",
        citations=("obs-1",), timestamp="2026-09-20T00:00:00Z",
    )
    assert decision.to_dict()["citations"] == ["obs-1"]
