"""M5 production-path counterexamples: approved packages as F0, not proof.

Packages are control-plane records. Metadata cannot verify a relation.
A package is an F0 asset only after approve + fixtures.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hunting.capabilities.route_resolver import CapabilityRouteResolver
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.contracts.lifecycle import (
    AnalyticPackage,
    CapabilityArtifact,
    ContentFeedback,
    HuntPackage,
    LifecycleStatus,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import SemanticGoalGraph, SemanticRelationGoal, SemanticVariable
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.proof_engine import ProofEngine
from hunting.registry.content_registry import VersionedContentRegistry
from hunting.registry.package_f0 import (
    PackageBackendCompiler,
    compile_analytic_ir,
    compile_capability_artifact,
    f0_operations_from_registry,
    is_f0_asset,
)
from tests.unit.test_v9_open_vocabulary_production import _vocab_mismatch_graph
from tests.unit.test_v9_provider_boundaries import MockProviderAdapter


def _process_artifact(**overrides: Any) -> CapabilityArtifact:
    payload: dict[str, Any] = {
        "id": "artifact.host_process",
        "version": "1",
        "owner": "content-team",
        "input_roles": ("host",),
        "output_roles": ("process",),
        "provider_compiler_ref": "package.process.v1",
        "supported_entity_types": ("host", "process"),
        "limitations": ("retrieval only; package metadata is not proof",),
        "schema_version": "schema-1",
        "parser_version": "parser-1",
        "permission_version": "perm-1",
        "fixtures": ("positive", "negative"),
        "completeness_contract": {
            "coverage": "sample",
            "operation_ir": {
                "input_entity_kinds": ["host"],
                "output_entity_kinds": ["process"],
                "native_field_bindings": {"subject": ["host"]},
                "output_value_bindings": {"object": ["image"]},
            },
        },
    }
    payload.update(overrides)
    return CapabilityArtifact(**payload)


class _PackageAdapter(MockProviderAdapter):
    def discover_full_capabilities(self):
        catalog = super().discover_full_capabilities()
        catalog.source_profiles = [
            TelemetrySourceProfile(
                source_id="src-process",
                provider_id=self.provider_id,
                partition_id="main",
                native_type="opaque",
                fields=(
                    TelemetryFieldProfile("id-host", "host"),
                    TelemetryFieldProfile("id-image", "image"),
                ),
            )
        ]
        return catalog

    def execute_query(self, **kwargs: Any) -> QueryResult:
        self.executions.append(kwargs)
        return QueryResult(
            query_id=str(kwargs.get("query_id") or "q-package"),
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=[{"host": "HOST-1", "image": "/bin/sh", "pid": "7"}],
            row_count=1,
        )


def _approved_registry() -> VersionedContentRegistry:
    registry = VersionedContentRegistry()
    artifact = registry.register(_process_artifact())
    registry.transition(artifact.id, artifact.version, LifecycleStatus.APPROVED, actor="analyst")
    return registry


def test_draft_package_is_not_an_f0_asset():
    artifact = _process_artifact()
    assert artifact.executable is False
    assert is_f0_asset(artifact) is False
    with pytest.raises(ValueError, match="not an F0 asset"):
        compile_capability_artifact(artifact, provider_id="pkg_provider")


def test_analytic_ir_applies_named_transform_stages():
    package = AnalyticPackage(
        id="analytic.host_process",
        version="1",
        owner="content-team",
        semantic_expression={
            "input_roles": ["endpoint"],
            "output_roles": ["process"],
            "input_entity_kinds": ["host"],
            "output_entity_kinds": ["process"],
            "compiler_ref": "package.analytic.v1",
        },
        transformations=(
            {"stage": "normalize_roles", "mapping": {"endpoint": "host"}},
            {"stage": "project_fields", "roles": ["process"]},
            {"stage": "apply_constraints", "constraints": ["image"]},
        ),
        tests=("positive", "negative"),
        limitations=("ir is not proof",),
        status=LifecycleStatus.APPROVED,
    )
    ir = compile_analytic_ir(package)
    assert ir.input_roles == ("host",)
    assert ir.projection_roles == ("process",)
    assert "image" in ir.supported_constraints
    operation = PackageBackendCompiler().compile(ir, provider_id="pkg_provider")
    assert operation.discovery_provenance[0] == "F0_PACKAGE"
    assert "SPL" not in json.dumps(ir.to_dict())


def test_approved_package_is_f0_route_without_c2_or_c3(
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
    c2_calls = {"count": 0}

    def forbidden_c2(*_args: Any, **_kwargs: Any) -> str:
        c2_calls["count"] += 1
        raise AssertionError("C2 must not run when an approved F0 package route exists")

    engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph()),
        source_profiler_caller=forbidden_c2,
        configured_adapters=[adapter],
        content_registry=registry,
    )
    result = engine.execute_hunt(
        HuntRequest(
            id="req-m5-f0",
            kind=HuntRequestKind.QUESTION,
            content="Which process ran on HOST-1?",
            provider_hints=("pkg_provider",),
        ),
        adapter=adapter,
    )

    assert c2_calls["count"] == 0
    assert len(result.state.queries) >= 1
    assert all(not (query.parameters or {}).get("c3_invoked") for query in result.state.queries)
    routes = (getattr(result.state, "candidate_routes", {}) or {}).get("goal-query") or []
    assert any(
        (route.get("frontier_stage") == "F0_CERTIFIED" if isinstance(route, dict)
         else getattr(route, "frontier_stage", "") == "F0_CERTIFIED")
        for route in routes
    )
    versions = result.account.package_versions or result.state.package_versions
    assert any(item.get("id") == "artifact.host_process" and item.get("version") == "1" for item in versions)
    assert result.state.observations


def test_f0_package_path_is_cheaper_than_c2_mapping_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    irrelevant = [
        ProviderOperation(
            id="read_health",
            provider_id="pkg_provider",
            scope_ids=("scope",),
            input_entity_kinds=("sensor",),
            output_entity_kinds=("health",),
            output_fields=("sensor_status",),
        )
    ]

    def _run(registry: VersionedContentRegistry | None, counter: dict[str, int]) -> None:
        adapter = _PackageAdapter("pkg_provider", list(irrelevant))

        def count_c2(*_args: Any, **_kwargs: Any) -> str:
            counter["count"] += 1
            return json.dumps({"proposals": [], "rejected": ["no mapping"]})

        engine = HypothesisHuntEngine(
            compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph("HOST-1")),
            source_profiler_caller=count_c2,
            configured_adapters=[adapter],
            content_registry=registry,
        )
        engine.execute_hunt(
            HuntRequest(
                id="req-m5-cost",
                kind=HuntRequestKind.QUESTION,
                content="Which process ran on HOST-1?",
                provider_hints=("pkg_provider",),
            ),
            adapter=adapter,
        )

    f0_c2 = {"count": 0}
    f1_c2 = {"count": 0}
    _run(_approved_registry(), f0_c2)
    _run(None, f1_c2)
    assert f0_c2["count"] == 0
    assert f1_c2["count"] >= 1
    assert f0_c2["count"] < f1_c2["count"]


def test_package_metadata_cannot_verify_unrelated_or_role_swapped_rows():
    registry = _approved_registry()
    operation = compile_capability_artifact(registry.get("artifact.host_process", "1"), provider_id="pkg_provider")
    engine = ProofEngine()
    unrelated = engine.evaluate(
        goal=SemanticRelationGoal(id="g1", subject="var_host", relation="visited", object="var_dom"),
        operation=operation,
        query_result=QueryResult(
            query_id="q-unrelated",
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=[{"bogus_col": "xyz"}],
            row_count=1,
        ),
    )
    swapped = engine.evaluate(
        goal=SemanticRelationGoal(id="g2", subject="var_user", relation="logged_on_to", object="var_host"),
        operation=operation,
        query_result=QueryResult(
            query_id="q-swapped",
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=[{"query": "admin", "dest_ip": "10.0.0.1"}],
            row_count=1,
        ),
    )
    assert unrelated.verified is False
    assert swapped.verified is False
    assert unrelated.verdict == "PROOF_GAP"
    assert swapped.verdict == "PROOF_GAP"


def test_hunt_does_not_auto_approve_draft_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    registry = VersionedContentRegistry()
    registry.register(_process_artifact())
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
    engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph()),
        configured_adapters=[adapter],
        content_registry=registry,
    )
    engine.execute_hunt(
        HuntRequest(
            id="req-m5-draft",
            kind=HuntRequestKind.QUESTION,
            content="Which process ran on HOST-1?",
            provider_hints=("pkg_provider",),
        ),
        adapter=adapter,
    )
    leftover = registry.get("artifact.host_process", "1")
    assert leftover is not None
    assert leftover.status == LifecycleStatus.DRAFT
    assert leftover.executable is False
    assert f0_operations_from_registry(registry, "pkg_provider") == ()


def test_schema_parser_permission_drift_removes_f0_route():
    registry = _approved_registry()
    graph = SemanticGoalGraph(
        id="gg-1",
        request_id="req-drift",
        objective="observe a process",
        variables=[
            SemanticVariable(id="host", entity_type="host", value="HOST-1"),
            SemanticVariable(id="process", entity_type="process"),
        ],
        relations=[
            SemanticRelationGoal(id="goal-query", subject="host", relation="unregistered action", object="process"),
        ],
    )
    before = CapabilityRouteResolver().resolve(
        graph, (), "pkg_provider", content_registry=registry,
    )
    assert any(
        route.frontier_stage == "F0_CERTIFIED"
        for route in before.routes_by_goal.get("goal-query", ())
    )
    registry.invalidate_for_drift(schema_version="schema-2", reason="schema changed")
    registry.invalidate_for_drift(parser_version="parser-2", reason="parser changed")
    registry.invalidate_for_drift(permission_version="perm-2", reason="permission changed")
    after = CapabilityRouteResolver().resolve(
        graph, (), "pkg_provider", content_registry=registry,
    )
    assert f0_operations_from_registry(registry, "pkg_provider") == ()
    assert not any(
        route.frontier_stage == "F0_CERTIFIED"
        for route in after.routes_by_goal.get("goal-query", ())
    )


def test_false_positive_feedback_is_retained_and_not_auto_revoking():
    registry = _approved_registry()
    feedback = registry.record_feedback(ContentFeedback(
        id="fb-1",
        artifact_id="artifact.host_process",
        artifact_version="1",
        kind="false_positive",
        actor="analyst",
        citations=("obs-1",),
        note="row was administrative",
    ))
    assert registry.list_feedback(artifact_id="artifact.host_process") == (feedback,)
    assert registry.get("artifact.host_process", "1").status == LifecycleStatus.APPROVED
    triaged = registry.triage_feedback("fb-1", status="triaged", reviewer="analyst")
    assert triaged.status == "triaged"
    with pytest.raises(ValueError, match="LLM"):
        registry.triage_feedback("fb-1", status="wontfix", reviewer="llm")


def test_hunt_package_f0_requires_tests_and_does_not_alias_scenarios():
    package = HuntPackage(
        id="hunt.generic",
        version="1",
        owner="content-team",
        graph_template={"operation_ir": {
            "input_roles": ["host"],
            "output_roles": ["process"],
            "supported_entity_types": ["host", "process"],
            "compiler_ref": "package.hunt.v1",
            "native_field_bindings": {"subject": ["host"]},
            "output_value_bindings": {"object": ["image"]},
        }},
        tests=("positive", "negative"),
        limitations=("template is not a case branch",),
        completeness_contract={"coverage": "sample"},
        status=LifecycleStatus.APPROVED,
    )
    registry = VersionedContentRegistry()
    registry.register(package)
    operations = f0_operations_from_registry(registry, "pkg_provider")
    assert operations
    assert all("tor" not in operation.id.casefold() for operation in operations)
    assert all("amber" not in operation.id.casefold() for operation in operations)
    assert Observation(
        id="obs-1",
        provider_scope=ProviderScope("pkg_provider", {"source": "pkg"}, "scope"),
        cell_id="cell-1",
        timestamp="2026-09-21T00:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "HOST-1"},
        raw_event={"host": "HOST-1"},
    ).id == "obs-1"
