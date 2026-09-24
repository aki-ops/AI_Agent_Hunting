"""Workstream L / M1 production-path counterexamples.

These tests exercise the default engine path. Injecting route_goal_ids or
calling the planner in isolation is not sufficient evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hunting.capabilities.runtime_materializer import materialize_runtime_operation
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, StoppingDecision
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.source_profile import (
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetryFieldProfile,
    TelemetrySourceProfile,
)
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from tests.unit.test_v9_provider_boundaries import MockProviderAdapter, _stub_compiler_payload


def _vocab_mismatch_graph(host_value: str = "HOST-1") -> str:
    return json.dumps({
        "id": "graph-vocab-mismatch",
        "request_id": "req-f1-prod",
        "objective": "observe a process",
        "variables": [
            {
                "id": "host",
                "entity_type": "host",
                "value": host_value,
                "value_origin": "request",
                "verification_status": "UNVERIFIED",
                "constraints": [],
            },
            {
                "id": "process",
                "entity_type": "process",
                "value": None,
                "value_origin": "llm_proposal",
                "verification_status": "UNVERIFIED",
                "constraints": [],
            },
        ],
        "relations": [
            {
                "id": "goal-query",
                "subject": "host",
                "relation": "unregistered action",
                "object": "process",
                "required": True,
                "description": "novel wording for a host-to-process observation",
                "atomic_obligation": "observe process",
                "provenance_span": "observe a process",
                "dependencies": [],
                "dependency_operator": "AND",
                "gate_condition": None,
            }
        ],
        "qualifiers": [],
        "answers": [{"variable_id": "process", "answer_type": "process", "required": True}],
        "assumptions": [],
        "uncertainties": [],
        "forbidden_inferences": [],
        "clarification_triggers": [],
    })


def test_f1_executable_typed_route_reaches_engine_query_without_c2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "process_creation",
        "host": "HOST-1",
        "pid": 7,
        "image": "/bin/sh",
        "cmdline": "sh -c id",
    }])
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda *_args, **_kwargs: _vocab_mismatch_graph())
    c2_calls = {"count": 0}

    def forbidden_c2(*_args: Any, **_kwargs: Any) -> str:
        c2_calls["count"] += 1
        raise AssertionError("C2 must not run when F1 admits an executable typed route")

    engine = HypothesisHuntEngine(
        compiler=compiler,
        source_profiler_caller=forbidden_c2,
        configured_adapters=[adapter],
    )
    result = engine.execute_hunt(
        HuntRequest(
            id="req-f1-prod",
            kind=HuntRequestKind.QUESTION,
            content="Which process ran on HOST-1?",
            provider_hints=("cdb",),
        ),
        adapter=adapter,
    )

    assert c2_calls["count"] == 0
    assert len(result.state.queries) >= 1
    assert result.state.stopping_decision != StoppingDecision.STOP_UNSUPPORTED
    audit = getattr(result.state, "source_profile_audit", {}) or {}
    assert str(audit.get("status", "")).upper() != "RELATION_SCOPED_PROFILING"


def test_no_llm_caller_cannot_complete_unsupported_census(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    irrelevant = MockProviderAdapter(
        "sensor_provider",
        [
            ProviderOperation(
                id="read_health",
                provider_id="sensor_provider",
                scope_ids=("sensor-scope",),
                input_entity_kinds=("ANY",),
                output_fields=("sensor_status",),
                output_fact_kinds=("sensor_health",),
                completeness="cursor EOF proof",
            )
        ],
    )
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda *_args, **_kwargs: _stub_compiler_payload("process_execution", ["host"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    result = engine.execute_hunt(
        HuntRequest(
            id="req-no-c2-census",
            kind=HuntRequestKind.QUESTION,
            content="Find process execution on host",
        ),
        adapters=[irrelevant],
    )

    assert result.state.stopping_decision != StoppingDecision.STOP_UNSUPPORTED
    assert result.state.stopping_decision in {
        StoppingDecision.STOP_INCONCLUSIVE,
        StoppingDecision.STOP_BUDGET,
    }
    assert irrelevant.executions == []


def test_deferred_c2_cannot_complete_unsupported_census(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    host_bearing = MockProviderAdapter(
        "sensor_provider",
        [
            ProviderOperation(
                id="read_health",
                provider_id="sensor_provider",
                scope_ids=("sensor-scope",),
                input_entity_kinds=("ANY",),
                output_fields=("sensor_status", "host"),
                output_fact_kinds=("sensor_health",),
                completeness="cursor EOF proof",
            )
        ],
    )
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda *_args, **_kwargs: _stub_compiler_payload("process_execution", ["host"])
    )

    def deferred_c2(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("LLM budget reserved before source profiling")

    engine = HypothesisHuntEngine(
        compiler=compiler,
        source_profiler_caller=deferred_c2,
    )
    result = engine.execute_hunt(
        HuntRequest(
            id="req-deferred-c2",
            kind=HuntRequestKind.QUESTION,
            content="Find process execution on host",
        ),
        adapters=[host_bearing],
    )

    assert result.state.stopping_decision != StoppingDecision.STOP_UNSUPPORTED
    assert result.state.stopping_decision in {
        StoppingDecision.STOP_INCONCLUSIVE,
        StoppingDecision.STOP_BUDGET,
    }
    assert host_bearing.executions == []
    audit = getattr(result.state, "source_profile_audit", {}) or {}
    assert _capability_census_mentions_deferral(audit)


def _capability_census_mentions_deferral(audit: dict[str, Any]) -> bool:
    statuses = {str(audit.get("status", "")).upper()}
    statuses.update(
        str(item.get("status", "")).upper()
        for item in audit.get("relation_calls") or ()
        if isinstance(item, dict)
    )
    return bool(statuses & {
        "RELATION_DEFERRED_BY_BUDGET",
        "LLM_BUDGET_EXHAUSTED_BEFORE_PROFILING",
        "NO_LLM_CALLER",
        "NO_PROFILE_BATCHES",
    })


def test_runtime_proposal_does_not_grant_relation_guarantee() -> None:
    profile = TelemetrySourceProfile(
        source_id="source-1",
        provider_id="mock",
        partition_id="scope",
        native_type="events",
        fields=(
            TelemetryFieldProfile("f-user", "user"),
            TelemetryFieldProfile("f-host", "host"),
        ),
    )
    proposal = SourceCapabilityProposal(
        source_id="source-1",
        relation="novel_wording",
        goal_id="goal-1",
        input_roles={"person": "f-user"},
        output_roles={"host": "f-host"},
    )
    capability = RuntimeCapability(
        capability_id="runtime:source-1:novel",
        provider_id="mock",
        source_id="source-1",
        relation="novel_wording",
        goal_id="goal-1",
        input_roles={"person": "f-user"},
        output_roles={"host": "f-host"},
        status="VALIDATED",
        proof_mode="retrieval_only",
        schema_fingerprint="fp-1",
    )

    operation = materialize_runtime_operation(
        proposal,
        profile,
        {"goal_id": "goal-1", "subject_type": "person", "object_type": "host"},
        capability,
    )

    assert operation is not None
    assert operation.route_goal_ids == ("goal-1",)
    assert operation.guaranteed_relations == ()
    assert operation.route_mode == "EXPLORE"
