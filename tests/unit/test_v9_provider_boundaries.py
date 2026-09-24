"""Tests for v9 Workstream I: Provider Boundary Cleanup.

Gate I Acceptance Criteria:
- Provider absence, ambiguity, unsupported relation and backend degradation produce
  explicit states without switching to an unrelated backend.
- Remove implicit CDB fallback when no provider is configured.
- Do not select configured_adapters[0] when no eligible provider route exists.
- Keep source and field semantics in provider descriptors/manifests.
- Keep deterministic provider compilers for approved operations.
- Keep LLM native query generation quarantined and optional.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.capabilities import ProviderCapabilityCatalog
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    HuntRequest,
    StoppingDecision,
)
from hunting.contracts.native_query import NativeQueryCandidate, NativeQueryValidationResult
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.engine import HypothesisHuntEngine


class MockProviderAdapter:
    """Mock adapter for provider routing tests with explicit capability contracts."""

    def __init__(
        self,
        provider_id: str,
        operations: list[ProviderOperation] | None = None,
        *,
        status: str = "ONLINE",
    ) -> None:
        self.provider_id = provider_id
        self.scope = ProviderScope(
            provider_id=provider_id,
            native_partition={"source": provider_id},
            scope_id=f"{provider_id}_scope",
        )
        self._operations = operations or []
        self._status = status
        self.executions: list[dict[str, Any]] = []

    def discover_full_capabilities(self) -> ProviderCapabilityCatalog:
        observable: list[str] = []
        for op in self._operations:
            observable.extend(op.output_fields)
        return ProviderCapabilityCatalog(
            provider_id=self.provider_id,
            status=self._status,
            observable_fields=sorted(set(observable)) or ["event_id", "host"],
            operations=list(self._operations),
            permissions=["read"],
            completeness_semantics="cursor EOF proof",
        )

    def execute_query(self, **kwargs: Any) -> QueryResult:
        self.executions.append(kwargs)
        return QueryResult(
            query_id=kwargs.get("query_id", "q-mock"),
            outcome=QueryOutcome.UNKNOWN,
            executed_ok=True,
            complete=True,
            rows=[],
            row_count=0,
        )


def _stub_compiler_payload(fact_type: str = "process_execution", entity_types: list[str] | None = None) -> str:
    return json.dumps({
        "id": "graph-mock",
        "objective": "Test objective",
        "claims": [
            {
                "id": "claim-1",
                "fact_type": fact_type,
                "target_entity_type": (entity_types or ["host"])[0],
                "required_roles": entity_types or ["host"],
                "observation_requirements": [
                    {
                        "id": "req-1",
                        "fact_kind": fact_type,
                        "required_roles": entity_types or ["host"],
                        "field_roles": {"host": "host"},
                    }
                ],
            }
        ],
        "variables": [
            {"id": "host", "entity_type": "host", "value": "host-1"}
        ],
        "relations": [
            {"id": "rel-1", "subject": "host", "relation": fact_type, "object": "host", "required": True}
        ],
        "qualifiers": [],
        "answers": [{"variable_id": "host", "answer_type": "value", "required": True}],
        "assumptions": [],
        "uncertainties": [],
        "forbidden_inferences": [],
        "clarification_triggers": [],
    })


# =============================================================================
# 1. Provider Absence
# =============================================================================

def test_provider_absence_produces_explicit_unsupported_state_without_cdb(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When no provider adapter is configured, engine stops with STOP_UNSUPPORTED without CDB fallback."""
    monkeypatch.chdir(tmp_path)
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: _stub_compiler_payload("identity_binding", ["user"])
    )
    # Engine created without any adapter
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-no-provider",
        kind="NL_QUESTION",
        content="Which host did alice log on to?",
    )

    result = engine.execute_hunt(request)

    # Acceptance Gate I: Provider absence produces explicit STOP_UNSUPPORTED state
    assert result.state.stopping_decision == StoppingDecision.STOP_UNSUPPORTED
    assert any("provider absence" in r.lower() for r in result.state.residuals)
    assert len(result.state.queries) == 0
    # Invariant: No CDB sqlite files created in workspace
    assert not (tmp_path / "cdb.sqlite").exists()


# =============================================================================
# 2. Unsupported Relation & No Selection of configured_adapters[0]
# =============================================================================

def test_unsupported_relation_does_not_select_first_configured_adapter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When configured provider does not support the required relation, engine does NOT execute on it."""
    monkeypatch.chdir(tmp_path)
    # Irrelevant provider that only supports sensor_health
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
        llm_caller=lambda _: _stub_compiler_payload("process_execution", ["host"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-unsupported",
        kind="NL_QUESTION",
        content="Find process execution on host",
    )

    result = engine.execute_hunt(request, adapters=[irrelevant])

    # Vocabulary miss + no C2 caller is an incomplete census, not a completed
    # unsupported capability.  The irrelevant adapter still must not execute.
    assert result.state.stopping_decision != StoppingDecision.STOP_UNSUPPORTED
    assert result.state.stopping_decision in {
        StoppingDecision.STOP_INCONCLUSIVE,
        StoppingDecision.STOP_BUDGET,
    }
    assert irrelevant.executions == []


# =============================================================================
# 3. Backend Degradation
# =============================================================================

def test_backend_degradation_produces_explicit_unreachable_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When all configured providers are offline/unreachable, engine stops with STOP_UNREACHABLE without CDB fallback."""
    monkeypatch.chdir(tmp_path)
    degraded = MockProviderAdapter(
        "splunk_live",
        [
            ProviderOperation(
                id="search_events",
                provider_id="splunk_live",
                scope_ids=("splunk_scope",),
                input_entity_kinds=("ANY",),
                output_fields=("host", "process"),
                output_fact_kinds=("process_execution",),
                completeness="cursor EOF proof",
            )
        ],
        status="OFFLINE",
    )
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: _stub_compiler_payload("process_execution", ["host"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-degraded",
        kind="NL_QUESTION",
        content="Find process execution on host",
    )

    result = engine.execute_hunt(request, adapters=[degraded])

    # Acceptance Gate I: Backend degradation produces explicit STOP_UNREACHABLE
    assert result.state.stopping_decision == StoppingDecision.STOP_UNREACHABLE
    assert any("degradation" in r.lower() or "unreachable" in r.lower() for r in result.state.residuals)
    assert degraded.executions == []


# =============================================================================
# 4. Provider Ambiguity
# =============================================================================

def test_provider_ambiguity_produces_explicit_clarification_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When multiple eligible providers match without hints or priority, engine produces STOP_NEEDS_CLARIFICATION."""
    monkeypatch.chdir(tmp_path)
    op = ProviderOperation(
        id="query_process",
        provider_id="p1",
        scope_ids=("s1",),
        input_entity_kinds=("ANY", "host"),
        output_fields=("host", "process"),
        output_fact_kinds=("process_execution",),
        completeness="cursor EOF proof",
    )
    p1 = MockProviderAdapter("edr_alpha", [op])
    p2_op = ProviderOperation(
        id="query_process",
        provider_id="p2",
        scope_ids=("s2",),
        input_entity_kinds=("ANY", "host"),
        output_fields=("host", "process"),
        output_fact_kinds=("process_execution",),
        completeness="cursor EOF proof",
    )
    p2 = MockProviderAdapter("edr_beta", [p2_op])

    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: _stub_compiler_payload("process_execution", ["host"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-ambig",
        kind="NL_QUESTION",
        content="Check for malware execution on host",
        provider_hints=(),  # No hints to disambiguate!
    )

    result = engine.execute_hunt(request, adapters=[p1, p2])

    # Acceptance Gate I: Provider ambiguity produces explicit STOP_NEEDS_CLARIFICATION
    assert result.state.stopping_decision == StoppingDecision.STOP_NEEDS_CLARIFICATION
    assert any("ambiguity" in r.lower() for r in result.state.residuals)
    assert p1.executions == []
    assert p2.executions == []


# =============================================================================
# 5. Disambiguation via Provider Hints
# =============================================================================

def test_provider_disambiguation_via_request_hints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When provider hints are supplied, engine disambiguates and selects the specified provider."""
    monkeypatch.chdir(tmp_path)
    op1 = ProviderOperation(
        id="query_process",
        provider_id="edr_alpha",
        scope_ids=("s1",),
        input_entity_kinds=("ANY", "host"),
        output_fields=("host", "process"),
        output_fact_kinds=("process_execution",),
        completeness="cursor EOF proof",
    )
    p1 = MockProviderAdapter("edr_alpha", [op1])
    op2 = ProviderOperation(
        id="query_process",
        provider_id="edr_beta",
        scope_ids=("s2",),
        input_entity_kinds=("ANY", "host"),
        output_fields=("host", "process"),
        output_fact_kinds=("process_execution",),
        completeness="cursor EOF proof",
    )
    p2 = MockProviderAdapter("edr_beta", [op2])

    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: _stub_compiler_payload("process_execution", ["host"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-hinted",
        kind="NL_QUESTION",
        content="Check for malware execution on host",
        provider_hints=("edr_beta",),  # Explicit hint disambiguates!
    )

    result = engine.execute_hunt(request, adapters=[p1, p2])

    # Selected provider must be edr_beta
    assert result.state.capability_catalog.provider_id == "edr_beta"
    assert p1.executions == []


# =============================================================================
# 6. Quarantined LLM Native Query Boundary
# =============================================================================

def test_quarantined_native_query_candidate_validation() -> None:
    """NativeQueryCandidate enforces validation ceilings and rejects malformed provider candidates."""
    # Valid candidate
    cand = NativeQueryCandidate(
        provider="splunk",
        query_text="index=main sourcetype=WinEventLog:Security EventCode=4624",
        source_ids=("main",),
        time_window="NOW-1d/NOW",
        expected_fields=("host", "user"),
        max_rows=500,
        reason="Authentication proof",
    )
    assert cand.provider == "splunk"
    assert cand.max_rows == 500

    # Invalid empty provider / query_text rejected
    with pytest.raises(ValueError, match="provider and query_text"):
        NativeQueryCandidate(provider="", query_text="test")

    with pytest.raises(ValueError, match="provider and query_text"):
        NativeQueryCandidate(provider="splunk", query_text="   ")

    # Invalid max_rows ceiling rejected
    with pytest.raises(ValueError, match="max_rows"):
        NativeQueryCandidate(provider="splunk", query_text="test", max_rows=0)

    with pytest.raises(ValueError, match="max_rows"):
        NativeQueryCandidate(provider="splunk", query_text="test", max_rows=20000)

    # Validation result contracts
    val_res = NativeQueryValidationResult(
        accepted=True,
        normalized_query="index=main EventCode=4624",
        estimated_cost=2,
        reasons=("AST syntax verified",),
        query_signature="sig-123",
    )
    val_dict = val_res.to_dict()
    assert val_dict["accepted"] is True
    assert val_dict["estimated_cost"] == 2
    assert val_dict["query_signature"] == "sig-123"
