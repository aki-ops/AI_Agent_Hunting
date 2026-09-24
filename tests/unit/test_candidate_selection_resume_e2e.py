"""Unit tests for Phase 4: Semantic Graph Candidate Disambiguation and Resume without Recompilation.

Enforces:
1. 6 candidate hosts -> Agent does NOT guess or auto-select -> STOP_NEEDS_USER_DECISION.
2. User selects 1 host (e.g. MACLORY-AIR13).
3. Graph resumes without recompiling C1 (preserves request ID and semantic graph).
4. Binding is grounded as 'user_selection' into endpoint variable.
5. Downstream file query executes against selected host and produces evidence/answer.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.capabilities import ProviderCapabilityCatalog
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import Account
from hunting.contracts.hunt import (
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    Hypothesis,
    HypothesisOrigin,
    StoppingDecision,
)
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.engine import HypothesisHuntEngine


class MultiHostFileAdapter:
    """Mock adapter simulating 6 candidate hosts for a user, and files on a given host."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    @property
    def provider_id(self) -> str:
        return "mock-edr"

    @property
    def scope(self) -> ProviderScope:
        return ProviderScope(provider_id="mock-edr", native_partition={"index": "main"}, scope_id="scope-1")

    def discover_full_capabilities(self) -> ProviderCapabilityCatalog:
        return ProviderCapabilityCatalog(
            provider_id="mock-edr",
            status="ONLINE",
            operations=list(_build_test_operations()),
            details={},
        )

    def execute_query(
        self,
        operation_id: str,
        entity: Any,
        window: str,
        limit: int,
        query_id: str,
        **_kwargs: Any,
    ) -> QueryResult:
        ent_val = getattr(entity, "name", getattr(entity, "username", getattr(entity, "value", str(entity))))
        self.calls.append((operation_id, ent_val))

        if operation_id == "resolve-user-host":
            # Return 6 candidate hosts for mallory
            rows = [
                {"host": "WORKSTATION-01", "user": "mallory"},
                {"host": "WORKSTATION-02", "user": "mallory"},
                {"host": "WORKSTATION-03", "user": "mallory"},
                {"host": "WORKSTATION-04", "user": "mallory"},
                {"host": "WORKSTATION-05", "user": "mallory"},
                {"host": "MACLORY-AIR13", "user": "mallory"},
            ]
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=True,
                rows=rows,
                row_count=len(rows),
                native_query=f"search user={ent_val} | table host, user",
            )
        elif operation_id == "logged-on-to-host":
            rows = [
                {"host": "WORKSTATION-01", "user": ent_val},
                {"host": "WORKSTATION-02", "user": ent_val},
                {"host": "WORKSTATION-03", "user": ent_val},
                {"host": "WORKSTATION-04", "user": ent_val},
                {"host": "WORKSTATION-05", "user": ent_val},
                {"host": "MACLORY-AIR13", "user": ent_val},
            ]
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=True,
                rows=rows,
                row_count=len(rows),
                native_query=f"search user={ent_val} action=logon | table host, user",
            )
        elif operation_id == "find-files-on-host":
            # Return file modified on selected host
            rows = [{"file": "confidential_plan.docx", "host": ent_val, "action": "modified"}]
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=True,
                rows=rows,
                row_count=len(rows),
                native_query=f"search host={ent_val} | table file, host, action",
            )
        return QueryResult(
            query_id=query_id,
            outcome=QueryOutcome.EMPTY,
            executed_ok=True,
            complete=True,
            rows=[],
            row_count=0,
        )


def _build_test_graph() -> SemanticGoalGraph:
    return SemanticGoalGraph(
        id="graph-mallory-files",
        request_id="req-mallory-01",
        objective="Find confidential files on Mallory's endpoint",
        variables=[
            SemanticVariable(id="var_user", entity_type="account", value="mallory", value_origin="request"),
            SemanticVariable(id="var_endpoint", entity_type="endpoint", value=None, value_origin="llm_proposal"),
            SemanticVariable(id="var_file", entity_type="file", value=None, value_origin="llm_proposal"),
        ],
        relations=[
            SemanticRelationGoal(id="rel_user_host", subject="var_user", relation="associated_with", object="var_endpoint", required=True),
            SemanticRelationGoal(id="rel_host_file", subject="var_endpoint", relation="modified", object="var_file", required=True),
        ],
        answers=[SemanticAnswerGoal(variable_id="var_file", answer_type="file")],
    )


def _build_test_operations() -> list[ProviderOperation]:
    return [
        ProviderOperation(
            id="resolve-user-host",
            provider_id="mock-edr",
            scope_ids=("scope-1",),
            input_entity_kinds=("account",),
            output_entity_kinds=("host",),
            guaranteed_relations=("associated_with",),
            input_roles=("person", "account"),
        output_roles=("endpoint", "host"),
        output_value_bindings={"object": ("host",)},
        output_binding_entity_kinds={"object": "endpoint"},
        discriminator_fields=("logon_type",),
        proof_mode="relation_observable",
        ),
        ProviderOperation(
            id="logged-on-to-host",
            provider_id="mock-edr",
            scope_ids=("scope-1",),
            input_entity_kinds=("account",),
            output_entity_kinds=("host", "endpoint"),
            guaranteed_relations=("logged_on_to",),
            input_roles=("person", "account"),
        output_roles=("endpoint", "host"),
        output_value_bindings={"object": ("host",)},
        output_binding_entity_kinds={"object": "endpoint"},
        discriminator_fields=("logon_type",),
        proof_mode="relation_observable",
        ),
        ProviderOperation(
            id="find-files-on-host",
            provider_id="mock-edr",
            scope_ids=("scope-1",),
            input_entity_kinds=("host",),
            output_entity_kinds=("file",),
            guaranteed_relations=("modified",),
            input_roles=("endpoint", "host"),
            output_roles=("file",),
            output_value_bindings={"object": ("file",)},
            output_binding_entity_kinds={"object": "file"},
            proof_mode="relation_observable",
        ),
    ]


def test_six_candidate_hosts_triggers_stop_needs_user_decision() -> None:
    """Phase 4 Test 1: 6 candidate hosts -> agent does NOT guess -> STOP_NEEDS_USER_DECISION."""
    adapter = MultiHostFileAdapter()
    graph = _build_test_graph()
    req = HuntRequest(
        id="req-mallory-01",
        kind=HuntRequestKind.NL_QUESTION,
        content="Find confidential files on Mallory's endpoint",
        entities=[Account(username="mallory")],
    )

    engine = HypothesisHuntEngine()

    # Inject prepared graph and plan for deterministic test
    engine._semantic_compilation_cache[req.id] = (
        req.content,
        HuntObjective(
            request_id=req.id,
            statement=req.content,
            time_window="2026-02-01T00:00:00Z/P1D",
            semantic_goal_graph=graph,
        ),
        [Hypothesis("h1", req.content, HypothesisOrigin.INPUT)],
        [],
    )

    result = engine.execute_hunt(req, adapter=adapter)

    # 1. Verification: Agent must NOT guess, must stop with STOP_NEEDS_USER_DECISION
    assert result.account.stopping_decision == StoppingDecision.STOP_NEEDS_USER_DECISION
    # 2. No graph qualifier authorizes a second discriminator query. The
    # complete candidate set is preserved and downstream proof is blocked.
    executed_ops = [op for op, _ in adapter.calls]
    assert executed_ops[0] in {"resolve-user-host", "logged-on-to-host"}
    assert "find-files-on-host" not in executed_ops
    endpoint_set = result.state.candidate_sets.get("var_endpoint")
    assert endpoint_set is not None
    assert len(endpoint_set.valid_candidates) == 6


def test_user_selection_resumes_graph_and_executes_downstream_file_query() -> None:
    """Phase 4 Test 2: User selects MACLORY-AIR13 -> graph resumes without recompiling C1 -> executes downstream file query."""
    adapter = MultiHostFileAdapter()
    graph = _build_test_graph()

    req = HuntRequest(
        id="req-mallory-01",
        kind=HuntRequestKind.NL_QUESTION,
        content="Find confidential files on Mallory's endpoint",
        entities=[Account(username="mallory")],
    )

    engine = HypothesisHuntEngine()

    # Prime cache so C1 is NOT recompiled
    engine._semantic_compilation_cache[req.id] = (
        req.content,
        HuntObjective(
            request_id=req.id,
            statement=req.content,
            time_window="2026-02-01T00:00:00Z/P1D",
            semantic_goal_graph=graph,
        ),
        [Hypothesis("h1", req.content, HypothesisOrigin.INPUT)],
        [],
    )

    # Run pass 1: produces 6 candidate hosts
    result1 = engine.execute_hunt(req, adapter=adapter)
    assert result1.account.stopping_decision == StoppingDecision.STOP_NEEDS_USER_DECISION

    # Pass 2: User selects candidate host MACLORY-AIR13
    # Resume with initial_bindings
    result2 = engine.execute_hunt(
        req,
        adapter=adapter,
        initial_bindings={"var_endpoint": "MACLORY-AIR13"},
    )

    # Downstream file query must have executed against MACLORY-AIR13
    executed_calls = adapter.calls
    assert any(op == "find-files-on-host" and ent == "MACLORY-AIR13" for op, ent in executed_calls)
    assert result2.account.stopping_decision == StoppingDecision.STOP_ANSWERED
    identity = next(
        item for item in result2.state.semantic_analysis["goal_verdicts"]
        if item["goal_id"] == "rel_user_host"
    )
    assert identity["status"] == "BINDING_SELECTED"
    assert all(
        not proof.get("verified")
        for proof in identity["proof_results"]
        if "user_selection_binding" in proof.get("reason_codes", [])
    )


def test_resume_hunt_resumes_in_place_without_restarting() -> None:
    """Verify engine.resume_hunt resumes directly on result.state without calling census or compiler."""
    adapter = MultiHostFileAdapter()
    graph = _build_test_graph()

    req = HuntRequest(
        id="req-mallory-resume",
        kind=HuntRequestKind.NL_QUESTION,
        content="Find confidential files on Mallory's endpoint",
        entities=[Account(username="mallory")],
    )

    engine = HypothesisHuntEngine()

    engine._semantic_compilation_cache[req.id] = (
        req.content,
        HuntObjective(
            request_id=req.id,
            statement=req.content,
            time_window="2026-02-01T00:00:00Z/P1D",
            semantic_goal_graph=graph,
        ),
        [Hypothesis("h1", req.content, HypothesisOrigin.INPUT)],
        [],
    )

    result1 = engine.execute_hunt(req, adapter=adapter)
    assert result1.account.stopping_decision == StoppingDecision.STOP_NEEDS_USER_DECISION

    # Spy on census service to ensure it is NOT called during resume_hunt
    census_calls = 0
    orig_census = engine.census_service.census
    def _spy_census(*args: Any, **kwargs: Any) -> Any:
        nonlocal census_calls
        census_calls += 1
        return orig_census(*args, **kwargs)
    engine.census_service.census = _spy_census

    # Resume directly on result1.state
    result2 = engine.resume_hunt(
        result1.state,
        initial_bindings={"var_endpoint": "MACLORY-AIR13"},
        adapter=adapter,
    )

    assert census_calls == 0, "resume_hunt must not re-run census!"
    assert result2.account.stopping_decision == StoppingDecision.STOP_ANSWERED
    assert any(op == "find-files-on-host" and ent == "MACLORY-AIR13" for op, ent in adapter.calls)


def test_semantic_hunt_does_not_call_legacy_evaluate_stopping() -> None:
    adapter = MultiHostFileAdapter()
    graph = _build_test_graph()
    req = HuntRequest(
        id="req-mallory-01",
        kind=HuntRequestKind.NL_QUESTION,
        content="Find confidential files on Mallory's endpoint",
        entities=[Account(username="mallory")],
    )
    engine = HypothesisHuntEngine()
    engine._semantic_compilation_cache[req.id] = (
        req.content,
        HuntObjective(
            request_id=req.id,
            statement=req.content,
            time_window="2026-02-01T00:00:00Z/P1D",
            semantic_goal_graph=graph,
        ),
        [Hypothesis("h1", req.content, HypothesisOrigin.INPUT)],
        [],
    )
    calls: list[str] = []
    original = engine.controller.evaluate_stopping

    def _spy(state):
        calls.append("legacy_stop")
        return original(state)

    engine.controller.evaluate_stopping = _spy  # type: ignore[method-assign]
    result = engine.execute_hunt(req, adapter=adapter)
    assert result.account.stopping_decision == StoppingDecision.STOP_NEEDS_USER_DECISION
    assert calls == []
