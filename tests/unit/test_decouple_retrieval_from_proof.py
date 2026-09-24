"""Unit test for Phase 5: Decouple retrieval from proof.

Enforces:
1. An unproven secondary compiler constraint on an upstream relation does NOT block downstream retrieval.
2. Downstream query executes with the discovered entity and gathers observations.
3. Compiler-proposed descriptive restrictions are limitations, not
   INCONCLUSIVE_RESTRICTIONS_UNVERIFIED.
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
)
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.engine import HypothesisHuntEngine


class SingleHostAdapterWithRestrictions:
    """Mock adapter returning 1 host for a user, and files on a host."""

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
            operations=[
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
                    proof_mode="relation_observable",
                    # Note: does NOT support 'hardware_form_factor' constraint
                    supported_constraints=(),
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
            ],
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
            # Returns 1 host for mallory
            rows = [{"host": "MACLORY-AIR13", "user": "mallory"}]
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=True,
                rows=rows,
                row_count=len(rows),
                native_query=f"search user={ent_val} | table host, user",
            )
        elif operation_id == "find-files-on-host":
            rows = [{"file": "sensitive_doc.pdf", "host": ent_val, "action": "modified"}]
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


def test_unproven_constraint_does_not_block_downstream_retrieval() -> None:
    """Phase 5: An unproven constraint gathers evidence downstream; ProofEngine withholds SUPPORTED."""
    adapter = SingleHostAdapterWithRestrictions()
    graph = SemanticGoalGraph(
        id="graph-mallory-constraints",
        request_id="req-mallory-c1",
        objective="Find sensitive files on Mallory's MacBook",
        variables=[
            SemanticVariable(id="var_user", entity_type="account", value="mallory", value_origin="request"),
            # Host has an explicit secondary constraint: hardware_form_factor=MacBook
            SemanticVariable(
                id="var_endpoint",
                entity_type="endpoint",
                value=None,
                value_origin="llm_proposal",
                constraints=(SemanticConstraint(key="hardware_form_factor", value="MacBook"),),
            ),
            SemanticVariable(id="var_file", entity_type="file", value=None, value_origin="llm_proposal"),
        ],
        relations=[
            SemanticRelationGoal(id="rel_user_host", subject="var_user", relation="associated_with", object="var_endpoint", required=True),
            SemanticRelationGoal(id="rel_host_file", subject="var_endpoint", relation="modified", object="var_file", required=True),
        ],
        answers=[SemanticAnswerGoal(variable_id="var_file", answer_type="file")],
    )

    req = HuntRequest(
        id="req-mallory-c1",
        kind=HuntRequestKind.NL_QUESTION,
        content="Find sensitive files on Mallory's MacBook",
        entities=[Account(username="mallory")],
    )

    engine = HypothesisHuntEngine()

    # Pre-populate compilation cache to supply the test graph deterministically
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

    # 1. Verification: Downstream query WAS executed (not blocked by unproven constraint)
    executed_ops = [op for op, _ in adapter.calls]
    assert "resolve-user-host" in executed_ops
    assert "find-files-on-host" in executed_ops

    # 2. Verification: Downstream file query executed against the grounded host
    assert any(op == "find-files-on-host" and ent == "MACLORY-AIR13" for op, ent in adapter.calls)

    # 3. Compiler-proposed hardware_form_factor is not a proof obligation.
    semantic_analysis = result.account.semantic_analysis or {}
    goal_verdicts = {gv["goal_id"]: gv for gv in semantic_analysis.get("goal_verdicts", [])}

    assert "rel_user_host" in goal_verdicts
    assert goal_verdicts["rel_user_host"]["status"] != "INCONCLUSIVE_RESTRICTIONS_UNVERIFIED"
    assert "hardware_form_factor=MacBook" not in goal_verdicts["rel_user_host"]["unverified_restrictions"]

    # rel_host_file has no unverified restrictions and is SUPPORTED
    assert "rel_host_file" in goal_verdicts
    assert goal_verdicts["rel_host_file"]["status"] == "SUPPORTED"

    # Every provider execution is charged exactly once to the authoritative
    # SearchEnvelope budget and mirrored by the legacy compatibility counters.
    executed_query_count = len(adapter.calls)
    assert executed_query_count == 2
    assert len(result.state.queries) == executed_query_count
    assert result.state.query_count == executed_query_count
    assert engine.budget_ledger.query_count == executed_query_count
    assert result.state.search_envelope is not None
    assert (
        result.state.search_envelope.budgets.consumed_queries
        == executed_query_count
    )
