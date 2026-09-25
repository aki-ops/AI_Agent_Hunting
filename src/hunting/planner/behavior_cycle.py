"""Behavior goals: count first, then prove only when the set is small enough.

The count is a ledger observation. It is not a proof citation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryResult
from hunting.evidence.behavior_comparator import benign_citation, derive_comparator
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.planner.sizing import escalation_for, measure_sizing


@dataclass
class EntityOutcome:
    value: str
    verdict: str
    citation: str | None = None
    comparator: dict[str, bool] = field(default_factory=dict)


@dataclass
class BehaviorCycleResult:
    sizing_observation: Observation
    escalated: bool
    escalation: str | None
    prove_ran: bool
    queries: list[dict[str, str]]
    outcomes: list[EntityOutcome]
    sizing_query: QueryResult
    prove_query: QueryResult | None = None


def _call(adapter: Any, **kwargs: Any) -> QueryResult:
    import inspect
    accepted = inspect.signature(adapter.execute_query).parameters
    payload = {key: value for key, value in kwargs.items() if key in accepted or "kwargs" in accepted}
    return adapter.execute_query(**payload)


def _sizing_facts(result: QueryResult) -> tuple[int, int, int, list[str]]:
    rows = list(result.rows or [])
    if rows and "distinct_entities" in rows[0]:
        users = rows[0].get("users") or []
        if isinstance(users, str):
            users = [users]
        scope = int(getattr(result, "raw_count", None) or rows[0].get("scope_count") or 0)
        return (
            int(rows[0].get("match_count") or result.row_count or 0),
            int(rows[0]["distinct_entities"]),
            max(scope, 1),
            [str(item) for item in users if str(item).strip()],
        )
    distinct = _entities(rows)
    return (
        int(getattr(result, "row_count", None) or len(rows)),
        len(distinct),
        int(getattr(result, "raw_count", None) or max(len(distinct), 1)),
        distinct,
    )


def _entities(rows: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for row in rows:
        value = str(row.get("account") or row.get("user") or row.get("username") or "").strip()
        if value and value not in found:
            found.append(value)
    return found


def _window_bounds(time_window: str) -> tuple[str, str]:
    start, _, end = str(time_window or "").partition("/")
    return start, end


def run_behavior_cycle(
    *,
    adapter: Any,
    goal: Any,
    goal_graph: Any,
    scope: ProviderScope,
    time_window: str,
    operation_id: str,
    ledger: ObservationLedger,
    baseline_values: tuple[str, ...] = (),
    history_rows: list[dict[str, Any]] | None = None,
    proof_engine: Any | None = None,
    limit: int = 100,
) -> BehaviorCycleResult:
    """Run the sizing query, then the proof query only when the set is small."""
    from hunting.evidence.proof_engine import ProofEngine

    engine = proof_engine or ProofEngine()
    magnitude = str(getattr(goal_graph, "expected_magnitude", "population") or "population")
    sizing_result = _call(
        adapter,
        operation_id=operation_id,
        entity=None,
        window=time_window,
        limit=limit,
        query_id=f"{goal.id}-sizing",
        parameters={"purpose": "sizing"},
    )
    rows = list(sizing_result.rows or [])
    match_count, distinct_n, scope_size, named_users = _sizing_facts(sizing_result)
    sizing = measure_sizing(
        match_count=match_count,
        distinct_entities=distinct_n,
        scope_size=scope_size,
        expected_magnitude=magnitude,
    )
    observation = Observation(
        id=f"obs-{goal.id}-sizing",
        provider_scope=scope,
        cell_id=f"cell-{goal.id}-sizing",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        epistemic_type=EpistemicType.OBSERVED,
        native_type="sizing",
        fields={
            "observation_class": "SIZING",
            "coverage_ratio": sizing.coverage_ratio,
            "match_count": sizing.match_count,
            "distinct_entities": sizing.distinct_entities,
            "strategy": sizing.strategy,
        },
        query_id=sizing_result.query_id,
    )
    ledger.add_observation(observation)
    queries = [{
        "purpose": "sizing",
        "query_id": sizing_result.query_id,
        "native_query": str(sizing_result.native_query or ""),
    }]
    note = escalation_for(sizing, magnitude)
    if note or sizing.strategy == "require_comparator":
        goal_graph.escalations = [*getattr(goal_graph, "escalations", ()), note or "escalate: comparator required before proof"]
        goal_graph.behavior_queries = queries
        goal_graph.benign_citations = []
        return BehaviorCycleResult(
            sizing_observation=observation,
            escalated=True,
            escalation=goal_graph.escalations[-1],
            prove_ran=False,
            queries=queries,
            outcomes=[],
            sizing_query=sizing_result,
        )

    prove_result = _call(
        adapter,
        operation_id=operation_id,
        entity=None,
        window=time_window,
        limit=limit,
        query_id=f"{goal.id}-prove",
        parameters={"purpose": "prove"},
    )
    queries.append({
        "purpose": "prove",
        "query_id": prove_result.query_id,
        "native_query": str(prove_result.native_query or ""),
    })
    goal_graph.behavior_queries = queries
    start, end = _window_bounds(time_window)
    outcomes: list[EntityOutcome] = []
    prove_rows = list(prove_result.rows or [])
    for value in _entities(prove_rows) or named_users:
        own_rows = [row for row in prove_rows if str(row.get("account") or row.get("user") or row.get("username") or "") == value]
        comparator = derive_comparator(
            own_rows,
            history_rows or rows,
            baseline_values,
            window_start=start,
            window_end=end,
            value=value,
        )
        citation = benign_citation(value, baseline_values)
        if citation:
            outcomes.append(EntityOutcome(value=value, verdict="CANDIDATE", citation=citation, comparator=comparator))
            continue
        proof = engine.evaluate(
            goal=goal,
            query_result=QueryResult(
                query_id=prove_result.query_id,
                outcome=prove_result.outcome,
                executed_ok=prove_result.executed_ok,
                complete=prove_result.complete,
                rows=own_rows,
                row_count=len(own_rows),
                native_query=prove_result.native_query,
            ),
            bindings={str(getattr(goal, "subject", "subject")): value},
            goal_graph=goal_graph,
            comparator=comparator,
            min_coverage_to_refute=getattr(goal_graph, "min_coverage_to_refute", None),
            coverage_ratio=sizing.coverage_ratio,
        )
        outcomes.append(EntityOutcome(
            value=value,
            verdict=str(proof.verdict),
            citation=None,
            comparator=comparator,
        ))
    goal_graph.benign_citations = [item.citation for item in outcomes if item.citation]
    return BehaviorCycleResult(
        sizing_observation=observation,
        escalated=False,
        escalation=None,
        prove_ran=True,
        queries=queries,
        outcomes=outcomes,
        sizing_query=sizing_result,
        prove_query=prove_result,
    )
