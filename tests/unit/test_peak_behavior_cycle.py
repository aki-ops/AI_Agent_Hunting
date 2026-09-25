"""The logon hypothesis runs count, comparator, baseline, escalate, and Act as one cycle."""
from __future__ import annotations

from hunting.act.act import commit_act
from hunting.act_input import account_to_act_input
from hunting.contracts.cells import ProviderScope
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.evidence.behavior_comparator import derive_comparator
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.planner.behavior_cycle import run_behavior_cycle
from hunting.planner.semantic_executor import SemanticPlanExecutor

WINDOW = "2026-09-01T00:00:00Z/2026-09-20T00:00:00Z"
COUNT_SPL = "| tstats count where EventCode=4624 by user"
PROVE_SPL = "search index=wineventlog EventCode=4624 Logon_Type=10"


def _graph():
    graph = SemanticGoalGraph(
        id="g",
        request_id="req-logon",
        objective="service account interactive logon",
        variables=[
            SemanticVariable(id="service_account", entity_type="account"),
            SemanticVariable(id="windows_server", entity_type="endpoint"),
        ],
        relations=[SemanticRelationGoal(
            id="goal-1",
            subject="service_account",
            relation="logged_on_to",
            object="windows_server",
            goal_class="behavior",
        )],
    )
    graph.expected_magnitude = "small"
    return graph


def _scope():
    return ProviderScope(provider_id="splunk", native_partition={"index": "wineventlog"}, scope_id="splunk_wineventlog")


class _Adapter:
    def __init__(self, accounts: list[str], prove_rows: list[dict]):
        self.accounts = accounts
        self.prove_rows = prove_rows
        self.purposes: list[str] = []

    def execute_query(self, **kwargs):
        purpose = str((kwargs.get("parameters") or {}).get("purpose") or "")
        self.purposes.append(purpose)
        if purpose == "sizing":
            return QueryResult(
                query_id=kwargs["query_id"],
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=True,
                rows=[{"user": name, "host": "WIN-SRV", "timestamp": "2026-09-10T00:00:00Z"} for name in self.accounts],
                row_count=len(self.accounts),
                raw_count=20,
                native_query=COUNT_SPL,
            )
        return QueryResult(
            query_id=kwargs["query_id"],
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=self.prove_rows,
            row_count=len(self.prove_rows),
            native_query=PROVE_SPL,
        )


def test_count_is_a_ledger_observation_and_not_a_proof_citation():
    ledger = ObservationLedger()
    adapter = _Adapter(["svc-new"], [{
        "user": "svc-new", "host": "WIN-SRV", "timestamp": "2026-09-10T00:00:00Z",
    }])
    cycle = run_behavior_cycle(
        adapter=adapter,
        goal=_graph().relations[0],
        goal_graph=_graph(),
        scope=_scope(),
        time_window=WINDOW,
        operation_id="logon",
        ledger=ledger,
    )
    assert [obs.fields["observation_class"] for obs in ledger.observations] == ["SIZING"]
    assert cycle.queries[0]["native_query"] == COUNT_SPL
    assert cycle.prove_ran is True
    assert all(item.citation != cycle.sizing_observation.id for item in cycle.outcomes)


def test_twelve_accounts_stop_before_the_proof_query():
    ledger = ObservationLedger()
    names = [f"svc-{index}" for index in range(12)]
    adapter = _Adapter(names, [])
    cycle = run_behavior_cycle(
        adapter=adapter,
        goal=_graph().relations[0],
        goal_graph=_graph(),
        scope=_scope(),
        time_window=WINDOW,
        operation_id="logon",
        ledger=ledger,
    )
    assert adapter.purposes == ["sizing"]
    assert cycle.prove_ran is False
    assert cycle.escalated is True
    assert "12 distinct entities" in (cycle.escalation or "")


def test_first_seen_comes_from_rows_not_a_caller_flag():
    inside = {"user": "svc-new", "timestamp": "2026-09-10T00:00:00Z"}
    older = {"user": "svc-new", "timestamp": "2026-08-01T00:00:00Z"}
    fresh = derive_comparator([inside], [inside], (), window_start="2026-09-01T00:00:00Z", window_end="2026-09-20T00:00:00Z", value="svc-new")
    repeat = derive_comparator([inside], [inside, older], (), window_start="2026-09-01T00:00:00Z", window_end="2026-09-20T00:00:00Z", value="svc-new")
    assert fresh["first_seen"] is True
    assert repeat["first_seen"] is False


def test_logon_cycle_proves_first_seen_and_cites_baseline_without_benign(tmp_path):
    graph = _graph()
    ledger = ObservationLedger()
    prove_rows = [
        {"user": "svc-new", "host": "WIN-SRV", "timestamp": "2026-09-10T01:00:00Z"},
        {"user": "svc-backup", "host": "WIN-SRV", "timestamp": "2026-09-10T02:00:00Z"},
    ]
    adapter = _Adapter(["svc-new", "svc-backup"], prove_rows)
    cycle = run_behavior_cycle(
        adapter=adapter,
        goal=graph.relations[0],
        goal_graph=graph,
        scope=_scope(),
        time_window=WINDOW,
        operation_id="logon",
        ledger=ledger,
        baseline_values=("svc-backup",),
    )
    by_value = {item.value: item for item in cycle.outcomes}
    assert by_value["svc-new"].verdict == "PROVEN"
    assert by_value["svc-new"].comparator["first_seen"] is True
    assert by_value["svc-backup"].citation == "known-benign:svc-backup"
    assert by_value["svc-backup"].verdict != "BENIGN"
    assert adapter.purposes == ["sizing", "prove"]
    account_queries = cycle.queries
    from types import SimpleNamespace
    payload = account_to_act_input(SimpleNamespace(
        request_id="req-logon",
        stopping_decision="STOP_INCONCLUSIVE",
        hypotheses=[],
        observation_citations=[],
        gap_breakdown={},
        queries=account_queries,
        semantic_analysis={},
    ))
    assert payload["spls"] == [COUNT_SPL, PROVE_SPL]
    committed = commit_act(
        source="req-logon",
        spls=payload["spls"],
        backlog=[{"kind": "hypothesis", "text": "interactive service logon"}],
        stakeholder=["one proved, one known-benign"],
        detection_tier="report",
        export_dir=tmp_path,
    )
    assert committed["validations"] == ["DRAFT", "DRAFT"]


def test_large_cycle_act_keeps_the_count_query_and_the_gap():
    graph = _graph()
    ledger = ObservationLedger()
    names = [f"svc-{index}" for index in range(12)]
    adapter = _Adapter(names, [])
    cycle = run_behavior_cycle(
        adapter=adapter,
        goal=graph.relations[0],
        goal_graph=graph,
        scope=_scope(),
        time_window=WINDOW,
        operation_id="logon",
        ledger=ledger,
    )
    from types import SimpleNamespace
    payload = account_to_act_input(SimpleNamespace(
        request_id="req-logon",
        stopping_decision="STOP_INCONCLUSIVE",
        hypotheses=[],
        observation_citations=[],
        gap_breakdown={},
        queries=cycle.queries,
        semantic_analysis={"escalations": [cycle.escalation]},
    ))
    assert payload["spls"] == [COUNT_SPL]
    assert any("12 distinct entities" in gap for gap in payload["gaps"])
    assert "prove" not in adapter.purposes


def test_executor_uses_the_behavior_cycle_for_a_prove_step():
    graph = _graph()
    names = [f"svc-{index}" for index in range(12)]
    adapter = _Adapter(names, [])
    plan = LogicalPlan(
        id="plan-logon",
        goal_graph_id=graph.id,
        provider_id="splunk",
        steps=[PlanStep(
            id="step-logon",
            operation_id="logon",
            advances_goal_ids=("goal-1",),
            mode="PROVE",
        )],
    )
    ledger = ObservationLedger()
    SemanticPlanExecutor(adapter, ()).execute(
        plan,
        _scope(),
        WINDOW,
        goal_graph=graph,
        ledger=ledger,
    )
    assert adapter.purposes == ["sizing"]
    assert ledger.observations[0].fields["observation_class"] == "SIZING"
    assert graph.escalations
