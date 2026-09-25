"""Behavior goals are counted before proof, including when the route is EXPLORE."""
from __future__ import annotations

from types import SimpleNamespace

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
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter
from hunting.planner.behavior_cycle import run_behavior_cycle
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner

WINDOW = "2026-09-01T00:00:00Z/2026-09-20T00:00:00Z"


def _graph():
    graph = SemanticGoalGraph(
        id="g-logon",
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
    graph.min_coverage_to_refute = 0.8
    return graph


def _scope():
    return ProviderScope(provider_id="cdb", native_partition={"table": "events"}, scope_id="cdb_events")


class _CountAdapter:
    def __init__(self, users: list[str]):
        self.users = users
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
                rows=[{
                    "match_count": len(self.users),
                    "distinct_entities": len(self.users),
                    "users": self.users,
                }],
                row_count=len(self.users),
                raw_count=20,
                native_query="SELECT COUNT(DISTINCT user)",
            )
        return QueryResult(
            query_id=kwargs["query_id"],
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=[{"user": name, "host": "WIN-SRV", "timestamp": "2026-09-10T00:00:00Z"} for name in self.users],
            row_count=len(self.users),
            native_query="SELECT * FROM events",
        )


def test_behavior_plan_counts_before_proof_without_a_known_account():
    graph = _graph()
    original = [PlanStep(
        id="step-explore",
        operation_id="search_text",
        input_bindings={"subject": "service_account"},
        output_bindings={"object": "windows_server"},
        advances_goal_ids=("goal-1",),
        relation="logged_on_to",
        mode="EXPLORE",
    )]
    steps = SemanticGoalPlanner._with_behavior_sizing(original, graph)
    assert [step.mode for step in steps] == ["SIZING", "EXPLORE"]
    assert steps[0].input_bindings == {}
    assert steps[1].depends_on == ("step-explore-sizing",)
    adapter = _CountAdapter(["svc-new"])
    SemanticPlanExecutor(adapter, ()).execute(
        LogicalPlan(id="p", goal_graph_id=graph.id, provider_id="cdb", steps=steps),
        _scope(),
        WINDOW,
        goal_graph=graph,
        ledger=ObservationLedger(),
    )
    assert adapter.purposes[0] == "sizing"


def test_explore_route_still_counts_a_behavior_goal():
    graph = _graph()
    adapter = _CountAdapter(["svc-new"])
    plan = LogicalPlan(
        id="p",
        goal_graph_id=graph.id,
        provider_id="cdb",
        steps=[PlanStep(
            id="step-explore",
            operation_id="search_text",
            input_bindings={"subject": "service_account"},
            advances_goal_ids=("goal-1",),
            relation="logged_on_to",
            mode="EXPLORE",
        )],
    )
    SemanticPlanExecutor(adapter, ()).execute(plan, _scope(), WINDOW, goal_graph=graph, ledger=ObservationLedger())
    assert "sizing" in adapter.purposes


def test_splunk_sizing_is_a_count_and_cdb_sizing_counts_distinct_users():
    splunk = SplunkLiveAdapter(
        splunk_url="http://offline",
        index="wineventlog",
        manifest_path="configs/splunk_botsv2.yaml",
        verify_ssl=False,
    )
    spl, _, _ = splunk._build_spl(
        "search_text", None, WINDOW, None, 10, purpose="sizing",
    )
    assert "dc(user)" in spl
    assert "head " not in spl

    cdb = CdbAdapter(":memory:")
    cdb.insert_events([
        {"timestamp": "2026-09-10T00:00:00Z", "native_type": "logon", "host": "WIN-SRV", "user": "svc-new"},
        {"timestamp": "2026-09-10T01:00:00Z", "native_type": "logon", "host": "WIN-SRV", "user": "svc-backup"},
        {"timestamp": "2026-09-10T02:00:00Z", "native_type": "logon", "host": "WIN-SRV", "user": "svc-new"},
    ])
    result = cdb.execute_query(
        operation_id="search_text",
        entity=None,
        window=WINDOW,
        query_id="q-size",
        parameters={"purpose": "sizing"},
    )
    assert "COUNT(DISTINCT user)" in result.native_query
    assert result.rows[0]["distinct_entities"] == 2
    assert result.rows[0]["match_count"] == 3
    assert result.raw_count == 3


def test_cycle_results_reach_the_account_and_low_coverage_is_not_refuted():
    seen: dict = {}

    class _Recorder:
        def evaluate(self, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(verdict="PROOF_GAP")

    graph = _graph()
    adapter = _CountAdapter(["svc-new"])
    cycle = run_behavior_cycle(
        adapter=adapter,
        goal=graph.relations[0],
        goal_graph=graph,
        scope=_scope(),
        time_window=WINDOW,
        operation_id="search_text",
        ledger=ObservationLedger(),
        proof_engine=_Recorder(),
    )
    account = SimpleNamespace(
        request_id="req-logon",
        stopping_decision="STOP_INCONCLUSIVE",
        hypotheses=[],
        observation_citations=[],
        gap_breakdown={},
        queries=[],
        semantic_analysis={
            "behavior_queries": cycle.queries,
            "benign_citations": ["known-benign:svc-backup"],
        },
    )
    payload = account_to_act_input(account)
    assert payload["spls"] == ["SELECT COUNT(DISTINCT user)", "SELECT * FROM events"]
    assert seen["min_coverage_to_refute"] == 0.8
    assert seen["coverage_ratio"] < 0.8
    assert seen["coverage_ratio"] == cycle.sizing_observation.fields["coverage_ratio"]


def test_cdb_logon_cycle_proves_one_account_and_stops_a_large_set(tmp_path):
    cdb = CdbAdapter(":memory:")
    cdb.insert_events([
        {"timestamp": "2026-09-10T01:00:00Z", "native_type": "logon", "host": "WIN-SRV", "user": "svc-new"},
        {"timestamp": "2026-09-10T02:00:00Z", "native_type": "logon", "host": "WIN-SRV", "user": "svc-backup"},
    ])
    graph = _graph()
    ledger = ObservationLedger()
    cycle = run_behavior_cycle(
        adapter=cdb,
        goal=graph.relations[0],
        goal_graph=graph,
        scope=_scope(),
        time_window=WINDOW,
        operation_id="search_text",
        ledger=ledger,
        baseline_values=("svc-backup",),
    )
    assert ledger.observations[0].fields["observation_class"] == "SIZING"
    by_value = {item.value: item for item in cycle.outcomes}
    assert by_value["svc-new"].verdict == "PROVEN"
    assert by_value["svc-backup"].citation == "known-benign:svc-backup"
    assert "COUNT(DISTINCT user)" in cycle.queries[0]["native_query"]
    account = SimpleNamespace(
        request_id="req-logon",
        stopping_decision="STOP_INCONCLUSIVE",
        hypotheses=[],
        observation_citations=[],
        gap_breakdown={},
        queries=[],
        semantic_analysis={"behavior_queries": graph.behavior_queries, "benign_citations": graph.benign_citations},
    )
    assert account_to_act_input(account)["spls"][0].startswith("SELECT COUNT")

    wide = CdbAdapter(":memory:")
    wide.insert_events([
        {"timestamp": "2026-09-10T01:00:00Z", "native_type": "logon", "host": "WIN-SRV", "user": f"svc-{index}"}
        for index in range(12)
    ])
    wide_graph = _graph()
    wide_cycle = run_behavior_cycle(
        adapter=wide,
        goal=wide_graph.relations[0],
        goal_graph=wide_graph,
        scope=_scope(),
        time_window=WINDOW,
        operation_id="search_text",
        ledger=ObservationLedger(),
    )
    assert wide_cycle.prove_ran is False
    assert wide_cycle.escalated is True
    assert len(wide_cycle.queries) == 1
    assert "12 distinct entities" in (wide_cycle.escalation or "")
