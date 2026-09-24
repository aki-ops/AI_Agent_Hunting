"""Workstream E: Tests for Candidate Control, Cardinality, and Discriminator Lifecycle.

Acceptance gate E:
- two singular host candidates never fan out into the proof goal;
- user selection resumes the same accepted graph without a second C1 call;
- selection provenance appears in the run account;
- plural outcomes retain legitimate multiple results;
- discriminator lifecycle emits STOP_NEEDS_CLARIFICATION when differentiating action is unavailable.
"""
from hunting.contracts.bindings import (
    CandidateBinding,
    CandidateSet,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, HuntState
from hunting.contracts.queries import (
    ProviderOperation,
    QueryOutcome,
    QueryResult,
)
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.engine import HypothesisHuntEngine
from hunting.human_loop.clarification import (
    ClarificationController,
    DisambiguationAction,
    DiscriminatorQuerySpec,
)
from hunting.planner.semantic_executor import SemanticExecutionResult, SemanticPlanExecutor, StepExecution


def test_two_singular_host_candidates_never_fan_out_into_proof_goal() -> None:
    """Acceptance Gate E: Two singular host candidates never fan out into the proof goal."""
    step_1 = PlanStep(
        id="s1",
        operation_id="lookup-hosts",
        input_bindings={"subject": "user"},
        output_bindings={"object": "host"},
        advances_goal_ids=("goal-1",),
    )
    step_2 = PlanStep(
        id="s2",
        operation_id="prove-infection",
        input_bindings={"subject": "host"},
        output_bindings={"object": "verdict"},
        advances_goal_ids=("goal-2",),
        depends_on=("s1",),
    )
    plan = LogicalPlan(
        id="test-plan",
        goal_graph_id="g1",
        provider_id="mock",
        steps=[step_1, step_2],
    )

    class MultiHostAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs["operation_id"] == "lookup-hosts":
                # Returns 2 host candidates for a singular slot
                return QueryResult(
                    kwargs["query_id"],
                    QueryOutcome.ROWS,
                    True,
                    True,
                    rows=[{"host_val": "host-corp-1"}, {"host_val": "host-corp-2"}],
                )
            return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[{"status": "infected"}])

    adapter = MultiHostAdapter()
    ops = [
        ProviderOperation("lookup-hosts", "mock", ("test",), input_entity_kinds=("user",), output_entity_kinds=("host",), output_value_bindings={"object": ("host_val",)}),
        ProviderOperation("prove-infection", "mock", ("test",), input_entity_kinds=("host",), output_entity_kinds=("verdict",)),
    ]
    executor = SemanticPlanExecutor(adapter, ops)
    scope = ProviderScope(provider_id="mock", native_partition={"index": "main"}, scope_id="test")

    res = executor.execute(
        plan=plan,
        scope=scope,
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        initial_variables={"user": "alice"},
        target_cardinality={"host": "singular"},
    )

    # Step 1 was executed but classified as AMBIGUOUS
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["operation_id"] == "lookup-hosts"
    assert res.needs_user_decision
    assert any("ambiguous output binding 'host'" in r for r in res.unresolved_reasons.values())

    # Step 2 must NEVER execute (zero downstream fan-out queries!)
    assert not any(c["operation_id"] == "prove-infection" for c in adapter.calls)


def test_user_selection_resumes_accepted_graph_without_second_c1_call() -> None:
    """Acceptance Gate E: User selection resumes the same accepted graph without a second C1 call."""
    step_1 = PlanStep(
        id="s1",
        operation_id="lookup-hosts",
        input_bindings={"subject": "user"},
        output_bindings={"object": "host"},
        advances_goal_ids=("goal-1",),
    )
    step_2 = PlanStep(
        id="s2",
        operation_id="prove-infection",
        input_bindings={"subject": "host"},
        output_bindings={"object": "verdict"},
        advances_goal_ids=("goal-2",),
        depends_on=("s1",),
    )
    plan = LogicalPlan(
        id="test-plan",
        goal_graph_id="g1",
        provider_id="mock",
        steps=[step_1, step_2],
    )

    class DownstreamAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, **kwargs):
            self.calls.append(kwargs)
            return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[{"status": "clean"}])

    adapter = DownstreamAdapter()
    ops = [
        ProviderOperation("lookup-hosts", "mock", ("test",), input_entity_kinds=("user",), output_entity_kinds=("host",), output_value_bindings={"object": ("host_val",)}),
        ProviderOperation("prove-infection", "mock", ("test",), input_entity_kinds=("host",), output_entity_kinds=("verdict",)),
    ]
    executor = SemanticPlanExecutor(adapter, ops)
    scope = ProviderScope(provider_id="mock", native_partition={"index": "main"}, scope_id="test")

    # User selects "host-corp-1" to resolve the ambiguity
    res = executor.execute(
        plan=plan,
        scope=scope,
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        initial_variables={"user": "alice", "host": "host-corp-1"},
        initial_variable_sources={"host": "user_selection"},
    )

    # Step 1 was satisfied by user selection (no provider query needed for step 1)
    # Step 2 was executed with selected host!
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["operation_id"] == "prove-infection"
    assert adapter.calls[0]["entity"] == "host-corp-1"

    # Selection provenance appears in the run account
    assert "host" in res.binding_provenance
    assert any(
        item["source"] == "user_selection" and item["value"] == "host-corp-1"
        for item in res.binding_provenance["host"]
    )


def test_plural_outcome_retains_legitimate_multiple_results() -> None:
    """Acceptance Gate E: Plural outcomes retain legitimate multiple results."""
    step = PlanStep(
        id="s-sweep",
        operation_id="discover-ips",
        input_bindings={"subject": "subnet"},
        output_bindings={"object": "ips"},
        advances_goal_ids=("g-pop",),
    )
    plan = LogicalPlan(id="pop-plan", goal_graph_id="g-pop", provider_id="mock", steps=[step])

    class PluralAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, **kwargs):
            self.calls.append(kwargs)
            return QueryResult(
                kwargs["query_id"],
                QueryOutcome.ROWS,
                True,
                True,
                rows=[{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}],
            )

    adapter = PluralAdapter()
    ops = [
        ProviderOperation("discover-ips", "mock", ("test",), input_entity_kinds=("subnet",), output_entity_kinds=("ip",), output_value_bindings={"object": ("ip",)}),
    ]
    executor = SemanticPlanExecutor(adapter, ops)
    scope = ProviderScope(provider_id="mock", native_partition={"index": "main"}, scope_id="test")

    res = executor.execute(
        plan=plan,
        scope=scope,
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        initial_variables={"subnet": "10.0.0.0/24"},
        target_cardinality={"ips": "plural"},
    )

    # 3 IPs were found, preserved, and NOT marked ambiguous!
    assert not res.needs_user_decision
    assert res.variables["ips"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert len(res.unresolved_reasons) == 0


def test_discriminator_lifecycle_emits_stop_needs_clarification() -> None:
    """Acceptance Gate E: Discriminator lifecycle emits STOP_NEEDS_CLARIFICATION when no action remains."""
    controller = ClarificationController(interactive=False, max_discriminator_attempts=1)

    cset = CandidateSet(variable_id="compromised_host", entity_type="host", cardinality="singular")
    cand1 = CandidateBinding(value="host-a", entity_type="host", supporting_fact_ids=("fact-1",))
    cand2 = CandidateBinding(value="host-b", entity_type="host", supporting_fact_ids=("fact-2",))
    cset.add_candidate(cand1)
    cset.add_candidate(cand2)

    # Attempt 1: synthesize discriminator
    action1, spec = controller.resolve_candidate_set(cset, request_id="req-test")
    assert action1 == DisambiguationAction.DISCRIMINATE
    assert spec.target_variable_id == "compromised_host"
    assert spec.expected_information_gain > 0

    # Attempt 2: discriminator already exhausted -> STOP_NEEDS_CLARIFICATION checkpoint
    action2, checkpoint = controller.resolve_candidate_set(cset, request_id="req-test")
    assert action2 == DisambiguationAction.NEEDS_DISAMBIGUATION
    assert checkpoint.status == "STOP_NEEDS_CLARIFICATION"
    assert "host-a" in checkpoint.candidate_values
    assert "host-b" in checkpoint.candidate_values
    assert "fact-1" in checkpoint.supporting_citations


def test_ambiguous_executor_preserves_candidates_without_downstream_fanout() -> None:
    step_1 = PlanStep(
        id="s1",
        operation_id="lookup-hosts",
        input_bindings={"subject": "user"},
        output_bindings={"object": "host"},
        advances_goal_ids=("goal-1",),
    )
    step_2 = PlanStep(
        id="s2",
        operation_id="prove-infection",
        input_bindings={"subject": "host"},
        output_bindings={"object": "verdict"},
        advances_goal_ids=("goal-2",),
        depends_on=("s1",),
    )
    plan = LogicalPlan(id="test-plan", goal_graph_id="g1", provider_id="mock", steps=[step_1, step_2])

    class MultiHostAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs["operation_id"] == "lookup-hosts":
                return QueryResult(
                    kwargs["query_id"],
                    QueryOutcome.ROWS,
                    True,
                    True,
                    rows=[{"host_val": "host-corp-1"}, {"host_val": "host-corp-2"}],
                )
            return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[{"status": "infected"}])

    adapter = MultiHostAdapter()
    ops = [
        ProviderOperation("lookup-hosts", "mock", ("test",), input_entity_kinds=("user",), output_entity_kinds=("host",), output_value_bindings={"object": ("host_val",)}),
        ProviderOperation("prove-infection", "mock", ("test",), input_entity_kinds=("host",), output_entity_kinds=("verdict",)),
    ]
    res = SemanticPlanExecutor(adapter, ops).execute(
        plan=plan,
        scope=ProviderScope(provider_id="mock", native_partition={"index": "main"}, scope_id="test"),
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        initial_variables={"user": "alice"},
        target_cardinality={"host": "singular"},
    )
    assert adapter.calls[0]["operation_id"] == "lookup-hosts"
    assert res.ambiguous_candidates["host"] == ["host-corp-1", "host-corp-2"]
    assert "host" not in res.variables
    assert not any(c["operation_id"] == "prove-infection" for c in adapter.calls)


def test_select_discriminator_operation_rejects_candidate_fanout_ops() -> None:
    spec = DiscriminatorQuerySpec(
        target_variable_id="host",
        candidate_values=("h1", "h2"),
        discriminator_relation="logged_on_to",
        discriminator_field="host",
    )
    fanout_op = ProviderOperation(
        "by-host",
        "mock",
        ("test",),
        input_entity_kinds=("host",),
        output_entity_kinds=("host",),
        guaranteed_relations=("logged_on_to",),
    )
    cheap_op = ProviderOperation(
        "by-account",
        "mock",
        ("test",),
        input_entity_kinds=("account",),
        output_entity_kinds=("host", "endpoint"),
        guaranteed_relations=("logged_on_to",),
        output_value_bindings={"object": ("host",)},
        discriminator_fields=("logon_type",),
    )
    selected = ClarificationController.select_discriminator_operation([fanout_op, cheap_op], spec, "host")
    assert selected is cheap_op
    skipped = ClarificationController.select_discriminator_operation(
        [fanout_op, cheap_op],
        spec,
        "host",
        exclude_operation_ids=("by-account",),
    )
    assert skipped is None


def test_select_discriminator_operation_rejects_same_native_signature() -> None:
    spec = DiscriminatorQuerySpec(
        target_variable_id="endpoint",
        candidate_values=("h1", "h2"),
        discriminator_relation="logged_on_to",
        discriminator_field="host",
    )
    source = ProviderOperation(
        "person-endpoint",
        "mock",
        ("test",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        guaranteed_relations=("associated_with",),
        native_signature="mock.identity.endpoint.v1",
        discriminator_fields=("sourcetype",),
    )
    alias = ProviderOperation(
        "account-endpoint",
        "mock",
        ("test",),
        input_entity_kinds=("account",),
        output_entity_kinds=("host",),
        guaranteed_relations=("logged_on_to",),
        native_signature="mock.identity.endpoint.v1",
        discriminator_fields=("LogonType",),
    )
    assert ClarificationController.select_discriminator_operation(
        [source, alias],
        spec,
        "host",
        exclude_operation_ids=(source.id,),
        exclude_native_signatures=(source.native_signature,),
    ) is None


def test_engine_previews_same_native_spl_before_discriminator_execution() -> None:
    """A compiled discriminator with no delta must not execute or consume budget."""
    graph = SemanticGoalGraph(
        id="graph-preview",
        request_id="req-preview",
        objective="resolve endpoint",
        variables=[
            SemanticVariable(id="account", entity_type="account", value="alice"),
            SemanticVariable(
                id="endpoint",
                entity_type="endpoint",
                constraints=(SemanticConstraint("logon_type", "interactive"),),
            ),
        ],
        relations=[
            SemanticRelationGoal(
                id="rel-1",
                subject="account",
                relation="associated_with",
                object="endpoint",
            ),
        ],
    )
    source = ProviderOperation(
        "source-op", "mock", ("scope",),
        input_entity_kinds=("account",), output_entity_kinds=("endpoint",),
        guaranteed_relations=("associated_with",), native_signature="mock.source.v1",
    )
    discriminator = ProviderOperation(
        "discriminator-op", "mock", ("scope",),
        input_entity_kinds=("account",), output_entity_kinds=("endpoint",),
        guaranteed_relations=("logged_on_to",), discriminator_fields=("logon_type",),
        discriminator_constraint_bindings={"logon_type": "logon_type"},
        native_signature="mock.discriminator.v1",
    )

    class PreviewAdapter:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def preview_query(self, **_kwargs: object) -> dict[str, object]:
            return {
                "base_query": "search user=alice | table host",
                "native_query": "search user=alice | table host",
                "has_secondary_predicate": True,
            }

        def execute_query(self, **kwargs: object) -> QueryResult:
            self.calls.append(kwargs)
            return QueryResult(
                query_id=str(kwargs["query_id"]), outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=True, rows=[{"host": "host-a"}],
                native_query="search user=alice | table host",
            )

    adapter = PreviewAdapter()
    state = HuntState(
        objective=HuntObjective(
            request_id="req-preview", statement="resolve endpoint",
            time_window="2026-01-01T00:00:00Z/P1D",
        ),
        semantic_goal_graph=graph,
    )
    candidate_set = CandidateSet(variable_id="endpoint", entity_type="endpoint", cardinality="singular")
    candidate_set.add_candidate(CandidateBinding(value="host-a", entity_type="endpoint"))
    candidate_set.add_candidate(CandidateBinding(value="host-b", entity_type="endpoint"))
    state.candidate_sets["endpoint"] = candidate_set
    execution = SemanticExecutionResult(
        executions=[StepExecution(
            step_id="step-1", query_id="source-query", operation_id="source-op",
            result=QueryResult(
                query_id="source-query", outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=True,
                rows=[{"host": "host-a"}, {"host": "host-b"}],
                native_query="search user=alice | table host",
            ),
            inputs={"subject": ["alice"]}, status="AMBIGUOUS",
        )],
        ambiguous_candidates={"endpoint": ["host-a", "host-b"]},
        needs_user_decision=True,
    )
    engine = HypothesisHuntEngine()
    result = engine._attempt_semantic_discrimination(
        state=state, execution=execution,
        scope=ProviderScope(provider_id="mock", native_partition={"partition": "main"}, scope_id="scope"),
        active_adapter=adapter, operations=(source, discriminator), goal_graph=graph,
        target_cardinality={"endpoint": "singular"}, time_window=state.objective.time_window,
    )

    assert result is execution
    assert adapter.calls == []
    assert state.queries == []
