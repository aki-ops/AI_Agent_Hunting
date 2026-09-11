from hunting.contracts.cells import ProviderScope
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep
from hunting.contracts.semantic_route import SemanticRouteStatus
from hunting.planner.semantic_executor import SemanticPlanExecutor


class FakeAdapter:
    def __init__(self) -> None:
        self.calls = []

    def execute_query(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["operation_id"] == "lookup-host":
            return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[{"host_value": "host-1"}])
        return QueryResult(kwargs["query_id"], QueryOutcome.ROWS, True, True, rows=[{"domain_value": "example.test"}])


def test_executor_passes_declared_output_to_dependent_step() -> None:
    adapter = FakeAdapter()
    operations = [
        ProviderOperation("lookup-host", "p", ("scope",), input_entity_kinds=("person",), output_entity_kinds=("host",), output_value_bindings={"object": ("host_value",)}),
        ProviderOperation("lookup-domain", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("domain",), output_value_bindings={"object": ("domain_value",)}),
    ]
    plan = LogicalPlan("p1", "g1", "p", [
        PlanStep("s1", "lookup-host", {"subject": "person"}, {"object": "host"}),
        PlanStep("s2", "lookup-domain", {"subject": "host"}, {"object": "domain"}, depends_on=("s1",)),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D", {"person": "Amber"})
    assert len(adapter.calls) == 2
    assert adapter.calls[1]["entity"] == "host-1"
    assert result.variables["domain"] == ["example.test"]
    assert result.unresolved_step_ids == []


class PagedAdapter:
    def __init__(self) -> None:
        self.calls = []

    def execute_query(self, operation_id, entity, window, limit, query_id, offset=0):
        self.calls.append((operation_id, entity, offset))
        if offset == 0:
            return QueryResult(query_id, QueryOutcome.ROWS, True, False, rows=[{"host_value": "host-1"}], cursor="1", row_count=1)
        return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"host_value": "host-2"}], row_count=1)


def test_executor_continues_partial_pages_before_grounding_next_step() -> None:
    adapter = PagedAdapter()
    operations = [
        ProviderOperation("lookup-host", "p", ("scope",), pagination="offset", input_entity_kinds=("person",), output_entity_kinds=("host",), output_value_bindings={"object": ("host_value",)}, output_binding_entity_kinds={"object": "host"}),
        ProviderOperation("lookup-domain", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("domain",), output_value_bindings={"object": ("domain_value",)}, output_binding_entity_kinds={"object": "domain"}),
    ]
    # The second step is deliberately not executed in this fixture because
    # the first operation's second page still only contains host values; the
    # assertion verifies the generic pagination contract itself.
    plan = LogicalPlan("p2", "g1", "p", [PlanStep("s1", "lookup-host", {"subject": "person"}, {"object": "host"})])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D", {"person": "Amber"},
        variable_types={"person": "person", "host": "host"},
    )
    assert [call[2] for call in adapter.calls] == [0, 1]
    assert result.variables["host"] == ["host-1", "host-2"]
    assert result.executions[0].result.complete is True
    assert [page["offset"] for page in result.page_trace] == [0, 1]
    assert result.continuations == {}


def test_executor_rejects_wrong_typed_output_binding() -> None:
    adapter = FakeAdapter()
    operation = ProviderOperation(
        "lookup", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",),
        output_value_bindings={"object": ("user",)}, output_binding_entity_kinds={"object": "account"},
    )
    plan = LogicalPlan("p3", "g1", "p", [PlanStep("s1", "lookup", {"subject": "account"}, {"object": "host"})])
    result = SemanticPlanExecutor(adapter, [operation]).execute(
        plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D", {"account": "a"},
        variable_types={"account": "account", "host": "host"},
    )
    assert result.variables.get("host") is None
    assert result.executions[0].status == "EXECUTED"


def test_executor_fans_out_all_candidates_instead_of_using_first_candidate() -> None:
    class FanoutAdapter:
        def __init__(self) -> None:
            self.entities = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            value = getattr(entity, "username", str(entity))
            self.entities.append(value)
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"host_value": f"host-for-{value}"}])

    adapter = FanoutAdapter()
    operation = ProviderOperation(
        "lookup", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",),
        output_value_bindings={"object": ("host_value",)}, output_binding_entity_kinds={"object": "host"},
    )
    plan = LogicalPlan("p4", "g1", "p", [PlanStep("s1", "lookup", {"subject": "account"}, {"object": "host"})])
    result = SemanticPlanExecutor(adapter, [operation]).execute(
        plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D",
        {"account": ["a-1", "a-2"]}, variable_types={"account": "account", "host": "host"},
    )
    assert adapter.entities == ["a-1", "a-2"]
    assert result.variables["host"] == ["host-for-a-1", "host-for-a-2"]
    assert result.binding_provenance["host"][0]["source"] == "s1"


def test_executor_blocks_downstream_step_when_upstream_result_is_partial() -> None:
    class PartialAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append(operation_id)
            if operation_id == "person-account":
                return QueryResult(query_id, QueryOutcome.ROWS, True, False, rows=[{"account": "mallory"}])
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"host": "venus"}])

    adapter = PartialAdapter()
    operations = [
        ProviderOperation("person-account", "p", ("scope",), input_entity_kinds=("person",), output_entity_kinds=("account",), output_value_bindings={"object": ("account",)}, output_binding_entity_kinds={"object": "account"}),
        ProviderOperation("account-host", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",), output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"}),
    ]
    plan = LogicalPlan("partial", "g", "p", [
        PlanStep("s1", "person-account", {"subject": "person"}, {"object": "account"}),
        PlanStep("s2", "account-host", {"subject": "account"}, {"object": "host"}, depends_on=("s1",)),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D", {"person": "Mallory"},
        variable_types={"person": "person", "account": "account", "host": "host"},
    )
    assert adapter.calls == ["person-account"]
    assert result.unresolved_reasons["s2"].startswith("required upstream proof is incomplete")
    assert result.binding_provenance["account"][0]["status"] == "CANDIDATE"
    route = next(item for item in result.route_assessments if item.goal_id == "s1")
    assert route.status.value == "ATTEMPTED_PARTIAL"
    assert route.execution_complete is False
    assert route.route_exhausted is False


def test_executor_uses_declared_or_alternative_when_primary_has_no_proof() -> None:
    class AlternativeAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append(operation_id)
            rows = [] if operation_id == "primary" else [{"host": "macbook-1"}]
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=rows)

    adapter = AlternativeAdapter()
    operations = [
        ProviderOperation("primary", "p", ("scope",), input_entity_kinds=("person",), output_entity_kinds=("host",), output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"}),
        ProviderOperation("alternative", "p", ("scope",), input_entity_kinds=("person",), output_entity_kinds=("host",), output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"}),
    ]
    plan = LogicalPlan("or-plan", "g", "p", [
        PlanStep("s1", "primary", {"subject": "person"}, {"object": "host"}, alternative_operation_ids=("alternative",)),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D", {"person": "Mallory"},
        variable_types={"person": "person", "host": "host"},
    )
    assert adapter.calls == ["primary", "alternative"]
    assert result.variables["host"] == ["macbook-1"]
    assert result.executions[-1].operation_id == "alternative"


def test_executor_relaxes_search_hint_once_when_narrow_query_is_empty() -> None:
    class RelaxingAdapter:
        def __init__(self) -> None:
            self.parameters = []

        def execute_query(self, operation_id, entity, window, limit, query_id, parameters=None):
            self.parameters.append(dict(parameters or {}))
            if parameters and parameters.get("constraint_search_terms"):
                return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[])
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"file_path": "report.locked"}])

    adapter = RelaxingAdapter()
    operation = ProviderOperation(
        "find-file", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        searchable_constraints=("file_type",), output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
    )
    plan = LogicalPlan("relax", "g", "p", [PlanStep(
        "s1", "find-file", {"subject": "host"}, {"object": "file"},
        constraints=("file_type=PowerPoint",),
    )])
    result = SemanticPlanExecutor(adapter, [operation]).execute(
        plan, ProviderScope("p", "scope", {}), "2026-01-01T00:00:00Z/P1D", {"host": "venus"},
        variable_types={"host": "host", "file": "file"},
    )
    assert len(adapter.parameters) == 2
    assert adapter.parameters[0]["constraint_search_terms"] == ["PowerPoint"]
    assert "constraint_search_terms" not in adapter.parameters[1]
    assert result.variables["file"] == ["report.locked"]
    assert any(page.get("relaxation") == "removed_searchable_constraints" for page in result.page_trace)
    assert [attempt.stage_id for attempt in result.attempts] == ["narrow", "base_relation"]
    assert result.attempts[1].row_count == 1
    assert result.route_assessments[0].status.value == "CANDIDATE_OBSERVED"


def test_executor_does_not_fan_out_ambiguous_output_bindings() -> None:
    class BroadProcessAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append((operation_id, entity))
            if operation_id in {"find-process", "find-process-alt"}:
                return QueryResult(
                    query_id,
                    QueryOutcome.ROWS,
                    True,
                    True,
                    rows=[{"pid": str(index)} for index in range(40)],
                )
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"file": "x"}])

    adapter = BroadProcessAdapter()
    operations = [
        ProviderOperation(
            "find-process", "p", ("scope",),
            input_entity_kinds=("host",), output_entity_kinds=("process",),
            output_value_bindings={"object": ("pid",)},
            output_binding_entity_kinds={"object": "process"},
        ),
        ProviderOperation(
            "find-process-alt", "p", ("scope",),
            input_entity_kinds=("host",), output_entity_kinds=("process",),
            output_value_bindings={"object": ("pid",)},
            output_binding_entity_kinds={"object": "process"},
        ),
        ProviderOperation(
            "find-file", "p", ("scope",),
            input_entity_kinds=("process",), output_entity_kinds=("file",),
            output_value_bindings={"object": ("file",)},
            output_binding_entity_kinds={"object": "file"},
        ),
    ]
    plan = LogicalPlan("ambiguous", "g", "p", [
        PlanStep(
            "s1", "find-process", {"subject": "host"}, {"object": "process"},
            alternative_operation_ids=("find-process-alt",),
        ),
        PlanStep("s2", "find-file", {"subject": "process"}, {"object": "file"}, depends_on=("s1",)),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan,
        ProviderScope("p", "scope", {}),
        "2026-01-01T00:00:00Z/P1D",
        {"host": "venus"},
        variable_types={"host": "host", "process": "process", "file": "file"},
        max_bindings=8,
    )

    assert [operation_id for operation_id, _ in adapter.calls] == ["find-process"]
    assert result.needs_user_decision is True
    assert result.variables.get("process") is None
    assert result.executions[0].status == "AMBIGUOUS"
    assert result.unresolved_reasons["s1"].startswith("ambiguous output binding")
    assert result.unresolved_reasons["s2"].startswith("required upstream proof is incomplete")


def test_executor_blocks_downstream_candidate_binding_until_user_selection() -> None:
    class RestrictionAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append(operation_id)
            if operation_id == "lookup-device":
                return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"host": "venus"}])
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"file": "secret.pptx.locked"}])

    adapter = RestrictionAdapter()
    operations = [
        ProviderOperation(
            "lookup-device", "p", ("scope",),
            input_entity_kinds=("account",), output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)},
            output_binding_entity_kinds={"object": "host"},
        ),
        ProviderOperation(
            "lookup-file", "p", ("scope",),
            input_entity_kinds=("host",), output_entity_kinds=("file",),
            output_value_bindings={"object": ("file",)},
            output_binding_entity_kinds={"object": "file"},
        ),
    ]
    plan = LogicalPlan("restriction", "g", "p", [
        PlanStep(
            "s1", "lookup-device", {"subject": "account"}, {"object": "host"},
            constraints=("device_type=MacBook",),
        ),
        PlanStep(
            "s2", "lookup-file", {"subject": "host"}, {"object": "file"},
            depends_on=("s1",),
        ),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan,
        ProviderScope("p", "scope", {}),
        "2026-01-01T00:00:00Z/P1D",
        {"account": "mallory"},
        variable_types={"account": "account", "host": "host", "file": "file"},
    )

    # An unverified upstream entity must not silently authorize a downstream
    # query.  The controller stops for an explicit user choice instead of
    # selecting a host or launching an exploratory fan-out.
    assert adapter.calls == ["lookup-device"]
    assert result.binding_provenance["host"][0]["status"] == "CANDIDATE"
    assert result.variables.get("file") is None
    assert result.needs_user_decision is True
    assert result.candidate_input_warnings["s2"].startswith("upstream candidate binding requires")


def test_executor_resumes_downstream_step_from_user_selected_binding() -> None:
    class SelectedAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append(operation_id)
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[{"file": "selected.txt"}])

    adapter = SelectedAdapter()
    operations = [
        ProviderOperation(
            "lookup-device", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"},
        ),
        ProviderOperation(
            "lookup-file", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
            output_value_bindings={"object": ("file",)}, output_binding_entity_kinds={"object": "file"},
        ),
    ]
    plan = LogicalPlan("selected", "g", "p", [
        PlanStep("s1", "lookup-device", {"subject": "account"}, {"object": "host"}),
        PlanStep("s2", "lookup-file", {"subject": "host"}, {"object": "file"}, depends_on=("s1",)),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan,
        ProviderScope("p", "scope", {}),
        "2026-01-01T00:00:00Z/P1D",
        {"account": "mallory", "host": "user-selected-host"},
        variable_types={"account": "account", "host": "host", "file": "file"},
        initial_variable_sources={"account": "request", "host": "user_selection"},
    )
    assert adapter.calls == ["lookup-file"]
    assert result.variables["file"] == ["selected.txt"]
    assert result.executions[0].status == "USER_SELECTED"
    assert len(result.binding_events) == 1
    assert result.binding_events[0].values == {"host": ["user-selected-host"]}


def test_untried_alternative_prevents_route_exhaustion() -> None:
    class FakeAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append(operation_id)
            return QueryResult(query_id, QueryOutcome.ROWS, True, True, rows=[])

    adapter = FakeAdapter()
    operations = [
        ProviderOperation(
            "primary-op", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"},
        ),
        ProviderOperation(
            "alt-op", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"},
        ),
    ]
    # Step has alternative alt-op
    plan = LogicalPlan("p-alt", "g", "p", [
        PlanStep(
            "s1", "primary-op", {"subject": "account"}, {"object": "host"},
            alternative_operation_ids=("alt-op",),
        ),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan,
        ProviderScope("p", "scope", {}),
        "2026-01-01T00:00:00Z/P1D",
        {"account": "mallory"},
        variable_types={"account": "account", "host": "host"},
    )
    # Both operations were tried because primary returned empty
    assert adapter.calls == ["primary-op", "alt-op"]
    assessment = result.route_assessments[0]
    assert assessment.status == SemanticRouteStatus.ATTEMPTED_EMPTY
    # Since both were evaluated and returned complete empty, route is exhausted
    assert assessment.route_exhausted is True


def test_partial_continuation_prevents_route_exhaustion() -> None:
    class PartialAdapter:
        def execute_query(self, operation_id, entity, window, limit, query_id, cursor=None):
            # Returns incomplete result (requires continuation)
            return QueryResult(query_id, QueryOutcome.ROWS, True, False, rows=[{"host": "wrk-1"}], cursor="offset-10")

    adapter = PartialAdapter()
    operations = [
        ProviderOperation(
            "lookup-dev", "p", ("scope",), input_entity_kinds=("account",), output_entity_kinds=("host",),
            output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"},
            pagination="offset",
        ),
    ]
    plan = LogicalPlan("p-partial", "g", "p", [
        PlanStep("s1", "lookup-dev", {"subject": "account"}, {"object": "host"}),
    ])
    result = SemanticPlanExecutor(adapter, operations).execute(
        plan,
        ProviderScope("p", "scope", {}),
        "2026-01-01T00:00:00Z/P1D",
        {"account": "mallory"},
        variable_types={"account": "account", "host": "host"},
        max_pages=1,
    )
    assessment = result.route_assessments[0]
    assert assessment.status == SemanticRouteStatus.ATTEMPTED_PARTIAL
    assert assessment.execution_complete is False
    assert assessment.route_exhausted is False
    assert "s1" in result.continuations

