"""Generic counterexamples for retrieval/proof/report slices 1-8.

No scenario names, no BOTS answers, no office playbooks.
"""
from __future__ import annotations

from hunting.contracts.candidate_route import CandidateRoute, RouteAdmission, RouteClass
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import StoppingDecision, StoppingTaxonomyState
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.outcome import FactualAnswerContract
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.transforms import (
    FileTypeSemanticTransform,
    get_transform_for_constraint,
    is_literal_telemetry_token,
)
from hunting.engine import (
    _cardinality_by_variable,
    _cover_constraint_keys,
    _executable_route_covers_goal,
    _facet_information_gain,
    _is_request_grounded_constraint,
    _proof_obligation_keys,
    _select_winning_facet,
    apply_facet_bucket_selection,
    apply_resume_bindings,
    execution_requires_user_decision,
)
from hunting.evidence.facts import extract_facts
from hunting.evidence.grouping import EvidenceGroupBuilder
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner
from hunting.reporter.renderer import render_analyst_report


def test_descriptive_file_type_is_not_a_native_search_playbook() -> None:
    transform = FileTypeSemanticTransform()
    assert transform.get_retrieval_terms("file_type", "office presentation") == ()
    assert get_transform_for_constraint("file_type", "office presentation") is None
    assert not is_literal_telemetry_token("office presentation")
    assert not is_literal_telemetry_token(".pptx.crypt")
    assert is_literal_telemetry_token(".pdf")
    assert is_literal_telemetry_token("quarterly.pdf")
    assert is_literal_telemetry_token("/tmp/notes.pdf")
    assert transform.get_retrieval_terms("file_extension", ".pdf") == (".pdf",)


def test_planner_does_not_compile_llm_file_aliases_into_native_terms() -> None:
    graph = SemanticGoalGraph(
        id="g-file",
        request_id="req-file",
        objective="Find a named document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable(
                "file",
                "file",
                constraints=({"key": "file_type", "operator": "equals", "value": "office presentation", "retrieval_terms": [".pptx", ".crypt"]},),
            ),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        qualifiers=[SemanticQualifierGoal("q1", "r1", "file_type", "office presentation", True, (".pptx", ".pptm"))],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        id="find-file",
        provider_id="p",
        scope_ids=("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path", "target_path")},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        searchable_constraints=("file_type", "file_extension"),
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(graph)
    assert plan.steps
    assert plan.steps[0].constraint_retrieval_terms == ()


def test_qualifier_literal_is_not_compiled_into_native_terms() -> None:
    graph = SemanticGoalGraph(
        id="g-qual",
        request_id="req-qual",
        objective="Find a named document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable("file", "file"),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        qualifiers=[SemanticQualifierGoal("q1", "r1", "file_extension", ".pdf", True, (".pdf",))],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        id="find-file",
        provider_id="p",
        scope_ids=("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        searchable_constraints=("file_extension",),
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(graph)
    assert plan.steps[0].constraint_retrieval_terms == ()


def test_planner_keeps_request_literal_extension() -> None:
    graph = SemanticGoalGraph(
        id="g-lit",
        request_id="req-lit",
        objective="Find secret.pdf on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable(
                "file",
                "file",
                value_origin="request",
                constraints=({"key": "file_name", "operator": "equals", "value": "secret.pdf"},),
            ),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        id="find-file",
        provider_id="p",
        scope_ids=("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        searchable_constraints=("file_name",),
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(graph)
    assert ("file_name", "secret.pdf") in plan.steps[0].constraint_retrieval_terms


def test_executor_does_not_push_descriptive_file_type_into_search_terms() -> None:
    class Adapter:
        def __init__(self) -> None:
            self.parameters: list[dict] = []

        def execute_query(self, operation_id, entity, window, limit, query_id, parameters=None):
            self.parameters.append(dict(parameters or {}))
            return QueryResult(
                query_id,
                QueryOutcome.ROWS,
                True,
                True,
                rows=[
                    {"file_path": "/docs/a.bin", "target_path": "/docs/a.bin"},
                    {"file_path": "/docs/a.bin.locked", "target_path": "/docs/a.bin.locked"},
                ],
            )

    adapter = Adapter()
    operation = ProviderOperation(
        "find-file", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("file",),
        searchable_constraints=("file_type",),
        output_value_bindings={"object": ("file_path", "target_path")},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
    )
    from hunting.contracts.semantic_graph import LogicalPlan, PlanStep
    plan = LogicalPlan("p1", "g", "p", [PlanStep(
        "s1", "find-file", {"subject": "host"}, {"object": "file"},
        constraints=("file_type=office presentation",),
        advances_goal_ids=("r1",),
        relation="modified",
    )])
    result = SemanticPlanExecutor(adapter, [operation]).execute(
        plan, ProviderScope("p", "scope", {}), "2017-08-01T00:00:00Z/P30D", {"host": "HOST-1"},
        variable_types={"host": "host", "file": "file"},
        target_cardinality={"file": "singular"},
    )
    assert all("constraint_search_terms" not in (p or {}) or not p.get("constraint_search_terms") for p in adapter.parameters)
    assert result.needs_user_decision is True
    assert set(result.ambiguous_candidates.get("file", [])) == {"/docs/a.bin", "/docs/a.bin.locked"}


def test_compiler_qualifiers_are_not_proof_keys() -> None:
    assert "importance" not in _proof_obligation_keys(
        required_texts=("importance=high", "state=encrypted", "file_type=office presentation"),
        supported_keys=frozenset({"host"}),
    )
    assert "host" in _proof_obligation_keys(
        required_texts=("host=HOST-1",),
        supported_keys=frozenset({"host"}),
    )


def test_request_grounded_identity_stays_a_proof_key() -> None:
    person = SemanticVariable(
        "user",
        "person",
        "Alice",
        value_origin="request",
        constraints=(SemanticConstraint("user", "Alice"),),
    )
    assert _is_request_grounded_constraint(person, person.constraints[0])
    invented = SemanticVariable(
        "file",
        "file",
        value_origin="llm_proposal",
        constraints=(SemanticConstraint("file_extension", ".pptx"),),
    )
    assert not _is_request_grounded_constraint(invented, invented.constraints[0])


def test_c2_cover_keys_ignore_compiler_phrases() -> None:
    keys = _cover_constraint_keys((
        {"key": "importance", "value": "critical"},
        {"key": "state", "value": "encrypted"},
        {"key": "file_type", "value": "office presentation"},
        {"key": "file_name", "value": "secret.pdf"},
        {"key": "encoding", "value": "encoded"},
    ))
    assert keys == {"file_name", "encoding"}
    operation = ProviderOperation(
        id="resolve-host",
        provider_id="p",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        output_value_bindings={"object": ("host",)},
        output_binding_entity_kinds={"object": "host"},
        guaranteed_relations=("associated_with",),
    )
    route = CandidateRoute(
        route_id="r1",
        goal_id="goal-1",
        provider_id="p",
        source_id="src",
        operation_id="resolve-host",
        route_class=RouteClass.EXECUTABLE,
        admission_status=RouteAdmission.ADMITTED,
        frontier_stage="F0_CERTIFIED",
    )
    junk = _cover_constraint_keys((
        {"key": "importance", "value": "critical"},
        {"key": "state", "value": "encrypted"},
    ))
    assert junk == set()
    assert _executable_route_covers_goal(
        goal_id="goal-1",
        routes=(route,),
        operations=(operation,),
        required_keys=junk,
    ) is True


def test_answer_slot_cardinality_maps_onto_variable_id() -> None:
    graph = SemanticGoalGraph(
        id="g",
        request_id="r",
        objective="name the file",
        variables=[SemanticVariable("var_file", "file")],
        relations=[],
        answers=[SemanticAnswerGoal("var_file", "file_name")],
    )
    contract = FactualAnswerContract(
        slots=("encrypted_file_name",),
        types={"encrypted_file_name": "file_name"},
        cardinality={"encrypted_file_name": "singular"},
    )
    mapped = _cardinality_by_variable(graph, contract)
    assert mapped["var_file"] == "singular"


def test_file_schema_fields_are_file_modification_not_process_or_web() -> None:
    obs = Observation(
        id="obs-1",
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "main"}),
        cell_id="c1",
        timestamp="2017-08-18T21:50:43Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="osquery_results",
        fields={
            "host": "HOST-1",
            "name": "notes.bin",
            "target_path": "/Users/a/notes.bin",
            "action": "MOVED_TO",
            "domain": "file_events",
            "site": "file_events",
        },
        raw_event={},
    )
    facts = extract_facts(obs)
    assert facts[0].fact_type == "file_modification"
    cards = EvidenceGroupBuilder().build_cards([obs])
    assert cards[0].fact_type == "file_modification"
    summary = cards[0].entity_summary or {}
    paths = " ".join(str(v) for v in summary.values())
    assert "notes.bin" in paths or "/Users/a/notes.bin" in str(cards[0].field_summary)


def test_stop_inconclusive_is_not_coverage_exhausted() -> None:
    assert StoppingDecision.STOP_INCONCLUSIVE.to_taxonomy_state() == StoppingTaxonomyState.INCONCLUSIVE
    assert StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP.to_taxonomy_state() == StoppingTaxonomyState.COVERAGE_EXHAUSTED
    assert StoppingDecision.STOP_UNSUPPORTED.to_taxonomy_state() == StoppingTaxonomyState.COVERAGE_EXHAUSTED


def test_analyst_report_lists_candidates_and_omits_source_dump() -> None:
    from hunting.contracts.coverage import CoverageBound
    from hunting.contracts.hunt import FinalHuntAccount, HuntObjective, Hypothesis, HypothesisStatus

    account = FinalHuntAccount(
        request_id="req-report",
        objective=HuntObjective(request_id="req-report", statement="What is the file name?"),
        hypotheses=[Hypothesis(id="h1", statement="A file changed on a host", status=HypothesisStatus.LIVE)],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_NEEDS_USER_DECISION,
        answer={"status": "INCONCLUSIVE", "reason": "USER_DECISION_REQUIRED", "explanation": "Pick a file candidate."},
        semantic_analysis={
            "needs_user_decision": True,
            "binding_provenance": {
                "var_file": [
                    {"value": "/docs/a.bin", "status": "CANDIDATE"},
                    {"value": "/docs/a.bin.locked", "status": "CANDIDATE"},
                ]
            },
        },
    )
    report = render_analyst_report(account)
    assert "/docs/a.bin.locked" in report
    assert "Perfmon:CPU" not in report
    assert "unexamined=splunk:" not in report
    assert report.count("\n") < 80


def _incomplete_file_rows() -> list[dict[str, str]]:
    return [
        {"file_path": "/docs/a.txt", "action": "CREATED"},
        {"file_path": "/docs/b.txt", "action": "CREATED"},
        {"file_path": "/docs/c.txt", "action": "CREATED"},
        {"file_path": "/docs/d.txt", "action": "MOVED_TO"},
        {"file_path": "/docs/e.txt", "action": "MOVED_TO"},
    ]


def test_incomplete_explore_emits_candidates_without_binding() -> None:
    class Adapter:
        def execute_query(self, operation_id, entity, window, limit, query_id, offset=0, parameters=None):
            return QueryResult(
                query_id,
                QueryOutcome.ROWS,
                True,
                False,
                rows=_incomplete_file_rows(),
                cursor=str(offset + 5),
            )

    operation = ProviderOperation(
        "find-file", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        discriminator_fields=("action", "file_path"),
        pagination="offset",
    )
    from hunting.contracts.semantic_graph import LogicalPlan, PlanStep
    plan = LogicalPlan("p1", "g", "p", [PlanStep(
        "s1", "find-file", {"subject": "host"}, {"object": "file"},
        advances_goal_ids=("r1",), relation="modified",
    )])
    result = SemanticPlanExecutor(Adapter(), [operation]).execute(
        plan, ProviderScope("p", "scope", {}), "2017-08-01T00:00:00Z/P30D", {"host": "HOST-1"},
        variable_types={"host": "host", "file": "file"},
        target_cardinality={"file": "singular"},
        max_pages=1,
    )
    assert result.needs_user_decision is True
    assert result.ambiguous_candidates["file"] == [row["file_path"] for row in _incomplete_file_rows()]
    assert "file" not in result.variables
    assert "s1" in result.continuations
    assert result.executions[0].status == "PARTIAL"
    assert execution_requires_user_decision(result) is True


def test_incomplete_explore_builds_census_groups_without_proof() -> None:
    from hunting.contracts.bindings import CandidateBinding, CandidateSet
    from hunting.contracts.hunt import HuntObjective, HuntState
    from hunting.engine import HypothesisHuntEngine
    from hunting.planner.semantic_executor import SemanticExecutionResult, StepExecution

    rows = _incomplete_file_rows()
    values = [row["file_path"] for row in rows]
    graph = SemanticGoalGraph(
        id="g-partial",
        request_id="req-partial",
        objective="Name a document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable("file", "file", value_origin="llm_proposal"),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        "find-file", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        discriminator_fields=("action", "file_path"),
    )
    execution = SemanticExecutionResult(
        executions=[StepExecution(
            step_id="s1", query_id="q-explore", operation_id="find-file",
            result=QueryResult(
                query_id="q-explore", outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=False, rows=list(rows), cursor="5",
            ),
            inputs={"subject": ["HOST-1"]}, status="PARTIAL",
        )],
        ambiguous_candidates={"file": list(values)},
        needs_user_decision=True,
        continuations={"s1": {"cursor": "5"}},
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="req-partial", statement="name the file",
            time_window="2017-08-01T00:00:00Z/P30D",
        ),
        semantic_goal_graph=graph,
    )
    cset = CandidateSet(variable_id="file", entity_type="file", cardinality="singular")
    for value in values:
        cset.add_candidate(CandidateBinding(value=value, entity_type="file"))
    state.candidate_sets["file"] = cset
    result = HypothesisHuntEngine()._attempt_semantic_discrimination(
        state=state,
        execution=execution,
        scope=ProviderScope("p", "scope", {}),
        active_adapter=object(),
        operations=(operation,),
        goal_graph=graph,
        target_cardinality={"file": "singular"},
        time_window="2017-08-01T00:00:00Z/P30D",
    )
    assert result.needs_user_decision is True
    assert "file" not in result.variables
    assert result.executions[0].status == "PARTIAL"
    groups = result.candidate_groups["file"]
    actions = {item["value"] for item in groups if item["field"] == "action"}
    assert actions == {"CREATED", "MOVED_TO"}
    assert all(item.get("proof_verified") is not True for item in groups)


def test_file_typed_operations_declare_census_discriminator_fields() -> None:
    from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter

    adapter = SplunkLiveAdapter(index="botsv2", verify_ssl=False)
    file_change = next(
        op for op in adapter.get_capability_descriptor().operations
        if op.id == "find_file_change_from_endpoint"
    )
    declared = {field.casefold() for field in file_change.discriminator_fields}
    assert {"target_path", "action", "file_path"} <= declared
    assert "file_type" not in file_change.discriminator_constraint_bindings
    assert "state" not in file_change.discriminator_constraint_bindings


def test_compiler_file_type_is_not_a_discriminator_predicate() -> None:
    from hunting.engine import (
        HypothesisHuntEngine,
        _filter_request_grounded_discriminator_predicates,
    )

    graph = SemanticGoalGraph(
        id="g-disc",
        request_id="req-disc",
        objective="Name a document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable(
                "file",
                "file",
                value_origin="llm_proposal",
                constraints=(
                    {"key": "file_type", "operator": "equals", "value": "office presentation"},
                    {"key": "state", "operator": "equals", "value": "encrypted"},
                ),
            ),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        "find-file", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path", "target_path")},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        discriminator_fields=("action", "target_path", "file_path"),
        discriminator_constraint_bindings={"file_type": "target_path", "state": "action"},
    )
    raw = HypothesisHuntEngine._discriminator_predicates_for_goal(graph, "file", operation)
    filtered = _filter_request_grounded_discriminator_predicates(
        raw,
        goal_graph=graph,
        variable_id="file",
        candidate_values=("/docs/a.bin", "/docs/a.bin.locked"),
        rows=(
            {"file_path": "/docs/a.bin", "action": "CREATED"},
            {"file_path": "/docs/a.bin.locked", "action": "MOVED_TO"},
        ),
    )
    assert filtered == ()


def test_complete_explore_builds_census_groups_without_autobind() -> None:
    from hunting.contracts.bindings import CandidateBinding, CandidateSet
    from hunting.contracts.hunt import HuntObjective, HuntState
    from hunting.engine import HypothesisHuntEngine
    from hunting.planner.semantic_executor import SemanticExecutionResult, StepExecution

    graph = SemanticGoalGraph(
        id="g-census",
        request_id="req-census",
        objective="Name a document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable("file", "file", value_origin="llm_proposal"),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        "find-file", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        discriminator_fields=("action", "file_path"),
    )
    rows = (
        {"file_path": "/tmp/notes.pdf", "action": "CREATED"},
        {"file_path": "/tmp/readme.txt", "action": "CREATED"},
        {"file_path": "/tmp/payload.bin.locked", "action": "MOVED_TO"},
    )
    execution = SemanticExecutionResult(
        executions=[StepExecution(
            step_id="s1", query_id="q-explore", operation_id="find-file",
            result=QueryResult(
                query_id="q-explore", outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=True, rows=list(rows),
            ),
            inputs={"subject": ["HOST-1"]}, status="AMBIGUOUS",
        )],
        ambiguous_candidates={
            "file": ["/tmp/notes.pdf", "/tmp/readme.txt", "/tmp/payload.bin.locked"],
        },
        needs_user_decision=True,
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="req-census", statement="name the file",
            time_window="2017-08-01T00:00:00Z/P30D",
        ),
        semantic_goal_graph=graph,
    )
    cset = CandidateSet(variable_id="file", entity_type="file", cardinality="singular")
    for value in execution.ambiguous_candidates["file"]:
        cset.add_candidate(CandidateBinding(value=value, entity_type="file"))
    state.candidate_sets["file"] = cset
    result = HypothesisHuntEngine()._attempt_semantic_discrimination(
        state=state,
        execution=execution,
        scope=ProviderScope("p", "scope", {}),
        active_adapter=object(),
        operations=(operation,),
        goal_graph=graph,
        target_cardinality={"file": "singular"},
        time_window="2017-08-01T00:00:00Z/P30D",
    )
    assert result.needs_user_decision is True
    assert len(result.ambiguous_candidates["file"]) == 3
    groups = result.candidate_groups["file"]
    assert {item["field"] for item in groups} == {"action"}
    actions = {item["value"] for item in groups}
    assert actions == {"CREATED", "MOVED_TO"}
    assert not any(item["field"] == "file_path" for item in groups)


def test_request_literal_in_bag_reduces_candidates_without_playbook() -> None:
    from hunting.contracts.bindings import CandidateBinding, CandidateSet
    from hunting.contracts.hunt import HuntObjective, HuntState
    from hunting.engine import HypothesisHuntEngine
    from hunting.planner.semantic_executor import SemanticExecutionResult, StepExecution

    graph = SemanticGoalGraph(
        id="g-lit",
        request_id="req-lit",
        objective="Find secret.pdf on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable(
                "file",
                "file",
                value_origin="request",
                constraints=(SemanticConstraint("file_name", "secret.pdf"),),
            ),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    operation = ProviderOperation(
        "find-file", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        discriminator_fields=("action", "file_path"),
        discriminator_constraint_bindings={"file_name": "file_path"},
    )
    values = ["/tmp/secret.pdf", "/tmp/readme.txt", "/tmp/notes.bin"]
    execution = SemanticExecutionResult(
        executions=[StepExecution(
            step_id="s1", query_id="q-explore", operation_id="find-file",
            result=QueryResult(
                query_id="q-explore", outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=True,
                rows=[{"file_path": value, "action": "CREATED"} for value in values],
            ),
            inputs={"subject": ["HOST-1"]}, status="AMBIGUOUS",
        )],
        ambiguous_candidates={"file": list(values)},
        needs_user_decision=True,
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="req-lit", statement="find secret.pdf",
            time_window="2017-08-01T00:00:00Z/P30D",
        ),
        semantic_goal_graph=graph,
    )
    cset = CandidateSet(variable_id="file", entity_type="file", cardinality="singular")
    for value in values:
        cset.add_candidate(CandidateBinding(value=value, entity_type="file"))
    state.candidate_sets["file"] = cset
    result = HypothesisHuntEngine()._attempt_semantic_discrimination(
        state=state,
        execution=execution,
        scope=ProviderScope("p", "scope", {}),
        active_adapter=object(),
        operations=(operation,),
        goal_graph=graph,
        target_cardinality={"file": "singular"},
        time_window="2017-08-01T00:00:00Z/P30D",
    )
    assert result.ambiguous_candidates["file"] == ["/tmp/secret.pdf"]
    assert result.needs_user_decision is True


def test_analyst_report_groups_candidates_instead_of_hiding_tail() -> None:
    from hunting.contracts.coverage import CoverageBound
    from hunting.contracts.hunt import FinalHuntAccount, HuntObjective, Hypothesis, HypothesisStatus

    hidden = "/docs/needed.bin.locked"
    provenance = [{"value": f"/tmp/noise-{index}.dat", "status": "CANDIDATE"} for index in range(20)]
    provenance.append({"value": hidden, "status": "CANDIDATE"})
    account = FinalHuntAccount(
        request_id="req-groups",
        objective=HuntObjective(request_id="req-groups", statement="What is the file name?"),
        hypotheses=[Hypothesis(id="h1", statement="A file changed on a host", status=HypothesisStatus.LIVE)],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_NEEDS_USER_DECISION,
        answer={"status": "INCONCLUSIVE", "reason": "USER_DECISION_REQUIRED", "explanation": "Pick a file group."},
        semantic_analysis={
            "needs_user_decision": True,
            "retrieval_incomplete": True,
            "continuations": {"s1": {"cursor": "400"}},
            "compiler_limitations": ["file_type=office presentation", "state=encrypted"],
            "goal_verdicts": [{
                "goal_id": "r1",
                "compiler_limitations": ["file_type=office presentation"],
            }],
            "binding_provenance": {"var_file": provenance},
            "candidate_groups": {
                "var_file": [
                    {
                        "field": "action",
                        "value": "MOVED_TO",
                        "count": 1,
                        "candidates": [hidden],
                    },
                    {
                        "field": "action",
                        "value": "CREATED",
                        "count": 20,
                        "candidates": [f"/tmp/noise-{index}.dat" for index in range(8)],
                    },
                ]
            },
        },
    )
    report = render_analyst_report(account)
    section_one = report.split("## 2.")[0]
    assert hidden in report
    assert "MOVED_TO" in report
    assert "20" in report
    assert "retrieval incomplete" in report.casefold()
    assert "pick a group" in report.casefold()
    assert "file_type=office presentation" in report
    assert "Perfmon" not in report
    assert "/tmp/noise-19.dat" not in report
    assert report.count("/tmp/noise-") < 3
    assert section_one.count("\n") <= 40
    assert report.count("\n") < 90


def test_information_gain_prefers_the_field_that_splits() -> None:
    process_groups = [
        {"field": "image", "value": "a.exe", "count": 2, "candidates": ["p1", "p2"]},
        {"field": "image", "value": "b.exe", "count": 1, "candidates": ["p3"]},
        {"field": "file_path", "value": "p1", "count": 1, "candidates": ["p1"]},
        {"field": "file_path", "value": "p2", "count": 1, "candidates": ["p2"]},
        {"field": "file_path", "value": "p3", "count": 1, "candidates": ["p3"]},
    ]
    file_groups = [
        {"field": "action", "value": "CREATED", "count": 4, "candidates": ["a", "b", "c", "d"]},
        {"field": "path_suffix", "value": ".pdf", "count": 1, "candidates": ["/tmp/a.pdf"]},
        {"field": "path_suffix", "value": ".txt", "count": 1, "candidates": ["/tmp/b.txt"]},
        {"field": "path_suffix", "value": ".doc", "count": 1, "candidates": ["/tmp/c.doc"]},
        {"field": "path_suffix", "value": ".bin", "count": 1, "candidates": ["/tmp/d.bin"]},
    ]
    assert _select_winning_facet(process_groups, 3) == "image"
    assert _select_winning_facet(file_groups, 4) == "path_suffix"
    assert _select_winning_facet([], 4) is None
    assert _facet_information_gain(4, (1, 1, 1, 1)) > _facet_information_gain(4, (4,))


def test_process_census_wins_on_image_not_identity() -> None:
    from hunting.contracts.bindings import CandidateBinding, CandidateSet
    from hunting.contracts.hunt import HuntObjective, HuntState
    from hunting.engine import HypothesisHuntEngine
    from hunting.planner.semantic_executor import SemanticExecutionResult, StepExecution

    values = ["pid-1", "pid-2", "pid-3"]
    rows = (
        {"process_guid": "pid-1", "image": "a.exe"},
        {"process_guid": "pid-2", "image": "a.exe"},
        {"process_guid": "pid-3", "image": "b.exe"},
    )
    graph = SemanticGoalGraph(
        id="g-proc",
        request_id="req-proc",
        objective="Name a process on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable("process", "process", value_origin="llm_proposal"),
        ],
        relations=[SemanticRelationGoal("r1", "host", "executed", "process")],
        answers=[SemanticAnswerGoal("process", "process_name")],
    )
    operation = ProviderOperation(
        "find-process", "p", ("scope",),
        input_entity_kinds=("host",), output_entity_kinds=("process",),
        output_value_bindings={"object": ("process_guid",)},
        output_binding_entity_kinds={"object": "process"},
        guaranteed_relations=("executed",),
        discriminator_fields=("image", "file_path"),
    )
    execution = SemanticExecutionResult(
        executions=[StepExecution(
            step_id="s1", query_id="q-explore", operation_id="find-process",
            result=QueryResult(
                query_id="q-explore", outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=True, rows=list(rows),
            ),
            inputs={"subject": ["HOST-1"]}, status="AMBIGUOUS",
        )],
        ambiguous_candidates={"process": list(values)},
        needs_user_decision=True,
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="req-proc", statement="name the process",
            time_window="2017-08-01T00:00:00Z/P30D",
        ),
        semantic_goal_graph=graph,
    )
    cset = CandidateSet(variable_id="process", entity_type="process", cardinality="singular")
    for value in values:
        cset.add_candidate(CandidateBinding(value=value, entity_type="process"))
    state.candidate_sets["process"] = cset
    result = HypothesisHuntEngine()._attempt_semantic_discrimination(
        state=state,
        execution=execution,
        scope=ProviderScope("p", "scope", {}),
        active_adapter=object(),
        operations=(operation,),
        goal_graph=graph,
        target_cardinality={"process": "singular"},
        time_window="2017-08-01T00:00:00Z/P30D",
    )
    groups = result.candidate_groups["process"]
    assert {item["field"] for item in groups} == {"image"}
    assert not any(item["field"] == "file_path" for item in groups)
    assert not any(item["field"] == "process_guid" for item in groups)


def test_zero_information_gain_does_not_invent_groups() -> None:
    from hunting.contracts.bindings import CandidateBinding, CandidateSet
    from hunting.contracts.hunt import HuntObjective, HuntState
    from hunting.engine import HypothesisHuntEngine
    from hunting.planner.semantic_executor import SemanticExecutionResult, StepExecution

    values = ["HOST-A", "HOST-B", "HOST-C"]
    graph = SemanticGoalGraph(
        id="g-ig0",
        request_id="req-ig0",
        objective="Name a host",
        variables=[
            SemanticVariable("user", "person", "Alice", value_origin="request"),
            SemanticVariable("host", "host", value_origin="llm_proposal"),
        ],
        relations=[SemanticRelationGoal("r1", "user", "associated_with", "host")],
        answers=[SemanticAnswerGoal("host", "host_name")],
    )
    operation = ProviderOperation(
        "find-host", "p", ("scope",),
        input_entity_kinds=("person",), output_entity_kinds=("host",),
        output_value_bindings={"object": ("host",)},
        output_binding_entity_kinds={"object": "host"},
        guaranteed_relations=("associated_with",),
        discriminator_fields=("host",),
    )
    execution = SemanticExecutionResult(
        executions=[StepExecution(
            step_id="s1", query_id="q-explore", operation_id="find-host",
            result=QueryResult(
                query_id="q-explore", outcome=QueryOutcome.ROWS,
                executed_ok=True, complete=True,
                rows=[{"host": value} for value in values],
            ),
            inputs={"subject": ["Alice"]}, status="AMBIGUOUS",
        )],
        ambiguous_candidates={"host": list(values)},
        needs_user_decision=True,
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="req-ig0", statement="name the host",
            time_window="2017-08-01T00:00:00Z/P30D",
        ),
        semantic_goal_graph=graph,
    )
    cset = CandidateSet(variable_id="host", entity_type="host", cardinality="singular")
    for value in values:
        cset.add_candidate(CandidateBinding(value=value, entity_type="host"))
    state.candidate_sets["host"] = cset
    result = HypothesisHuntEngine()._attempt_semantic_discrimination(
        state=state,
        execution=execution,
        scope=ProviderScope("p", "scope", {}),
        active_adapter=object(),
        operations=(operation,),
        goal_graph=graph,
        target_cardinality={"host": "singular"},
        time_window="2017-08-01T00:00:00Z/P30D",
    )
    assert result.needs_user_decision is True
    assert result.candidate_groups.get("host") in (None, [])


def test_clarifier_discriminates_non_host_entity_types() -> None:
    from hunting.contracts.bindings import CandidateBinding, CandidateSet
    from hunting.human_loop.clarification import ClarificationController, DisambiguationAction

    cset = CandidateSet(variable_id="file", entity_type="file", cardinality="singular")
    cset.add_candidate(CandidateBinding(value="/docs/a.txt", entity_type="file"))
    cset.add_candidate(CandidateBinding(value="/docs/b.txt", entity_type="file"))
    action, spec = ClarificationController(interactive=False).resolve_candidate_set(
        cset, request_id="req-file",
    )
    assert action == DisambiguationAction.DISCRIMINATE
    assert spec.target_variable_id == "file"


def test_resume_bucket_keeps_members_without_playbook_or_fanout() -> None:
    groups = [
        {
            "field": "action",
            "value": "MOVED_TO",
            "count": 2,
            "candidates": ["/docs/d.txt", "/docs/e.txt"],
        },
        {
            "field": "action",
            "value": "CREATED",
            "count": 3,
            "candidates": ["/docs/a.txt", "/docs/b.txt", "/docs/c.txt"],
        },
    ]
    remaining = apply_facet_bucket_selection(groups, field="action", value="MOVED_TO")
    assert remaining == ["/docs/d.txt", "/docs/e.txt"]

    graph = SemanticGoalGraph(
        id="g-resume",
        request_id="req-resume",
        objective="Name a document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable(
                "file",
                "file",
                value_origin="llm_proposal",
                constraints=(SemanticConstraint("file_type", "office presentation"),),
            ),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    updated, selections = apply_resume_bindings(
        graph,
        facet_constraints={"file": ("action", "MOVED_TO")},
    )
    file_var = next(item for item in updated.variables if item.id == "file")
    assert file_var.value is None
    assert file_var.value_origin == "llm_proposal"
    assert ("action", "MOVED_TO") in {(item.key, item.value) for item in file_var.constraints}
    assert selections["file"] == ("action", "MOVED_TO")
    assert "office presentation" in {item.value for item in file_var.constraints}

    operation = ProviderOperation(
        id="find-file",
        provider_id="p",
        scope_ids=("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        searchable_constraints=("file_type", "file_extension", "action"),
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(updated)
    assert plan.steps
    assert plan.steps[0].constraint_retrieval_terms == ()
    assert ".pptx" not in str(plan.steps[0].constraints)


def test_resume_unique_path_is_not_fanout() -> None:
    graph = SemanticGoalGraph(
        id="g-one",
        request_id="req-one",
        objective="Name a document on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1", value_origin="request"),
            SemanticVariable("file", "file", value_origin="llm_proposal"),
        ],
        relations=[SemanticRelationGoal("r1", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file_name")],
    )
    updated, selections = apply_resume_bindings(
        graph,
        initial_bindings={"file": "/docs/needed.bin.locked"},
    )
    file_var = next(item for item in updated.variables if item.id == "file")
    assert file_var.value == "/docs/needed.bin.locked"
    assert file_var.value_origin == "user_selection"
    assert selections == {}
    many, _ = apply_resume_bindings(
        graph,
        initial_bindings={"file": ["/docs/a.txt", "/docs/b.txt"]},
    )
    unbound = next(item for item in many.variables if item.id == "file")
    assert unbound.value is None


def test_cli_prefers_facet_buckets_over_entity_dump() -> None:
    from types import SimpleNamespace

    from hunting.cli import _collect_facet_bucket_options, _collect_semantic_candidate_options

    hidden = "/docs/needed.bin.locked"
    analysis = {
        "candidate_groups": {
            "file": [
                {"field": "action", "value": "MOVED_TO", "count": 1, "candidates": [hidden]},
                {"field": "action", "value": "CREATED", "count": 20, "candidates": ["/tmp/noise-0.dat"]},
            ]
        },
        "binding_provenance": {
            "file": [{"value": f"/tmp/noise-{index}.dat", "status": "CANDIDATE"} for index in range(20)]
        },
    }
    result = SimpleNamespace(
        account=SimpleNamespace(semantic_analysis=analysis, candidate_sets={}),
        state=SimpleNamespace(candidate_sets={}),
    )
    buckets = _collect_facet_bucket_options(result)
    assert buckets[0][:3] == ("file", "action", "MOVED_TO")
    assert all(item[1] == "action" for item in buckets)
    dumped = _collect_semantic_candidate_options(result, {"file": "file"})
    assert len(dumped) == 20


def test_compiler_limitation_is_a_question_label_not_a_search_token() -> None:
    from hunting.contracts.coverage import CoverageBound
    from hunting.contracts.hunt import FinalHuntAccount, HuntObjective, Hypothesis, HypothesisStatus

    account = FinalHuntAccount(
        request_id="req-label",
        objective=HuntObjective(request_id="req-label", statement="What is the file name?"),
        hypotheses=[Hypothesis(id="h1", statement="A file changed on a host", status=HypothesisStatus.LIVE)],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_NEEDS_USER_DECISION,
        answer={"status": "INCONCLUSIVE", "reason": "USER_DECISION_REQUIRED", "explanation": "Pick a group."},
        semantic_analysis={
            "needs_user_decision": True,
            "compiler_limitations": ["file_type=office presentation"],
            "goal_verdicts": [{"goal_id": "r1", "compiler_limitations": ["file_type=office presentation"]}],
            "candidate_groups": {
                "file": [{"field": "action", "value": "MOVED_TO", "count": 1, "candidates": ["/docs/a.bin"]}]
            },
        },
    )
    report = render_analyst_report(account)
    assert "file_type=office presentation" in report
    assert "pick a group" in report.casefold()
    assert ".pptx" not in report
    assert "office presentation" not in report.split("**Candidate groups:**")[-1]
