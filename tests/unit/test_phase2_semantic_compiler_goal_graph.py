import json

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import (
    HuntRequest,
    HuntRequestKind,
    HuntState,
    StoppingDecision,
)
from hunting.contracts.semantic_graph import (
    AnswerContract,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.reporter.builder import build_final_hunt_account
from hunting.validator.investigation_validator import (
    SemanticGoalGraphValidator,
)


def test_answer_contract_and_goal_graph_contracts() -> None:
    """Verify AnswerContract and v8 GoalGraph fields serialize and deserialize."""
    ac = AnswerContract(
        slot_name="target_file",
        value_type="file",
        target_variable_id="file_var",
        required_qualifiers=("q1",),
        min_citations=2,
        acceptable_aliases=("document", "presentation"),
        acceptance_rule="observed file artifact with valid hash",
        description="Encrypted campaign presentation",
    )
    data = ac.to_dict()
    assert data["slot_name"] == "target_file"
    assert data["value_type"] == "file"
    assert data["min_citations"] == 2

    restored_ac = AnswerContract.from_dict(data)
    assert restored_ac.slot_name == "target_file"
    assert restored_ac.min_citations == 2
    assert "presentation" in restored_ac.acceptable_aliases

    graph = SemanticGoalGraph(
        id="goal-v8",
        request_id="req-v8",
        objective="Find the encrypted presentation",
        variables=[
            SemanticVariable("user", "person", "Mallory", value_origin="request"),
            SemanticVariable("host", "host", None, value_origin="llm_proposal"),
            SemanticVariable("file_var", "file", None, value_origin="llm_proposal"),
        ],
        relations=[
            SemanticRelationGoal(
                id="g1",
                subject="user",
                relation="associated_with",
                object="host",
                atomic_obligation="Verify user endpoint association",
                provenance_span="Mallory's laptop",
                dependencies=(),
                dependency_operator="AND",
            ),
            SemanticRelationGoal(
                id="g2",
                subject="host",
                relation="modified",
                object="file_var",
                atomic_obligation="Identify modified presentation",
                provenance_span="encrypted presentation file",
                dependencies=("g1",),
                dependency_operator="AND",
            ),
        ],
        qualifiers=[
            SemanticQualifierGoal("q1", "g2", "state", "encrypted"),
        ],
        answer_contracts=[ac],
        dependencies={"g2": ["g1"]},
        dependency_kinds={"g2": "AND"},
        provenance_spans={"g1": "Mallory's laptop", "g2": "encrypted presentation file"},
        assumptions=["Host is active during Q3"],
        forbidden_inferences=["Do not infer hostname directly from MacBook"],
        clarification_triggers=["Multiple hostnames associated with Mallory"],
    )

    d = graph.to_dict()
    assert d["answer_contracts"][0]["slot_name"] == "target_file"
    assert d["dependencies"]["g2"] == ["g1"]
    assert d["provenance_spans"]["g1"] == "Mallory's laptop"
    assert "Do not infer hostname directly from MacBook" in d["forbidden_inferences"]

    from_d = SemanticGoalGraph.from_dict(d)
    assert len(from_d.answer_contracts) == 1
    assert from_d.answer_contracts[0].target_variable_id == "file_var"
    assert from_d.dependencies["g2"] == ["g1"]


def test_validator_rejects_entity_mutation_mallory_cannot_become_alice() -> None:
    """Gate: User named Mallory; validator strictly rejects mutation to Alice."""
    graph = SemanticGoalGraph(
        id="goal-1",
        request_id="req-1",
        objective="Find files accessed by Mallory",
        variables=[
            SemanticVariable("p1", "person", "Alice", value_origin="llm_proposal"),
            SemanticVariable("f1", "file"),
        ],
        relations=[
            SemanticRelationGoal("r1", "p1", "modified", "f1"),
        ],
        answers=[],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, "What files were encrypted on Mallory's laptop?")
    assert not result.valid
    assert any("Entity mutation rejected" in err and "Alice" in err for err in result.rejections)


def test_validator_demotes_macbook_from_hostname_to_device_qualifier() -> None:
    """Gate: 'MacBook' in request is a device qualifier, never a hostname."""
    graph = SemanticGoalGraph(
        id="goal-2",
        request_id="req-2",
        objective="Find Mallory's MacBook",
        variables=[
            SemanticVariable("p1", "person", "Mallory", value_origin="request"),
            SemanticVariable("h1", "host", "MacBook", value_origin="llm_proposal"),
        ],
        relations=[
            SemanticRelationGoal("r1", "p1", "associated_with", "h1"),
        ],
        answers=[],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, "Find activity on Mallory's MacBook")
    assert result.valid
    # Host value must be unbound (None), with device_type constraint added
    validated_host = [v for v in result.validated_graph.variables if v.id == "h1"][0]
    assert validated_host.value is None
    assert any(c.key == "device_type" and "MacBook" in str(c.value) for c in validated_host.constraints)
    assert any("Device qualifier" in diag and "MacBook" in diag for diag in result.diagnostics)


def test_validator_preserves_proper_nouns_in_vietnamese_and_unfamiliar_names() -> None:
    """Gate: Preserves Vietnamese and unfamiliar proper nouns without mutation."""
    req_text = "Tìm các tệp mà ông Nguyễn Văn Bình đã tải về từ máy tính cá nhân"
    graph = SemanticGoalGraph(
        id="goal-vn",
        request_id="req-vn",
        objective="Tìm tệp tải về",
        variables=[
            SemanticVariable("p1", "person", "Nguyễn Văn Bình", value_origin="request"),
            SemanticVariable("f1", "file"),
        ],
        relations=[
            SemanticRelationGoal("r1", "p1", "downloaded", "f1", provenance_span="Nguyễn Văn Bình đã tải về"),
        ],
        answers=[],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, req_text)
    assert result.valid
    val_person = [v for v in result.validated_graph.variables if v.id == "p1"][0]
    assert val_person.value == "Nguyễn Văn Bình"


def test_validator_prunes_unrelated_story_expansion() -> None:
    """Gate: Downstream goals that do not reduce or qualify an answer slot are pruned."""
    graph = SemanticGoalGraph(
        id="goal-expansion",
        request_id="req-expansion",
        objective="Find Mallory's personal email",
        variables=[
            SemanticVariable("user", "person", "Mallory", value_origin="request"),
            SemanticVariable("email", "email_address", None),
            SemanticVariable("dns_server", "host", "8.8.8.8", value_origin="llm_proposal"),
            SemanticVariable("domain", "domain", "evil.com", value_origin="llm_proposal"),
        ],
        relations=[
            SemanticRelationGoal("r_target", "user", "associated_with", "email"),
            # Unrequested story expansion: random DNS exfil not leading to the requested email
            SemanticRelationGoal("r_story", "dns_server", "resolved", "domain"),
        ],
        answers=[],
        answer_contracts=[
            AnswerContract(slot_name="email", value_type="email_address", target_variable_id="email"),
        ],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, "What is Mallory's personal email address?")
    assert result.valid
    # The story goal r_story must be pruned because it has no connection to email answer slot
    remaining_rel_ids = [r.id for r in result.validated_graph.relations]
    assert "r_target" in remaining_rel_ids
    assert "r_story" not in remaining_rel_ids
    assert "r_story" in result.pruned_goal_ids
    assert any("Ungrounded story expansion pruned" in d and "r_story" in d for d in result.diagnostics)


def test_validator_rejects_cyclic_dependencies() -> None:
    """Gate: Dependencies must form an acyclic DAG."""
    graph = SemanticGoalGraph(
        id="goal-cycle",
        request_id="req-cycle",
        objective="Cycle test",
        variables=[
            SemanticVariable("p", "person", "Mallory", value_origin="request"),
            SemanticVariable("h", "host"),
        ],
        relations=[
            SemanticRelationGoal("r1", "p", "associated_with", "h", dependencies=("r2",)),
            SemanticRelationGoal("r2", "h", "logged_on_to", "p", dependencies=("r1",)),
        ],
        answers=[],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, "Mallory logged on")
    assert not result.valid
    assert any("Cyclic dependency detected" in err for err in result.rejections)


def test_validator_rejects_gate_operator_without_gate_condition() -> None:
    """Gate: GATE dependency operator requires explicit gate_condition."""
    graph = SemanticGoalGraph(
        id="goal-gate",
        request_id="req-gate",
        objective="Gate test",
        variables=[
            SemanticVariable("p", "person", "Mallory", value_origin="request"),
            SemanticVariable("h", "host"),
        ],
        relations=[
            SemanticRelationGoal(
                "r1", "p", "associated_with", "h",
                dependency_operator="GATE",
                gate_condition=None,
            ),
        ],
        answers=[],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, "Find Mallory's host")
    assert not result.valid
    assert any("GATE dependency operator but lacks gate_condition" in err for err in result.rejections)


def test_validator_rejects_native_query_leak_in_constraints() -> None:
    """Gate: No SPL/SQL/KQL syntax allowed in constraints or retrieval terms."""
    graph = SemanticGoalGraph(
        id="goal-leak",
        request_id="req-leak",
        objective="Leak test",
        variables=[
            SemanticVariable(
                "h", "host", None,
                constraints=[
                    SemanticConstraint(key="filter", value="index=main | table host", operator="equals"),
                ]
            ),
        ],
        relations=[
            SemanticRelationGoal("r1", "h", "observed", "h"),
        ],
        answers=[],
    )
    validator = SemanticGoalGraphValidator()
    result = validator.validate_goal_graph(graph, "Search for host")
    assert not result.valid
    assert any("Native query syntax leaked" in err for err in result.rejections)


def test_compiler_end_to_end_emits_goal_graph_and_persists_to_account() -> None:
    """Verify C1 compiler output flow through validation into FinalHuntAccount."""
    llm_payload = {
        "id": "goal-c1",
        "request_id": "req-c1",
        "objective": "Find the PowerPoint presentation on Mallory's MacBook",
        "variables": [
            {
                "id": "user",
                "entity_type": "person",
                "value": "Mallory",
                "value_origin": "request",
                "constraints": [],
            },
            {
                "id": "endpoint",
                "entity_type": "host",
                "value": "MacBook",  # Device qualifier to be demoted
                "value_origin": "llm_proposal",
                "constraints": [],
            },
            {
                "id": "pres",
                "entity_type": "file",
                "value": None,
                "value_origin": "llm_proposal",
                "constraints": [
                    {
                        "key": "extension",
                        "operator": "equals",
                        "value": ".pptx",
                        "retrieval_terms": [".pptx", ".ppt"],
                    }
                ],
            },
        ],
        "relations": [
            {
                "id": "g1",
                "subject": "user",
                "relation": "associated_with",
                "object": "endpoint",
                "required": True,
                "atomic_obligation": "Find endpoint associated with Mallory",
                "provenance_span": "Mallory's MacBook",
                "dependencies": [],
                "dependency_operator": "AND",
            },
            {
                "id": "g2",
                "subject": "endpoint",
                "relation": "stored_on",
                "object": "pres",
                "required": True,
                "atomic_obligation": "Find presentation file stored on endpoint",
                "provenance_span": "PowerPoint presentation",
                "dependencies": ["g1"],
                "dependency_operator": "AND",
            },
        ],
        "qualifiers": [
            {
                "id": "q1",
                "target_goal_id": "g2",
                "qualifier": "kind",
                "expected_value": "PowerPoint",
                "required": True,
            }
        ],
        "answers": [
            {"variable_id": "pres", "answer_type": "file_name", "required": True},
        ],
        "answer_contracts": [
            {
                "slot_name": "presentation_file",
                "value_type": "file_name",
                "target_variable_id": "pres",
                "required_qualifiers": ["q1"],
                "min_citations": 1,
                "acceptance_rule": "observed PowerPoint file on host",
            }
        ],
        "assumptions": ["Device was connected during August 2017"],
        "forbidden_inferences": ["Do not assume MacBook is the hostname"],
        "clarification_triggers": ["Ambiguous endpoint bindings"],
    }

    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: json.dumps(llm_payload))
    req = HuntRequest("req-c1", HuntRequestKind.NL_QUESTION, "Find the PowerPoint presentation on Mallory's MacBook")
    objective, hypotheses, requirements = compiler.compile(req)

    # 1. Verify compiler output
    assert objective.semantic_goal_graph is not None
    graph = objective.semantic_goal_graph
    assert len(graph.answer_contracts) == 1
    assert graph.answer_contracts[0].slot_name == "presentation_file"

    # 2. Verify MacBook demoted from hostname
    host_var = [v for v in graph.variables if v.id == "endpoint"][0]
    assert host_var.value is None  # Unbound
    assert any(c.key == "device_type" for c in host_var.constraints)

    # 3. Verify raw proposal and diagnostics preserved on objective
    assert objective.llm_raw_proposal is not None
    assert len(objective.validation_diagnostics) > 0

    # 4. Verify propagation to FinalHuntAccount
    state = HuntState(
        objective=objective,
        hypotheses=hypotheses,
        requirements=requirements,
        semantic_goal_graph=graph,
        llm_raw_proposal=objective.llm_raw_proposal,
        validated_graph=graph,
        validation_diagnostics=objective.validation_diagnostics,
        stopping_decision=StoppingDecision.STOP_BOUNDED,
    )
    account = build_final_hunt_account(state)

    assert account.llm_raw_proposal is not None
    assert account.validated_graph is not None
    assert len(account.validation_diagnostics) > 0
    assert account.semantic_goal_graph is not None
    assert len(account.semantic_goal_graph.answer_contracts) == 1
