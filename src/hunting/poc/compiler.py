"""PoC compiler — turns a PoC into a SemanticGoalGraph.

The compiler is deterministic. It does not call the LLM. It converts each
``TestStep`` into a typed relation on a ``SemanticGoalGraph`` that the v6
executor can already consume.

Why deterministic
-----------------
A PoC is, by definition, an explicit and anchored threat hypothesis. The
compiler's job is the boring one: turn a regex into a typed predicate on a
typed field. The LLM only sees this graph later, as evidence, when it
explains a result; it does not create the graph.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)


_RELATION_KIND = {
    "process": "process_execution",
    "dns": "dns_resolution",
    "web": "web_request_activity",
    "file": "file_artifact",
}


# Map PoC step ops to the SemanticConstraint operators (only equals /
# contains / exists are accepted by the contract; the others collapse to
# substring/equality or are recorded in retrieval_terms).
_OP_TO_CONSTRAINT_OP = {
    "EQUALS": "equals",
    "STARTS_WITH": "contains",
    "ENDS_WITH": "contains",
    "CONTAINS": "contains",
    "MATCHES": "contains",
    "EXISTS": "exists",
}


def _op_to_constraint_op(op: str) -> str:
    return _OP_TO_CONSTRAINT_OP.get(op.upper(), "contains")


_FIELD_TO_ENTITY = {
    "image": "process",
    "parent_image": "process",
    "cmdline": "command",
    "process": "process",
    "host": "host",
    "computer": "host",
    "endpoint": "host",
    "user": "account",
    "username": "account",
    "query": "domain",
    "domain": "domain",
    "site": "domain",
    "uri": "url",
    "url": "url",
    "src_ip": "ip",
    "client_ip": "ip",
    "ip": "ip",
    "file_path": "file",
    "method": "http_method",
}


def _field_to_entity_type(target_field: str) -> str:
    return _FIELD_TO_ENTITY.get(target_field.lower(), "event")


def compile_poc(poc, request_id: str, time_window: str) -> SemanticGoalGraph:
    """Compile a PoC into a SemanticGoalGraph.

    The PoC's first step becomes the anchor variable. Each subsequent step
    becomes a relation that constrains the anchor. The compiler always
    produces the same output for the same input.
    """
    if not poc.steps:
        raise ValueError(f"PoC {poc.poc_id} has no test steps")

    first_step = poc.steps[0]
    anchor_entity = _field_to_entity_type(first_step.target_field)
    anchor_value = first_step.value if first_step.op.value in {"EQUALS", "STARTS_WITH"} else None
    anchor = SemanticVariable(
        id=f"v-{request_id}-anchor",
        entity_type=anchor_entity,
        value=anchor_value,
        value_origin="request",
        verification_status="UNVERIFIED",
        constraints=(),
    )

    target_var_id = f"v-{request_id}-target"
    target_var = SemanticVariable(
        id=target_var_id,
        entity_type="event",
        value=None,
        value_origin="request",
        verification_status="UNVERIFIED",
        constraints=(),
    )

    variables = [anchor, target_var]
    relations: list[SemanticRelationGoal] = []
    qualifiers: list[Any] = []

    for index, step in enumerate(list(poc.steps) + list(poc.fallbacks)):
        op = _op_to_constraint_op(step.op.value)
        constraint_value = step.value if op != "exists" else None
        constraint = SemanticConstraint(
            key=step.target_field,
            operator=op,
            value=constraint_value,
            retrieval_terms=[step.description],
        )
        relation = SemanticRelationGoal(
            id=f"r-{request_id}-{step.step_id}",
            subject=anchor.id,
            relation=_RELATION_KIND.get(step.source_kind, "process_execution"),
            object=target_var_id,
            required=True,
            description=step.description,
        )
        relations.append(relation)
        original_target_field = step.target_field
        qualifiers.append(
            _Qualifier(
                id=f"q-{request_id}-{step.step_id}-{index}",
                target_goal_id=relation.id,
                qualifier=f"{original_target_field}:{op}",
                expected_value=step.value,
                required=True,
            )
        )

    answers = [
        SemanticAnswerGoal(
            variable_id=anchor.id,
            answer_type=anchor_entity,
            required=False,
        )
    ]

    graph = SemanticGoalGraph(
        id=f"sgg-{request_id}",
        request_id=request_id,
        objective=poc.summary,
        variables=variables,
        relations=relations,
        qualifiers=qualifiers,
        answers=answers,
        assumptions=[f"PoC {poc.poc_id}: {poc.name}"],
        uncertainties=list(poc.expected_chain),
    )
    return graph


class _Qualifier:
    """Local stand-in for the semantic qualifier contract; we keep the
    constructor minimal because the executor does not consume qualifiers
    during PoC mode — qualifiers are metadata only."""

    __slots__ = ("id", "target_goal_id", "qualifier", "expected_value", "required")

    def __init__(self, id: str, target_goal_id: str, qualifier: str, expected_value: Any, required: bool) -> None:
        self.id = id
        self.target_goal_id = target_goal_id
        self.qualifier = qualifier
        self.expected_value = expected_value
        self.required = required


def graph_summary(graph: SemanticGoalGraph) -> dict[str, Any]:
    """Compact summary for logs and reports."""
    return {
        "graph_id": graph.id,
        "request_id": graph.request_id,
        "objective": graph.objective,
        "variables": [
            {"id": v.id, "entity_type": v.entity_type, "value": v.value}
            for v in graph.variables
        ],
        "relations": [
            {
                "id": r.id,
                "subject": r.subject,
                "relation": r.relation,
                "object": r.object,
                "description": r.description,
            }
            for r in graph.relations
        ],
        "qualifiers": [
            {
                "id": q.id,
                "target_goal_id": q.target_goal_id,
                "qualifier": q.qualifier,
                "expected_value": q.expected_value,
            }
            for q in graph.qualifiers
        ],
    }
