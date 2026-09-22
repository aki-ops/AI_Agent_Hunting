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
from hunting.peak import able_drive

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


def _able_constraints(poc) -> tuple[SemanticConstraint, ...]:
    """Turn ABLE into typed constraints. Retrieval terms are the concrete tokens."""
    drive = able_drive(poc.actor, poc.behavior, poc.location, poc.evidence)
    constraints: list[SemanticConstraint] = []
    if poc.behavior:
        constraints.append(SemanticConstraint(
            key="able_behavior",
            operator="contains",
            value=poc.behavior,
            retrieval_terms=drive.observables,
        ))
    if poc.location:
        constraints.append(SemanticConstraint(
            key="able_location",
            operator="contains",
            value=poc.location,
            retrieval_terms=(drive.host,) if drive.host else (),
        ))
    if poc.evidence:
        constraints.append(SemanticConstraint(
            key="able_evidence",
            operator="contains",
            value=poc.evidence,
            retrieval_terms=drive.evidence_fields,
        ))
    if poc.actor:
        constraints.append(SemanticConstraint(
            key="able_actor",
            operator="equals",
            value=poc.actor,
            retrieval_terms=(drive.actor,) if drive.actor else (),
        ))
    return tuple(constraints)


def compile_poc(poc, request_id: str, time_window: str, scope_note: str = "") -> SemanticGoalGraph:
    """Compile a PoC into a SemanticGoalGraph.

    The PoC's first step becomes the anchor variable. Each subsequent step
    becomes a relation that constrains the anchor. ABLE is attached to the
    anchor as typed constraints whose retrieval terms are the concrete
    observables the agent ANDs into ``search_text``. The compiler always
    produces the same output for the same input.
    """
    if not poc.steps:
        raise ValueError(f"PoC {poc.poc_id} has no test steps")

    drive = able_drive(poc.actor, poc.behavior, poc.location, poc.evidence)
    first_step = poc.steps[0]
    anchor_entity = _field_to_entity_type(first_step.target_field)
    anchor_value = first_step.value if first_step.op.value in {"EQUALS", "STARTS_WITH"} else None
    anchor = SemanticVariable(
        id=f"v-{request_id}-anchor",
        entity_type=anchor_entity,
        value=anchor_value,
        value_origin="request",
        verification_status="UNVERIFIED",
        constraints=_able_constraints(poc),
    )

    target_var_id = f"v-{request_id}-target"
    relations: list[SemanticRelationGoal] = []
    qualifiers: list[Any] = []
    step_constraints: list[SemanticConstraint] = []

    for index, step in enumerate(list(poc.steps) + list(poc.fallbacks)):
        op = _op_to_constraint_op(step.op.value)
        constraint_value = step.value if op != "exists" else None
        step_constraints.append(SemanticConstraint(
            key=step.target_field,
            operator=op,
            value=constraint_value,
            retrieval_terms=[step.description],
        ))
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

    target_var = SemanticVariable(
        id=target_var_id,
        entity_type="event",
        value=None,
        value_origin="request",
        verification_status="UNVERIFIED",
        constraints=tuple(step_constraints),
    )
    variables = [anchor, target_var]

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
        assumptions=[
            f"PoC {poc.poc_id}: {poc.name}",
            *( [f"topic: {poc.topic}"] if poc.topic else [] ),
            *( [f"ABLE actor: {poc.actor}"] if poc.actor else ["ABLE actor: (unknown)"] ),
            *( [f"ABLE behavior: {poc.behavior}"] if poc.behavior else [] ),
            *( [f"ABLE location: {poc.location}"] if poc.location else [] ),
            *( [f"ABLE evidence: {poc.evidence}"] if poc.evidence else [] ),
            f"ABLE drive terms: {', '.join(drive.observables) or '(none)'}",
            f"ABLE host filter: {drive.host or '(none)'}",
            f"ABLE actor filter: {drive.actor or '(none)'}",
            f"ABLE source kinds: {', '.join(drive.source_kinds) or '(any)'}",
            *( [f"scope: {poc.scope}"] if poc.scope else [] ),
            *( [f"max_duration: {poc.max_duration}"] if poc.max_duration else [] ),
            *( [f"scope enforcement: {scope_note}"] if scope_note else [] ),
            *( [f"plan: {poc.plan}"] if poc.plan else [] ),
            *( [f"research: {r}" for r in poc.research_refs] ),
        ],
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
