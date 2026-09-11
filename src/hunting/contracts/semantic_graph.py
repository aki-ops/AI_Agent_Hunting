"""Provider-neutral semantic goals and executable logical plans."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


def _clean(value: str, name: str) -> str:
    value = str(value).strip()
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


@dataclass(frozen=True)
class SemanticConstraint:
    """Provider-neutral restriction attached to a graph variable.

    ``type``/``value`` is the shape emitted by the LLM, while ``key`` is the
    canonical internal name.  Keeping this typed prevents ``str(dict)`` from
    becoming part of query planning and makes malformed restrictions visible.
    """

    key: str
    value: Any = None
    operator: str = "equals"
    # Optional provider-neutral retrieval aliases proposed by the semantic
    # compiler.  These are data terms only (for example a file extension or
    # an observed label), never SPL/SQL/KQL.  Keeping them on the constraint
    # avoids putting a scenario-specific translation in a provider adapter.
    retrieval_terms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _clean(self.key, "SemanticConstraint.key").casefold())
        object.__setattr__(self, "operator", _clean(self.operator, "SemanticConstraint.operator").casefold())
        if self.operator not in {"equals", "contains", "exists"}:
            raise ValueError("SemanticConstraint.operator must be equals, contains or exists")
        terms = self.retrieval_terms or ()
        if isinstance(terms, str):
            terms = (terms,)
        object.__setattr__(self, "retrieval_terms", tuple(
            str(term).strip() for term in terms if str(term).strip()
        ))

    @classmethod
    def from_raw(cls, raw: Any, *, path: str = "constraint") -> "SemanticConstraint":
        if isinstance(raw, cls):
            return raw
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                raise ValueError(f"{path} must not be empty")
            if "=" in text:
                key, value = text.split("=", 1)
            elif ":" in text:
                key, value = text.split(":", 1)
            else:
                return cls(text)
            return cls(key.strip(), value.strip())
        if isinstance(raw, dict):
            key = raw.get("key", raw.get("type"))
            if key in (None, ""):
                raise ValueError(f"{path} object requires 'key' or 'type'")
            if "value" not in raw and str(raw.get("operator", "equals")).casefold() != "exists":
                raise ValueError(f"{path} object requires 'value'")
            retrieval_terms = raw.get("retrieval_terms", raw.get("search_terms", ()))
            if retrieval_terms is None:
                retrieval_terms = ()
            if isinstance(retrieval_terms, str):
                retrieval_terms = (retrieval_terms,)
            if not isinstance(retrieval_terms, (list, tuple)):
                raise ValueError(f"{path}.retrieval_terms must be an array of strings")
            return cls(
                str(key),
                raw.get("value"),
                str(raw.get("operator", "equals")),
                tuple(str(term) for term in retrieval_terms),
            )
        raise ValueError(f"{path} must be a string or object")

    def text(self) -> str:
        if self.operator == "exists":
            return f"{self.key}:exists"
        return f"{self.key}={self.value}"

    def to_dict(self) -> dict[str, Any]:
        payload = {"key": self.key, "operator": self.operator, "value": self.value}
        if self.retrieval_terms:
            payload["retrieval_terms"] = list(self.retrieval_terms)
        return payload


@dataclass(frozen=True)
class SemanticVariable:
    """A typed value in the user's goal graph, never a provider field."""
    id: str
    entity_type: str
    value: str | None = None
    constraints: tuple[SemanticConstraint, ...] = ()
    # Values proposed by the compiler are not provider-grounded entities.
    # ``request`` is retained as the compatibility default for programmatic
    # construction; parsed LLM payloads default to ``llm_proposal`` below.
    value_origin: str = "request"
    verification_status: str = "UNVERIFIED"

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _clean(self.id, "SemanticVariable.id"))
        object.__setattr__(self, "entity_type", _clean(self.entity_type, "SemanticVariable.entity_type").lower())
        if self.value is not None:
            object.__setattr__(self, "value", str(self.value).strip())
        object.__setattr__(self, "constraints", tuple(
            SemanticConstraint.from_raw(item, path=f"{self.id}.constraints[{index}]")
            for index, item in enumerate(self.constraints or ())
        ))
        origin = _clean(self.value_origin, f"{self.id}.value_origin").casefold()
        if origin not in {"request", "llm_proposal", "provider_observation"}:
            raise ValueError(f"{self.id}.value_origin is invalid")
        object.__setattr__(self, "value_origin", origin)
        status = _clean(self.verification_status, f"{self.id}.verification_status").upper()
        if status not in {"UNVERIFIED", "VERIFIED"}:
            raise ValueError(f"{self.id}.verification_status is invalid")
        object.__setattr__(self, "verification_status", status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "value": self.value,
            "constraints": [item.to_dict() for item in self.constraints],
            "value_origin": self.value_origin,
            "verification_status": self.verification_status,
        }


@dataclass(frozen=True)
class AnswerContract:
    """Expected output shape, acceptance condition, and citation requirements for an answer slot."""
    slot_name: str
    value_type: str
    target_variable_id: str
    required_qualifiers: tuple[str, ...] = ()
    min_citations: int = 1
    acceptable_aliases: tuple[str, ...] = ()
    acceptance_rule: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot_name", _clean(self.slot_name, "AnswerContract.slot_name"))
        object.__setattr__(self, "value_type", _clean(self.value_type, "AnswerContract.value_type").lower())
        object.__setattr__(self, "target_variable_id", _clean(self.target_variable_id, "AnswerContract.target_variable_id"))
        if isinstance(self.required_qualifiers, (list, set)):
            object.__setattr__(self, "required_qualifiers", tuple(str(x) for x in self.required_qualifiers))
        if isinstance(self.acceptable_aliases, (list, set)):
            object.__setattr__(self, "acceptable_aliases", tuple(str(x) for x in self.acceptable_aliases))
        if self.min_citations < 1:
            object.__setattr__(self, "min_citations", 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_name": self.slot_name,
            "value_type": self.value_type,
            "target_variable_id": self.target_variable_id,
            "required_qualifiers": list(self.required_qualifiers),
            "min_citations": self.min_citations,
            "acceptable_aliases": list(self.acceptable_aliases),
            "acceptance_rule": self.acceptance_rule,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnswerContract":
        slot_name = str(data.get("slot_name") or data.get("variable_id") or "answer").strip()
        value_type = str(data.get("value_type") or data.get("answer_type") or "value").strip()
        target_variable_id = str(data.get("target_variable_id") or data.get("variable_id") or slot_name).strip()
        return cls(
            slot_name=slot_name,
            value_type=value_type,
            target_variable_id=target_variable_id,
            required_qualifiers=tuple(str(x) for x in data.get("required_qualifiers", ())),
            min_citations=int(data.get("min_citations", 1)),
            acceptable_aliases=tuple(str(x) for x in data.get("acceptable_aliases", ())),
            acceptance_rule=str(data.get("acceptance_rule", "")).strip(),
            description=str(data.get("description", "")).strip(),
        )


@dataclass(frozen=True)
class SemanticRelationGoal:
    """A relation that must be established or refuted."""
    id: str
    subject: str
    relation: str
    object: str
    required: bool = True
    description: str = ""
    atomic_obligation: str = ""
    provenance_span: str = ""
    dependencies: tuple[str, ...] = ()
    dependency_operator: str = "AND"
    gate_condition: str | None = None

    def __post_init__(self) -> None:
        for name in ("id", "subject", "relation", "object"):
            object.__setattr__(self, name, _clean(getattr(self, name), f"SemanticRelationGoal.{name}"))
        object.__setattr__(self, "relation", self.relation.lower())
        if isinstance(self.dependencies, (list, set)):
            object.__setattr__(self, "dependencies", tuple(str(x) for x in self.dependencies))
        op = str(self.dependency_operator or "AND").upper()
        if op not in {"AND", "OR", "GATE"}:
            op = "AND"
        object.__setattr__(self, "dependency_operator", op)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject": self.subject,
            "relation": self.relation,
            "object": self.object,
            "required": self.required,
            "description": self.description,
            "atomic_obligation": self.atomic_obligation,
            "provenance_span": self.provenance_span,
            "dependencies": list(self.dependencies),
            "dependency_operator": self.dependency_operator,
            "gate_condition": self.gate_condition,
        }


@dataclass(frozen=True)
class SemanticQualifierGoal:
    """A qualifier on a relation/value; it is never silently inferred."""
    id: str
    target_goal_id: str
    qualifier: str
    expected_value: Any = None
    required: bool = True

    def __post_init__(self) -> None:
        for name in ("id", "target_goal_id", "qualifier"):
            object.__setattr__(self, name, _clean(getattr(self, name), f"SemanticQualifierGoal.{name}"))
        if isinstance(self.expected_value, str):
            object.__setattr__(self, "expected_value", self.expected_value.strip())

    def value_text(self) -> str:
        if isinstance(self.expected_value, (dict, list)):
            return json.dumps(self.expected_value, ensure_ascii=False, sort_keys=True)
        return str(self.expected_value)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "target_goal_id": self.target_goal_id, "qualifier": self.qualifier, "expected_value": self.expected_value, "required": self.required}


@dataclass(frozen=True)
class SemanticAnswerGoal:
    variable_id: str
    answer_type: str
    required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "variable_id", _clean(self.variable_id, "SemanticAnswerGoal.variable_id"))
        object.__setattr__(self, "answer_type", _clean(self.answer_type, "SemanticAnswerGoal.answer_type").lower())

    def to_dict(self) -> dict[str, Any]:
        return {"variable_id": self.variable_id, "answer_type": self.answer_type, "required": self.required}


@dataclass(frozen=True)
class ProofMethod:
    """One admissible proof route for a semantic relation.

    A goal may have several methods (OR).  A method can depend on several
    already-proven goals (AND).  Provider operations are references only;
    their contracts live in the capability catalog.
    """
    id: str
    goal_id: str
    prerequisite_goal_ids: tuple[str, ...] = ()
    operation_ids: tuple[str, ...] = ()
    expected_cost: int = 1
    description: str = ""

    def __post_init__(self) -> None:
        for name in ("id", "goal_id"):
            object.__setattr__(self, name, _clean(getattr(self, name), f"ProofMethod.{name}"))
        if isinstance(self.prerequisite_goal_ids, list):
            object.__setattr__(self, "prerequisite_goal_ids", tuple(self.prerequisite_goal_ids))
        if isinstance(self.operation_ids, list):
            object.__setattr__(self, "operation_ids", tuple(self.operation_ids))
        if self.expected_cost < 0:
            raise ValueError("ProofMethod.expected_cost must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal_id": self.goal_id,
            "prerequisite_goal_ids": list(self.prerequisite_goal_ids),
            "operation_ids": list(self.operation_ids),
            "expected_cost": self.expected_cost,
            "description": self.description,
        }


@dataclass
class SemanticGoalGraph:
    """Validated, provider-neutral representation of a hunt request."""
    id: str
    request_id: str
    objective: str
    variables: list[SemanticVariable] = field(default_factory=list)
    relations: list[SemanticRelationGoal] = field(default_factory=list)
    qualifiers: list[SemanticQualifierGoal] = field(default_factory=list)
    answers: list[SemanticAnswerGoal] = field(default_factory=list)
    answer_contracts: list[AnswerContract] = field(default_factory=list)
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    dependency_kinds: dict[str, str] = field(default_factory=dict)
    provenance_spans: dict[str, str] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    forbidden_inferences: list[str] = field(default_factory=list)
    clarification_triggers: list[str] = field(default_factory=list)
    raw_llm_proposal: dict[str, Any] | None = None
    validation_diagnostics: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.id = _clean(self.id, "SemanticGoalGraph.id")
        self.request_id = _clean(self.request_id, "SemanticGoalGraph.request_id")
        self.objective = _clean(self.objective, "SemanticGoalGraph.objective")
        variable_ids = {v.id for v in self.variables}
        if len(variable_ids) != len(self.variables):
            raise ValueError("SemanticGoalGraph contains duplicate variable ids")
        goal_ids = {g.id for g in self.relations}
        if len(goal_ids) != len(self.relations):
            raise ValueError("SemanticGoalGraph contains duplicate relation goal ids")
        for relation in self.relations:
            if relation.subject not in variable_ids or relation.object not in variable_ids:
                raise ValueError(f"Relation goal '{relation.id}' references an unknown variable")
            if relation.dependencies and relation.id not in self.dependencies:
                self.dependencies[relation.id] = list(relation.dependencies)
            if relation.dependency_operator and relation.id not in self.dependency_kinds:
                self.dependency_kinds[relation.id] = relation.dependency_operator
            if relation.provenance_span and relation.id not in self.provenance_spans:
                self.provenance_spans[relation.id] = relation.provenance_span
        for qualifier in self.qualifiers:
            if qualifier.target_goal_id not in goal_ids:
                raise ValueError(f"Qualifier '{qualifier.id}' references an unknown relation goal")
        for answer in self.answers:
            if answer.variable_id not in variable_ids:
                raise ValueError(f"Answer references an unknown variable '{answer.variable_id}'")
        for ac in self.answer_contracts:
            if ac.target_variable_id not in variable_ids:
                raise ValueError(f"AnswerContract references an unknown variable '{ac.target_variable_id}'")
        # Bidirectional reconciliation between answers and answer_contracts
        if not self.answer_contracts and self.answers:
            self.answer_contracts = [
                AnswerContract(
                    slot_name=a.variable_id,
                    value_type=a.answer_type,
                    target_variable_id=a.variable_id,
                )
                for a in self.answers
            ]
        elif not self.answers and self.answer_contracts:
            self.answers = [
                SemanticAnswerGoal(
                    variable_id=ac.target_variable_id,
                    answer_type=ac.value_type,
                )
                for ac in self.answer_contracts
            ]
        for goal_id, deps in self.dependencies.items():
            if goal_id not in goal_ids:
                raise ValueError(f"Dependency key '{goal_id}' is not a known relation goal")
            for dep in deps:
                if dep not in goal_ids:
                    raise ValueError(f"Goal '{goal_id}' depends on unknown relation goal '{dep}'")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "objective": self.objective,
            "variables": [v.to_dict() for v in self.variables],
            "relations": [r.to_dict() for r in self.relations],
            "qualifiers": [q.to_dict() for q in self.qualifiers],
            "answers": [a.to_dict() for a in self.answers],
            "answer_contracts": [ac.to_dict() for ac in self.answer_contracts],
            "dependencies": dict(self.dependencies),
            "dependency_kinds": dict(self.dependency_kinds),
            "provenance_spans": dict(self.provenance_spans),
            "assumptions": list(self.assumptions),
            "uncertainties": list(self.uncertainties),
            "forbidden_inferences": list(self.forbidden_inferences),
            "clarification_triggers": list(self.clarification_triggers),
            "validation_diagnostics": list(self.validation_diagnostics),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, request_id: str | None = None) -> "SemanticGoalGraph":
        graph_request_id = str(request_id or data.get("request_id", "")).strip()
        variables = [
            SemanticVariable(
                id=str(item.get("id", "")),
                entity_type=str(item.get("entity_type", "entity")),
                value=item.get("value"),
                constraints=tuple(item.get("constraints", [])),
                value_origin=str(item.get("value_origin", "llm_proposal")),
                verification_status=str(item.get("verification_status", "UNVERIFIED")),
            )
            for item in data.get("variables", []) if isinstance(item, dict)
        ]
        relations = [
            SemanticRelationGoal(
                id=str(item.get("id", "")),
                subject=str(item.get("subject", "")),
                relation=str(item.get("relation", "")),
                object=str(item.get("object", "")),
                required=bool(item.get("required", True)),
                description=str(item.get("description", "")),
                atomic_obligation=str(item.get("atomic_obligation", "")),
                provenance_span=str(item.get("provenance_span", "")),
                dependencies=tuple(item.get("dependencies", ())),
                dependency_operator=str(item.get("dependency_operator", "AND")),
                gate_condition=item.get("gate_condition"),
            )
            for item in data.get("relations", []) if isinstance(item, dict)
        ]
        qualifiers = [
            SemanticQualifierGoal(
                id=str(item.get("id", "")),
                target_goal_id=str(item.get("target_goal_id", "")),
                qualifier=str(item.get("qualifier", "")),
                expected_value=item.get("expected_value"),
                required=bool(item.get("required", True)),
            )
            for item in data.get("qualifiers", [])
            if isinstance(item, dict)
        ]
        answers = [
            SemanticAnswerGoal(
                variable_id=str(item.get("variable_id", "")),
                answer_type=str(item.get("answer_type", "value")),
                required=bool(item.get("required", True)),
            )
            for item in data.get("answers", []) if isinstance(item, dict)
        ]
        answer_contracts = [
            AnswerContract.from_dict(item)
            for item in data.get("answer_contracts", [])
            if isinstance(item, dict)
        ]
        raw_deps = data.get("dependencies", {})
        dependencies = {str(k): list(v) for k, v in raw_deps.items()} if isinstance(raw_deps, dict) else {}
        raw_dep_kinds = data.get("dependency_kinds", {})
        dependency_kinds = {str(k): str(v) for k, v in raw_dep_kinds.items()} if isinstance(raw_dep_kinds, dict) else {}
        raw_spans = data.get("provenance_spans", {})
        provenance_spans = {str(k): str(v) for k, v in raw_spans.items()} if isinstance(raw_spans, dict) else {}

        return cls(
            id=str(data.get("id", "")),
            request_id=graph_request_id,
            objective=str(data.get("objective", "")),
            variables=variables,
            relations=relations,
            qualifiers=qualifiers,
            answers=answers,
            answer_contracts=answer_contracts,
            dependencies=dependencies,
            dependency_kinds=dependency_kinds,
            provenance_spans=provenance_spans,
            assumptions=[str(value) for value in data.get("assumptions", [])],
            uncertainties=[str(value) for value in data.get("uncertainties", [])],
            forbidden_inferences=[str(value) for value in data.get("forbidden_inferences", [])],
            clarification_triggers=[str(value) for value in data.get("clarification_triggers", [])],
            raw_llm_proposal=data.get("raw_llm_proposal"),
            validation_diagnostics=[str(value) for value in data.get("validation_diagnostics", [])],
        )


@dataclass(frozen=True)
class PlanStep:
    """A provider-independent step selected from a capability."""
    id: str
    operation_id: str
    input_bindings: dict[str, str] = field(default_factory=dict)
    output_bindings: dict[str, str] = field(default_factory=dict)
    advances_goal_ids: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    expected_cost: int = 1
    constraints: tuple[str, ...] = ()
    constraint_retrieval_terms: tuple[tuple[str, str], ...] = ()
    # Actual SemanticGoalGraph relation advanced by this step.  Intermediate
    # prerequisite steps also carry the operation's declared relation.
    relation: str = "observed"
    constraint_metadata: tuple[dict[str, Any], ...] = ()
    # The planner may publish several provider operations that can prove the
    # same relation.  The selected operation remains deterministic, while the
    # alternatives remain auditable rather than becoming hidden adapter logic.
    alternative_operation_ids: tuple[str, ...] = ()
    # A downstream proof may only consume an incomplete upstream result when
    # the graph explicitly opts into that weaker epistemic contract.
    requires_complete_inputs: bool = True

    def __post_init__(self) -> None:
        for name in ("id", "operation_id"):
            object.__setattr__(self, name, _clean(getattr(self, name), f"PlanStep.{name}"))
        if self.expected_cost < 0:
            raise ValueError("PlanStep.expected_cost must be >= 0")
        if isinstance(self.advances_goal_ids, list):
            object.__setattr__(self, "advances_goal_ids", tuple(self.advances_goal_ids))
        if isinstance(self.depends_on, list):
            object.__setattr__(self, "depends_on", tuple(self.depends_on))
        if isinstance(self.constraints, list):
            object.__setattr__(self, "constraints", tuple(self.constraints))
        object.__setattr__(self, "constraints", tuple(
            item.text() if isinstance(item, SemanticConstraint)
            else SemanticConstraint.from_raw(item, path=f"{self.id}.constraints[{index}]").text()
            for index, item in enumerate(self.constraints or ())
        ))
        raw_terms = self.constraint_retrieval_terms or ()
        object.__setattr__(self, "constraint_retrieval_terms", tuple(
            (str(item[0]).strip().casefold(), str(item[1]).strip())
            for item in raw_terms
            if isinstance(item, (list, tuple)) and len(item) == 2
            and str(item[0]).strip() and str(item[1]).strip()
        ))
        object.__setattr__(self, "relation", _clean(self.relation, f"{self.id}.relation").casefold())
        metadata = tuple(dict(item) for item in (self.constraint_metadata or ()))
        metadata_keys = {str(item.get("key", "")).strip().casefold() for item in metadata}
        if any(not key for key in metadata_keys):
            raise ValueError("PlanStep.constraint_metadata requires non-empty keys")
        object.__setattr__(self, "constraint_metadata", metadata)
        if isinstance(self.alternative_operation_ids, list):
            object.__setattr__(self, "alternative_operation_ids", tuple(self.alternative_operation_ids))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "operation_id": self.operation_id, "input_bindings": dict(self.input_bindings), "output_bindings": dict(self.output_bindings), "advances_goal_ids": list(self.advances_goal_ids), "depends_on": list(self.depends_on), "expected_cost": self.expected_cost, "constraints": list(self.constraints), "constraint_retrieval_terms": [list(item) for item in self.constraint_retrieval_terms], "relation": self.relation, "constraint_metadata": [dict(item) for item in self.constraint_metadata], "alternative_operation_ids": list(self.alternative_operation_ids), "requires_complete_inputs": self.requires_complete_inputs}


@dataclass
class LogicalPlan:
    """A validated multi-step plan before native-provider compilation."""
    id: str
    goal_graph_id: str
    provider_id: str
    steps: list[PlanStep] = field(default_factory=list)
    unresolved_goal_ids: list[str] = field(default_factory=list)
    proof_methods: list[ProofMethod] = field(default_factory=list)
    selected_method_ids: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.id = _clean(self.id, "LogicalPlan.id")
        self.goal_graph_id = _clean(self.goal_graph_id, "LogicalPlan.goal_graph_id")
        self.provider_id = _clean(self.provider_id, "LogicalPlan.provider_id")
        step_ids = {s.id for s in self.steps}
        if len(step_ids) != len(self.steps):
            raise ValueError("LogicalPlan contains duplicate step ids")
        for step in self.steps:
            unknown = set(step.depends_on) - step_ids
            if unknown:
                raise ValueError(f"PlanStep '{step.id}' depends on unknown steps: {sorted(unknown)}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal_graph_id": self.goal_graph_id,
            "provider_id": self.provider_id,
            "steps": [s.to_dict() for s in self.steps],
            "unresolved_goal_ids": list(self.unresolved_goal_ids),
            "proof_methods": [method.to_dict() for method in self.proof_methods],
            "selected_method_ids": dict(self.selected_method_ids),
        }


def goal_graph_from_claim_graph(claim_graph: Any) -> SemanticGoalGraph:
    """Mechanically expose a legacy ClaimGraph as generic semantic goals."""
    variables: dict[str, SemanticVariable] = {}
    relations: list[SemanticRelationGoal] = []

    def variable_id(raw: Any, prefix: str) -> str:
        text = str(raw or "").strip()
        candidate = "".join(char if char.isalnum() else "_" for char in text).strip("_").lower()
        return candidate or prefix

    for claim in getattr(claim_graph, "claims", ()):
        subject_id = variable_id(getattr(claim, "subject", ""), "subject")
        variables.setdefault(subject_id, SemanticVariable(subject_id, "entity", getattr(claim, "subject", None)))
        object_value = getattr(claim, "object_or_value", None)
        object_id = variable_id(object_value, f"object_{len(relations) + 1}")
        object_type = str(getattr(claim, "value_type", None) or "entity").strip().lower()
        variables.setdefault(object_id, SemanticVariable(object_id, object_type, object_value))
        relations.append(SemanticRelationGoal(
            id=str(getattr(claim, "id", f"goal-{len(relations) + 1}")),
            subject=subject_id,
            relation=str(getattr(claim, "predicate", "observed")).strip().lower() or "observed",
            object=object_id,
            required=not bool(getattr(claim, "optional", False)),
            description=str(getattr(claim, "reason", "") or ""),
        ))

    return SemanticGoalGraph(
        id=f"semantic-{getattr(claim_graph, 'id', 'graph')}",
        request_id=str(getattr(claim_graph, "request_id", "request")),
        objective=str(getattr(claim_graph, "objective", "hunt")),
        variables=list(variables.values()),
        relations=relations,
        uncertainties=["Bridge generated from legacy ClaimGraph; semantic compiler migration pending"],
    )


__all__ = ["AnswerContract", "SemanticConstraint", "SemanticVariable", "SemanticRelationGoal", "SemanticQualifierGoal", "SemanticAnswerGoal", "ProofMethod", "SemanticGoalGraph", "PlanStep", "LogicalPlan", "goal_graph_from_claim_graph"]
