"""Provider-neutral semantic goals and executable logical plans."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
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


class ClarificationPredicateKind(str, Enum):
    """Reviewed deterministic predicates that may request clarification."""

    CONFLICTING_EQUALS = "CONFLICTING_EQUALS"


class ClarificationPredicateOperator(str, Enum):
    """Allowlisted operators for clarification predicates."""

    HAS_CONFLICT = "HAS_CONFLICT"


class ClarificationEvaluationResult(str, Enum):
    """Four-valued result of deterministic clarification evaluation."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass(frozen=True)
class ClarificationPredicate:
    """Typed, versioned condition proposed for deterministic evaluation."""

    id: str
    kind: ClarificationPredicateKind | str
    operator: ClarificationPredicateOperator | str
    variable_id: str | None = None
    constraint_key: str | None = None
    expected_cardinality: str | None = None
    quantifier: str | None = None
    operands: tuple[Any, ...] = ()
    provenance_span: str = ""
    schema_version: str = "1.0"
    rule_version: str = "1.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _clean(self.id, "ClarificationPredicate.id"))
        try:
            kind = (
                self.kind
                if isinstance(self.kind, ClarificationPredicateKind)
                else ClarificationPredicateKind(str(self.kind).strip().upper())
            )
        except ValueError:
            kind = str(self.kind or "").strip().upper()
        try:
            operator = (
                self.operator
                if isinstance(self.operator, ClarificationPredicateOperator)
                else ClarificationPredicateOperator(str(self.operator).strip().upper())
            )
        except ValueError:
            operator = str(self.operator or "").strip().upper()
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "operator", operator)
        if self.variable_id is not None:
            object.__setattr__(self, "variable_id", str(self.variable_id).strip() or None)
        if self.constraint_key is not None:
            key = str(self.constraint_key).strip().casefold()
            object.__setattr__(self, "constraint_key", key or None)
        operands = self.operands or ()
        if not isinstance(operands, tuple):
            operands = tuple(operands) if isinstance(operands, (list, set)) else (operands,)
        object.__setattr__(self, "operands", operands)
        object.__setattr__(self, "schema_version", _clean(self.schema_version, "ClarificationPredicate.schema_version"))
        object.__setattr__(self, "rule_version", _clean(self.rule_version, "ClarificationPredicate.rule_version"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClarificationPredicate":
        return cls(
            id=str(data.get("id", "")),
            kind=str(data.get("kind", "")),
            operator=str(data.get("operator", "")),
            variable_id=data.get("variable_id"),
            constraint_key=data.get("constraint_key"),
            expected_cardinality=data.get("expected_cardinality"),
            quantifier=data.get("quantifier"),
            operands=tuple(data.get("operands", ()) or ()),
            provenance_span=str(data.get("provenance_span", "")),
            schema_version=str(data.get("schema_version", "1.0")),
            rule_version=str(data.get("rule_version", "1.0")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value if isinstance(self.kind, Enum) else str(self.kind),
            "operator": self.operator.value if isinstance(self.operator, Enum) else str(self.operator),
            "variable_id": self.variable_id,
            "constraint_key": self.constraint_key,
            "expected_cardinality": self.expected_cardinality,
            "quantifier": self.quantifier,
            "operands": list(self.operands),
            "provenance_span": self.provenance_span,
            "schema_version": self.schema_version,
            "rule_version": self.rule_version,
        }


@dataclass(frozen=True)
class ClarificationEvaluation:
    """Auditable result produced by a deterministic clarification evaluator."""

    predicate_id: str
    result: ClarificationEvaluationResult | str
    deterministic_inputs: dict[str, Any] = field(default_factory=dict)
    reason_codes: tuple[str, ...] = ()
    state_version: str = "G0"
    evaluated_at_step_id: str = "SEMANTIC_ACCEPTANCE_STAGE_6"
    schema_version: str = "1.0"
    rule_version: str = "1.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "predicate_id", _clean(self.predicate_id, "ClarificationEvaluation.predicate_id"))
        result = (
            self.result
            if isinstance(self.result, ClarificationEvaluationResult)
            else ClarificationEvaluationResult(str(self.result).strip().upper())
        )
        object.__setattr__(self, "result", result)
        object.__setattr__(self, "deterministic_inputs", dict(self.deterministic_inputs or {}))
        object.__setattr__(self, "reason_codes", tuple(str(code) for code in (self.reason_codes or ())))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClarificationEvaluation":
        return cls(
            predicate_id=str(data.get("predicate_id", "")),
            result=str(data.get("result", "INVALID")),
            deterministic_inputs=dict(data.get("deterministic_inputs", {}) or {}),
            reason_codes=tuple(data.get("reason_codes", ()) or ()),
            state_version=str(data.get("state_version", "G0")),
            evaluated_at_step_id=str(data.get("evaluated_at_step_id", "SEMANTIC_ACCEPTANCE_STAGE_6")),
            schema_version=str(data.get("schema_version", "1.0")),
            rule_version=str(data.get("rule_version", "1.0")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicate_id": self.predicate_id,
            "result": self.result.value,
            "deterministic_inputs": dict(self.deterministic_inputs),
            "reason_codes": list(self.reason_codes),
            "state_version": self.state_version,
            "evaluated_at_step_id": self.evaluated_at_step_id,
            "schema_version": self.schema_version,
            "rule_version": self.rule_version,
        }


def evaluate_clarification_predicate(
    predicate: ClarificationPredicate,
    variables: list["SemanticVariable"],
    *,
    state_version: str = "G0",
    evaluated_at_step_id: str = "SEMANTIC_ACCEPTANCE_STAGE_6",
) -> ClarificationEvaluation:
    """Evaluate one reviewed clarification predicate without model judgment."""
    base = {
        "predicate_id": predicate.id,
        "state_version": state_version,
        "evaluated_at_step_id": evaluated_at_step_id,
        "schema_version": predicate.schema_version,
        "rule_version": predicate.rule_version,
    }
    if (
        predicate.kind != ClarificationPredicateKind.CONFLICTING_EQUALS
        or predicate.operator != ClarificationPredicateOperator.HAS_CONFLICT
    ):
        return ClarificationEvaluation(
            result=ClarificationEvaluationResult.INVALID,
            deterministic_inputs={
                "kind": predicate.kind.value if isinstance(predicate.kind, Enum) else str(predicate.kind),
                "operator": predicate.operator.value if isinstance(predicate.operator, Enum) else str(predicate.operator),
            },
            reason_codes=("UNSUPPORTED_PREDICATE_KIND_OR_OPERATOR",),
            **base,
        )
    if not predicate.variable_id or not predicate.constraint_key:
        return ClarificationEvaluation(
            result=ClarificationEvaluationResult.INVALID,
            deterministic_inputs={
                "variable_id": predicate.variable_id,
                "constraint_key": predicate.constraint_key,
            },
            reason_codes=("MISSING_REQUIRED_REFERENCE",),
            **base,
        )

    variable = next((item for item in variables if item.id == predicate.variable_id), None)
    if variable is None:
        return ClarificationEvaluation(
            result=ClarificationEvaluationResult.INVALID,
            deterministic_inputs={
                "variable_id": predicate.variable_id,
                "constraint_key": predicate.constraint_key,
            },
            reason_codes=("UNKNOWN_VARIABLE_REFERENCE",),
            **base,
        )

    values = sorted({
        str(constraint.value).strip().casefold()
        for constraint in variable.constraints
        if constraint.operator == "equals"
        and constraint.key == predicate.constraint_key
        and constraint.value is not None
    })
    has_conflict = len(values) > 1
    return ClarificationEvaluation(
        result=(
            ClarificationEvaluationResult.TRUE
            if has_conflict
            else ClarificationEvaluationResult.FALSE
        ),
        deterministic_inputs={
            "variable_id": variable.id,
            "constraint_key": predicate.constraint_key,
            "normalized_values": values,
            "distinct_value_count": len(values),
        },
        reason_codes=(
            "CONFLICTING_EQUALITY_VALUES"
            if has_conflict
            else "NO_CONFLICTING_EQUALITY_VALUES",
        ),
        **base,
    )


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
        if origin not in {"request", "llm_proposal", "provider_observation", "user_selection"}:
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
    goal_class: str = "artifact"

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
        goal_class = str(self.goal_class or "artifact").lower()
        if goal_class not in {"artifact", "behavior"}:
            goal_class = "artifact"
        object.__setattr__(self, "goal_class", goal_class)

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
            "goal_class": self.goal_class,
        }


@dataclass(frozen=True)
class SemanticQualifierGoal:
    """A qualifier on a relation/value; it is never silently inferred.

    ``retrieval_terms`` are provider-neutral data aliases proposed by the
    semantic compiler.  They are deliberately separate from ``expected_value``:
    the latter is the claim that must be proved, while the former only helps a
    provider locate candidate rows.  A provider must never invent these terms.
    """
    id: str
    target_goal_id: str
    qualifier: str
    expected_value: Any = None
    required: bool = True
    retrieval_terms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("id", "target_goal_id", "qualifier"):
            object.__setattr__(self, name, _clean(getattr(self, name), f"SemanticQualifierGoal.{name}"))
        if isinstance(self.expected_value, str):
            object.__setattr__(self, "expected_value", self.expected_value.strip())
        terms = self.retrieval_terms or ()
        if isinstance(terms, str):
            terms = (terms,)
        object.__setattr__(self, "retrieval_terms", tuple(
            str(term).strip() for term in terms if str(term).strip()
        ))

    def value_text(self) -> str:
        if isinstance(self.expected_value, (dict, list)):
            return json.dumps(self.expected_value, ensure_ascii=False, sort_keys=True)
        return str(self.expected_value)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "target_goal_id": self.target_goal_id,
            "qualifier": self.qualifier,
            "expected_value": self.expected_value,
            "required": self.required,
        }
        if self.retrieval_terms:
            payload["retrieval_terms"] = list(self.retrieval_terms)
        return payload


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
    outcome_contract: Any | None = None
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    dependency_kinds: dict[str, str] = field(default_factory=dict)
    provenance_spans: dict[str, str] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    forbidden_inferences: list[str] = field(default_factory=list)
    # Legacy prose is retained for audit/compatibility only. It is never
    # evaluated and can never authorize a clarification stop.
    clarification_triggers: list[str] = field(default_factory=list)
    clarification_predicates: list[ClarificationPredicate] = field(default_factory=list)
    clarification_evaluations: list[ClarificationEvaluation] = field(default_factory=list)
    raw_llm_proposal: dict[str, Any] | None = None
    validation_diagnostics: list[str] = field(default_factory=list)
    graph_revision: str = "G0"
    revision_history: tuple[dict[str, Any], ...] = ()

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
        if self.outcome_contract is None and (self.answers or self.answer_contracts):
            from hunting.contracts.outcome import outcome_from_legacy_answers
            self.outcome_contract = outcome_from_legacy_answers(self.answers, self.answer_contracts)
        for goal_id, deps in self.dependencies.items():
            if goal_id not in goal_ids:
                raise ValueError(f"Dependency key '{goal_id}' is not a known relation goal")
            for dep in deps:
                if dep not in goal_ids:
                    raise ValueError(f"Goal '{goal_id}' depends on unknown relation goal '{dep}'")

        self.clarification_triggers = [
            str(value).strip()
            for value in (self.clarification_triggers or [])
            if str(value).strip()
        ]
        self.clarification_predicates = [
            item
            if isinstance(item, ClarificationPredicate)
            else ClarificationPredicate.from_dict(item)
            for item in (self.clarification_predicates or [])
            if isinstance(item, (ClarificationPredicate, dict))
        ]
        predicate_ids = [item.id for item in self.clarification_predicates]
        if len(set(predicate_ids)) != len(predicate_ids):
            raise ValueError("SemanticGoalGraph contains duplicate clarification predicate ids")

        provided_evaluations = [
            item
            if isinstance(item, ClarificationEvaluation)
            else ClarificationEvaluation.from_dict(item)
            for item in (self.clarification_evaluations or [])
            if isinstance(item, (ClarificationEvaluation, dict))
        ]
        provided_by_id = {item.predicate_id: item for item in provided_evaluations}
        if len(provided_by_id) != len(provided_evaluations):
            raise ValueError("SemanticGoalGraph contains duplicate clarification evaluation ids")
        unknown_evaluation_ids = set(provided_by_id) - set(predicate_ids)
        if unknown_evaluation_ids:
            raise ValueError(
                "Clarification evaluations reference unknown predicate ids: "
                f"{sorted(unknown_evaluation_ids)}"
            )

        self.clarification_evaluations = [
            evaluate_clarification_predicate(
                predicate,
                self.variables,
                state_version=self.graph_revision,
            )
            for predicate in self.clarification_predicates
        ]

    @property
    def needs_clarification(self) -> bool:
        """Only a deterministic TRUE evaluation may authorize clarification."""
        return any(
            evaluation.result == ClarificationEvaluationResult.TRUE
            for evaluation in self.clarification_evaluations
        )

    def propose_expansion(
        self,
        intermediate_variables: list[SemanticVariable],
        intermediate_relations: list[SemanticRelationGoal],
        reason: str = "",
    ) -> "SemanticGoalGraph":
        """Propose an audited graph expansion revision (e.g. G0 -> G1)."""
        rev_str = self.graph_revision.lstrip("G")
        new_rev_num = int(rev_str) + 1 if rev_str.isdigit() else 1
        new_rev = f"G{new_rev_num}"
        history_entry = {
            "from_revision": self.graph_revision,
            "to_revision": new_rev,
            "reason": reason,
            "added_variables": [v.id for v in intermediate_variables],
            "added_relations": [r.id for r in intermediate_relations],
        }
        return SemanticGoalGraph(
            id=self.id,
            request_id=self.request_id,
            objective=self.objective,
            variables=list(self.variables) + list(intermediate_variables),
            relations=list(self.relations) + list(intermediate_relations),
            qualifiers=list(self.qualifiers),
            answers=list(self.answers),
            answer_contracts=list(self.answer_contracts),
            outcome_contract=self.outcome_contract,
            dependencies=dict(self.dependencies),
            dependency_kinds=dict(self.dependency_kinds),
            provenance_spans=dict(self.provenance_spans),
            assumptions=list(self.assumptions),
            uncertainties=list(self.uncertainties),
            forbidden_inferences=list(self.forbidden_inferences),
            clarification_triggers=list(self.clarification_triggers),
            clarification_predicates=list(self.clarification_predicates),
            clarification_evaluations=list(self.clarification_evaluations),
            raw_llm_proposal=self.raw_llm_proposal,
            validation_diagnostics=list(self.validation_diagnostics),
            graph_revision=new_rev,
            revision_history=tuple(list(self.revision_history) + [history_entry]),
        )

    def to_dict(self) -> dict[str, Any]:
        res = {
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
            "clarification_predicates": [
                predicate.to_dict() for predicate in self.clarification_predicates
            ],
            "clarification_evaluations": [
                evaluation.to_dict() for evaluation in self.clarification_evaluations
            ],
            "validation_diagnostics": list(self.validation_diagnostics),
            "graph_revision": self.graph_revision,
            "revision_history": [dict(item) for item in self.revision_history],
        }
        if self.outcome_contract is not None:
            from hunting.contracts.outcome import outcome_to_dict
            res["outcome_contract"] = outcome_to_dict(self.outcome_contract)
        return res

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
                goal_class=str(item.get("goal_class", "artifact")),
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
                retrieval_terms=tuple(item.get("retrieval_terms", item.get("search_terms", ())) or ()),
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
        outcome_contract = None
        if "outcome_contract" in data and data["outcome_contract"] is not None:
            from hunting.contracts.outcome import outcome_from_dict
            outcome_contract = outcome_from_dict(data["outcome_contract"])
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
            outcome_contract=outcome_contract,
            dependencies=dependencies,
            dependency_kinds=dependency_kinds,
            provenance_spans=provenance_spans,
            assumptions=[str(value) for value in data.get("assumptions", [])],
            uncertainties=[str(value) for value in data.get("uncertainties", [])],
            forbidden_inferences=[str(value) for value in data.get("forbidden_inferences", [])],
            clarification_triggers=[str(value) for value in data.get("clarification_triggers", [])],
            clarification_predicates=[
                ClarificationPredicate.from_dict(item)
                for item in data.get("clarification_predicates", [])
                if isinstance(item, dict)
            ],
            clarification_evaluations=[
                ClarificationEvaluation.from_dict(item)
                for item in data.get("clarification_evaluations", [])
                if isinstance(item, dict)
            ],
            raw_llm_proposal=data.get("raw_llm_proposal"),
            validation_diagnostics=[str(value) for value in data.get("validation_diagnostics", [])],
            graph_revision=str(data.get("graph_revision", "G0")),
            revision_history=tuple(dict(x) for x in data.get("revision_history", [])),
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
    dependency_operator: str = "AND"
    gate_condition: str | None = None
    # Execution authority is carried by the admitted route.  An unannotated
    # hand-authored step is discovery-only; PROVE must be explicit and backed
    # by an admitted proof contract.
    mode: str = "EXPLORE"

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
        op = str(getattr(self, "dependency_operator", "AND") or "AND").upper()
        if op not in {"AND", "OR", "GATE"}:
            op = "AND"
        object.__setattr__(self, "dependency_operator", op)
        mode = str(getattr(self, "mode", "EXPLORE") or "EXPLORE").upper()
        if mode not in {"EXPLORE", "DISCRIMINATE", "PROVE", "SIZING"}:
            raise ValueError("PlanStep.mode must be EXPLORE, DISCRIMINATE, PROVE or SIZING")
        object.__setattr__(self, "mode", mode)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "operation_id": self.operation_id,
            "input_bindings": dict(self.input_bindings),
            "output_bindings": dict(self.output_bindings),
            "advances_goal_ids": list(self.advances_goal_ids),
            "depends_on": list(self.depends_on),
            "expected_cost": self.expected_cost,
            "constraints": list(self.constraints),
            "constraint_retrieval_terms": [list(item) for item in self.constraint_retrieval_terms],
            "relation": self.relation,
            "constraint_metadata": [dict(item) for item in self.constraint_metadata],
            "alternative_operation_ids": list(self.alternative_operation_ids),
            "requires_complete_inputs": self.requires_complete_inputs,
            "dependency_operator": self.dependency_operator,
            "gate_condition": self.gate_condition,
            "mode": self.mode,
        }


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
    graph_revision: str = "G0"
    unresolved_reasons: dict[str, str] = field(default_factory=dict)

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
            "graph_revision": self.graph_revision,
            "unresolved_reasons": dict(self.unresolved_reasons),
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


def accept_graph_revision(
    current: SemanticGoalGraph,
    proposed: SemanticGoalGraph,
) -> SemanticGoalGraph:
    """Accept a proposed graph only when revision history preserves obligations.

    Adjacent exploration may open routes. It cannot drop or demote accepted
    required relations, change graph identity, or skip the revision record.
    """
    if proposed.id != current.id or proposed.request_id != current.request_id:
        raise ValueError("graph revision must keep the accepted graph identity")
    if proposed.graph_revision == current.graph_revision:
        raise ValueError("graph revision must increment graph_revision")
    if not proposed.revision_history:
        raise ValueError("graph revision must record revision_history")
    current_required = {
        rel.id: rel for rel in current.relations if getattr(rel, "required", False)
    }
    proposed_by_id = {rel.id: rel for rel in proposed.relations}
    for rel_id, rel in current_required.items():
        match = proposed_by_id.get(rel_id)
        if match is None:
            raise ValueError(f"graph revision dropped accepted obligation '{rel_id}'")
        if not getattr(match, "required", False):
            raise ValueError(f"graph revision demoted accepted obligation '{rel_id}'")
        if str(match.relation) != str(rel.relation):
            raise ValueError(f"graph revision mutated obligation relation '{rel_id}'")
    return proposed


__all__ = [
    "AnswerContract",
    "ClarificationEvaluation",
    "ClarificationEvaluationResult",
    "ClarificationPredicate",
    "ClarificationPredicateKind",
    "ClarificationPredicateOperator",
    "evaluate_clarification_predicate",
    "SemanticConstraint",
    "SemanticVariable",
    "SemanticRelationGoal",
    "SemanticQualifierGoal",
    "SemanticAnswerGoal",
    "ProofMethod",
    "SemanticGoalGraph",
    "PlanStep",
    "LogicalPlan",
    "goal_graph_from_claim_graph",
    "accept_graph_revision",
]
