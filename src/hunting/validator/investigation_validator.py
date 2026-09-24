"""Investigation Validator.

Deterministic Validator (Component 2 of General Cyclical Investigation Loop).
Validates schema, entity roles, provider isolation, and enforces mandatory unknowns
for unproven entity prerequisites before allowing hunt progression.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

from hunting.contracts.investigation_model import (
    InvestigationModel,
    InvestigationUnknown,
    NodeStatus,
    NodeType,
    RelationType,
)
from hunting.contracts.ontology import (
    CANONICAL_RELATION_VOCABULARY,
    UNCONSTRAINED_RELATION_ROLES,
    get_canonical_relation,
    types_are_compatible,
)
from hunting.contracts.semantic_graph import (
    ClarificationEvaluationResult,
    ClarificationPredicate,
    ClarificationPredicateKind,
    ClarificationPredicateOperator,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
    evaluate_clarification_predicate,
)

DEVICE_QUALIFIER_TERMS = {
    "macbook", "macbook pro", "macbook air", "mac", "air13",
    "laptop", "desktop", "workstation", "pc", "computer",
    "iphone", "android", "phone", "mobile", "tablet", "device",
}

DEVICE_QUALIFIER_REGEX = re.compile(
    r"\b(macbook(\s*(pro|air))?|air13|laptop|desktop|workstation|pc|computer|iphone|android|phone|mobile|tablet|device)\b",
    re.IGNORECASE,
)

NATIVE_QUERY_PATTERNS = [
    re.compile(r"\bindex\s*=", re.IGNORECASE),
    re.compile(r"\bsourcetype\s*=", re.IGNORECASE),
    re.compile(r"\|\s*(table|stats|eval|rex|where|rename|dedup|head)\b", re.IGNORECASE),
    re.compile(r"\b(search|where|table|rex)\b\s*\(", re.IGNORECASE),
]


@dataclass
class ValidationResult:
    """Outcome of deterministic investigation model validation."""
    valid: bool
    investigation_state: str  # "READY_FOR_DISCOVERY" | "READY_FOR_TEST" | "INVALID"
    mandatory_unknowns: list[InvestigationUnknown] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)


class InvestigationValidator:
    """Validates InvestigationModel output from LLM Semantic Investigator."""

    def validate_investigation_model(self, model: InvestigationModel) -> ValidationResult:
        """Deterministically validate investigation model and establish prerequisites."""
        violations: list[str] = []

        # 1. Provider Isolation: No SPL, index, or vendor leaks
        leaks = model.validate_provider_isolation()
        if leaks:
            violations.extend(leaks)

        # 2. Basic Structural Validation
        if not model.question.strip():
            violations.append("InvestigationModel.question must not be empty.")

        # 3. Entity Roles and Mandatory Unknowns
        mandatory_unknowns: list[InvestigationUnknown] = list(model.unknowns)

        # Ensure person subjects require endpoint resolution before testing
        for subj in model.subjects:
            subj_type = subj.type.lower()
            if subj_type in ("person", "user"):
                # Check if graph has a proven, KNOWN endpoint edge for this person
                has_proven_endpoint = False
                for edge in model.graph.get_edges_from(subj.id):
                    if (
                        edge.relation_type == RelationType.LOGGED_ON_TO.value
                        and edge.status == NodeStatus.KNOWN
                    ):
                        target_node = model.graph.get_node(edge.target_id)
                        if target_node and target_node.type in (NodeType.ENDPOINT.value, NodeType.HOST.value):
                            has_proven_endpoint = True
                            break

                if not has_proven_endpoint:
                    # Enforce mandatory unknown for person's endpoint
                    existing_unk = next(
                        (
                            u for u in mandatory_unknowns
                            if u.entity_type in ("endpoint", "host")
                            and "endpoint" in u.relation_to_resolve.lower()
                        ),
                        None,
                    )
                    if existing_unk is None:
                        unk = InvestigationUnknown(
                            id=f"unk-{subj.id}-endpoint",
                            entity_type="endpoint",
                            description=f"Identify workstation endpoint or client IP used by {subj.value}",
                            relation_to_resolve=f"person({subj.value}) -> logged_on_to -> endpoint",
                            mandatory=True,
                            status="UNRESOLVED",
                        )
                        mandatory_unknowns.append(unk)
                    else:
                        existing_unk.mandatory = True
                        existing_unk.status = "UNRESOLVED"

        if violations:
            return ValidationResult(
                valid=False,
                investigation_state="INVALID",
                mandatory_unknowns=mandatory_unknowns,
                violations=violations,
            )

        # 5. Determine Investigation State
        unresolved_mandatory = [u for u in mandatory_unknowns if u.mandatory and u.status == "UNRESOLVED"]
        if unresolved_mandatory:
            investigation_state = "READY_FOR_DISCOVERY"
        else:
            investigation_state = "READY_FOR_TEST"

        return ValidationResult(
            valid=True,
            investigation_state=investigation_state,
            mandatory_unknowns=mandatory_unknowns,
            violations=[],
        )



VALIDATION_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"mark\s+(as\s+)?(benign|malicious|clean)", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"override\s+state", re.IGNORECASE),
    re.compile(r"bypass\s+(controls|checks)", re.IGNORECASE),
]


@dataclass
class GoalGraphValidationResult:
    """Outcome of deterministic SemanticGoalGraph validation across 6 stages."""
    valid: bool
    validated_graph: SemanticGoalGraph
    diagnostics: list[str] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    pruned_goal_ids: list[str] = field(default_factory=list)
    needs_clarification: bool = False
    clarification_questions: list[str] = field(default_factory=list)
    stage_results: dict[str, bool] = field(default_factory=dict)


class SemanticGoalGraphValidator:
    """Deterministic 6-stage Semantic Acceptance Gate for SemanticGoalGraph proposals.

    Enforces Step C rules from 08 Master Plan:
    1. Schema, DAG & Reference Validation: acyclic dependencies, unique IDs, explicit gate_condition for GATE.
    2. Literal & Provenance Validation: entity preservation, no invented proper nouns, provenance verification, query isolation.
    3. Scope & Outcome Utility Validation: every goal must reduce or constrain an answer slot; prune story expansions.
    4. Relation Registry Status: canonical vocabulary relations; novel relations flagged as unproven / retrieval-only.
    5. Semantic-Risk Classification: device qualifiers demoted to typed constraints; prompt injection defense.
    6. Clarification Triggers: detect ambiguous semantics or explicit clarification requests.
    """

    def validate_goal_graph(
        self,
        graph: SemanticGoalGraph,
        request_content: str,
        request_entities: list[Any] | tuple[Any, ...] = (),
    ) -> GoalGraphValidationResult:
        diagnostics: list[str] = []
        rejections: list[str] = []
        pruned_goal_ids: list[str] = []
        clarification_questions: list[str] = []
        needs_clarification = False
        stage_results: dict[str, bool] = {}

        request_folded = request_content.casefold()
        explicit_entities: dict[str, set[str]] = {}
        for entity in request_entities or ():
            kind_value = getattr(getattr(entity, "kind", ""), "value", getattr(entity, "kind", ""))
            kind = str(kind_value).casefold()
            raw_value = (
                getattr(entity, "value", None)
                or getattr(entity, "name", None)
                or getattr(entity, "username", None)
                or getattr(entity, "address", None)
                or getattr(entity, "path", None)
            )
            if raw_value not in (None, ""):
                explicit_entities.setdefault(kind, set()).add(str(raw_value).casefold().strip())

        all_explicit_values = {val for vals in explicit_entities.values() for val in vals}

        # =========================================================================
        # Stage 1: Deterministic Schema, DAG, and Reference Validation
        # =========================================================================
        stage1_rejections: list[str] = []
        var_ids = {v.id for v in graph.variables}
        goal_ids = {r.id for r in graph.relations}

        # Check references
        for rel in graph.relations:
            if rel.subject not in var_ids:
                stage1_rejections.append(f"Goal '{rel.id}' references unknown subject variable '{rel.subject}'")
            if rel.object not in var_ids:
                stage1_rejections.append(f"Goal '{rel.id}' references unknown object variable '{rel.object}'")
        for q in graph.qualifiers:
            if q.target_goal_id not in goal_ids:
                stage1_rejections.append(f"Qualifier '{q.id}' references unknown target goal '{q.target_goal_id}'")

        # Check Acyclic Dependencies
        deps = dict(graph.dependencies)
        for rel in graph.relations:
            if rel.dependencies and rel.id not in deps:
                deps[rel.id] = list(rel.dependencies)

        visited: dict[str, int] = {}  # 0: visiting, 1: visited

        def has_cycle(node: str, path: list[str]) -> bool:
            visited[node] = 0
            for neighbor in deps.get(node, []):
                if visited.get(neighbor) == 0:
                    stage1_rejections.append(f"Cyclic dependency detected: {' -> '.join(path + [neighbor])}")
                    return True
                if neighbor not in visited:
                    if has_cycle(neighbor, path + [neighbor]):
                        return True
            visited[node] = 1
            return False

        for node in list(deps.keys()):
            if node not in visited:
                has_cycle(node, [node])

        # Check GATE condition
        for rel in graph.relations:
            op = graph.dependency_kinds.get(rel.id, rel.dependency_operator).upper()
            if op == "GATE" and not rel.gate_condition:
                stage1_rejections.append(f"Goal '{rel.id}' uses GATE dependency operator but lacks gate_condition.")

        rejections.extend(stage1_rejections)
        stage_results["schema_dag_references"] = len(stage1_rejections) == 0

        # =========================================================================
        # Stage 2: Literal and Provenance Validation
        # =========================================================================
        stage2_rejections: list[str] = []
        rewritten_variables: list[SemanticVariable] = []

        for var in graph.variables:
            current_var = var
            var_val = var.value.strip() if var.value else None
            val_lower = var_val.casefold() if var_val else ""

            # Check: Entity Mutation (e.g. Mallory -> Alice)
            if var.entity_type.casefold() in {"person", "user"} and var_val:
                if val_lower not in request_folded and val_lower not in all_explicit_values:
                    stage2_rejections.append(
                        f"Entity mutation rejected: proposed person '{var_val}' does not appear in request content."
                    )

            # Check: Invented proper noun marked as request origin
            if current_var.value_origin == "request" and var_val:
                if val_lower not in request_folded and val_lower not in all_explicit_values:
                    stage2_rejections.append(
                        f"Invented proper noun rejected: variable '{var.id}' value '{var_val}' is marked as request origin but does not appear in request."
                    )

            rewritten_variables.append(current_var)

        # Check for native query leaks
        for var in rewritten_variables:
            for constraint in var.constraints:
                for term in constraint.retrieval_terms:
                    for pat in NATIVE_QUERY_PATTERNS:
                        if pat.search(str(term)):
                            stage2_rejections.append(
                                f"Native query syntax leaked into constraint retrieval terms: '{term}'"
                            )
                for pat in NATIVE_QUERY_PATTERNS:
                    if pat.search(str(constraint.value or "")):
                        stage2_rejections.append(
                            f"Native query syntax leaked into constraint value: '{constraint.value}'"
                        )

        for ac in graph.answer_contracts:
            for pat in NATIVE_QUERY_PATTERNS:
                if pat.search(ac.acceptance_rule):
                    stage2_rejections.append(
                        f"Native query syntax leaked into AnswerContract acceptance rule: '{ac.acceptance_rule}'"
                    )

        # Check Provenance Spans
        for rel in graph.relations:
            span = rel.provenance_span or graph.provenance_spans.get(rel.id, "")
            if span:
                if span.casefold() not in request_folded:
                    diagnostics.append(f"Goal '{rel.id}' provenance span '{span}' does not match request content.")
            else:
                diagnostics.append(f"Goal '{rel.id}' missing explicit request provenance span.")

        rejections.extend(stage2_rejections)
        stage_results["literal_provenance"] = len(stage2_rejections) == 0

        # =========================================================================
        # Stage 3: Scope & Outcome Utility Validation (Story Expansion Pruning)
        # =========================================================================
        target_var_ids = {a.variable_id for a in graph.answers} | {
            ac.target_variable_id for ac in graph.answer_contracts
        }
        if not target_var_ids and rewritten_variables:
            target_var_ids = {rewritten_variables[-1].id}

        relevant_vars = set(target_var_ids)
        changed = True
        while changed:
            changed = False
            for rel in graph.relations:
                if rel.object in relevant_vars or rel.subject in relevant_vars:
                    if rel.subject not in relevant_vars:
                        relevant_vars.add(rel.subject)
                        changed = True
                    if rel.object not in relevant_vars:
                        relevant_vars.add(rel.object)
                        changed = True

        validated_relations: list[SemanticRelationGoal] = []
        for rel in graph.relations:
            if rel.subject in relevant_vars or rel.object in relevant_vars:
                validated_relations.append(rel)
            else:
                diagnostics.append(
                    f"Ungrounded story expansion pruned: goal '{rel.id}' ({rel.relation}) does not reduce any answer slot."
                )
                pruned_goal_ids.append(rel.id)

        # Retain at least one relation if all were pruned
        if not validated_relations and graph.relations:
            validated_relations = list(graph.relations)

        validated_qualifiers = [
            q for q in graph.qualifiers
            if q.target_goal_id in {r.id for r in validated_relations}
        ]
        stage_results["scope_outcome_utility"] = True

        # =========================================================================
        # Stage 4: Relation Registry Status Check
        # =========================================================================
        var_by_id = {variable.id: variable for variable in rewritten_variables}
        for rel in validated_relations:
            rel_norm = rel.relation.strip().casefold()
            if rel_norm not in CANONICAL_RELATION_VOCABULARY:
                diagnostics.append(
                    f"Novel relation '{rel.relation}' is not in approved canonical registry; "
                    f"can be explored with retrieval_only but cannot be proven without approved contract."
                )
                continue
            spec = get_canonical_relation(rel.relation)
            if spec is None:
                continue
            subject = var_by_id.get(rel.subject)
            obj = var_by_id.get(rel.object)
            subject_role = str(spec.subject_entity_role or "").strip().casefold()
            object_role = str(spec.object_value_role or "").strip().casefold()
            if (
                subject is not None
                and subject_role not in UNCONSTRAINED_RELATION_ROLES
                and not types_are_compatible(subject.entity_type, spec.subject_entity_role)
            ):
                rejections.append(
                    f"Goal '{rel.id}' relation '{rel.relation}' subject type "
                    f"'{subject.entity_type}' is incompatible with '{spec.subject_entity_role}'."
                )
            if (
                obj is not None
                and object_role not in UNCONSTRAINED_RELATION_ROLES
                and not types_are_compatible(obj.entity_type, spec.object_value_role)
            ):
                rejections.append(
                    f"Goal '{rel.id}' relation '{rel.relation}' object type "
                    f"'{obj.entity_type}' is incompatible with '{spec.object_value_role}'."
                )
        stage_results["relation_registry"] = True

        # =========================================================================
        # Stage 5: Semantic-Risk Classification
        # =========================================================================
        final_variables: list[SemanticVariable] = []
        for var in rewritten_variables:
            current_var = var
            var_val = var.value.strip() if var.value else None
            val_lower = var_val.casefold() if var_val else ""

            # Check: Device qualifier as hostname demotion
            if var.entity_type.casefold() in {"host", "endpoint", "computer"} and var_val:
                is_device_term = val_lower in DEVICE_QUALIFIER_TERMS or bool(
                    DEVICE_QUALIFIER_REGEX.search(val_lower)
                )
                if is_device_term:
                    diagnostics.append(
                        f"Device qualifier '{var_val}' cannot be used as hostname; "
                        f"demoting to constraint and unbinding host variable '{var.id}'."
                    )
                    existing_keys = {c.key for c in var.constraints}
                    new_constraints = list(var.constraints)
                    if "device_type" not in existing_keys:
                        new_constraints.append(
                            SemanticConstraint(key="device_type", value=var_val, operator="contains")
                        )
                    current_var = replace(
                        var,
                        value=None,
                        value_origin="llm_proposal",
                        constraints=tuple(new_constraints),
                    )
            final_variables.append(current_var)

        # Prompt injection check across all proposal texts
        for pat in VALIDATION_INJECTION_PATTERNS:
            for text_to_check in [graph.objective] + [r.description for r in graph.relations]:
                if pat.search(text_to_check):
                    rejections.append(f"Prompt injection pattern detected in graph text: '{text_to_check}'")
                    break
        stage_results["semantic_risk"] = True

        # =========================================================================
        # Stage 6: Typed Clarification Predicates
        # =========================================================================
        if graph.clarification_triggers:
            diagnostics.append(
                "Legacy clarification trigger prose retained as advisory uncertainty; "
                "prose is not an executable clarification predicate."
            )

        predicates = list(graph.clarification_predicates)
        predicate_ids = {predicate.id for predicate in predicates}

        # Materialize the existing deterministic conflicting-equals rule as a
        # typed predicate. This preserves programmatic graphs while ensuring the
        # evaluation record, rather than an ad-hoc Boolean, owns authority.
        for var in final_variables:
            vals_by_key: dict[str, set[str]] = {}
            for constraint in var.constraints:
                if constraint.operator == "equals" and constraint.value is not None:
                    key = constraint.key.strip().casefold()
                    vals_by_key.setdefault(key, set()).add(
                        str(constraint.value).strip().casefold()
                    )
            for key, values in vals_by_key.items():
                if len(values) <= 1:
                    continue
                predicate_id = f"clarify:{var.id}:conflicting-equals:{key}"
                if predicate_id not in predicate_ids and not any(
                    predicate.kind == ClarificationPredicateKind.CONFLICTING_EQUALS
                    and predicate.operator == ClarificationPredicateOperator.HAS_CONFLICT
                    and predicate.variable_id == var.id
                    and predicate.constraint_key == key
                    for predicate in predicates
                ):
                    predicates.append(ClarificationPredicate(
                        id=predicate_id,
                        kind=ClarificationPredicateKind.CONFLICTING_EQUALS,
                        operator=ClarificationPredicateOperator.HAS_CONFLICT,
                        variable_id=var.id,
                        constraint_key=key,
                        rule_version="1.0",
                    ))
                    predicate_ids.add(predicate_id)

        evaluations = [
            evaluate_clarification_predicate(
                predicate,
                final_variables,
                state_version=graph.graph_revision,
            )
            for predicate in predicates
        ]
        for predicate, evaluation in zip(predicates, evaluations):
            if evaluation.result == ClarificationEvaluationResult.TRUE:
                values = evaluation.deterministic_inputs.get("normalized_values", [])
                question = (
                    f"Variable '{predicate.variable_id}' has conflicting equality "
                    f"constraints for key '{predicate.constraint_key}': {values}"
                )
                clarification_questions.append(question)
                diagnostics.append(question)
            elif evaluation.result == ClarificationEvaluationResult.INVALID:
                rejections.append(
                    f"Clarification predicate '{predicate.id}' is invalid: "
                    f"{', '.join(evaluation.reason_codes)}"
                )
            elif evaluation.result == ClarificationEvaluationResult.UNKNOWN:
                diagnostics.append(
                    f"Clarification predicate '{predicate.id}' is unknown and non-authoritative."
                )

        needs_clarification = any(
            evaluation.result == ClarificationEvaluationResult.TRUE
            for evaluation in evaluations
        )
        stage_results["clarification"] = not any(
            evaluation.result == ClarificationEvaluationResult.INVALID
            for evaluation in evaluations
        )

        validated_graph = replace(
            graph,
            variables=final_variables,
            relations=validated_relations,
            qualifiers=validated_qualifiers,
            clarification_predicates=predicates,
            clarification_evaluations=evaluations,
            validation_diagnostics=list(diagnostics),
        )

        valid = len(rejections) == 0
        return GoalGraphValidationResult(
            valid=valid,
            validated_graph=validated_graph,
            diagnostics=diagnostics,
            rejections=rejections,
            pruned_goal_ids=pruned_goal_ids,
            needs_clarification=needs_clarification,
            clarification_questions=clarification_questions,
            stage_results=stage_results,
        )


SemanticAcceptanceGate = SemanticGoalGraphValidator


__all__ = [
    "ValidationResult",
    "InvestigationValidator",
    "GoalGraphValidationResult",
    "SemanticGoalGraphValidator",
    "SemanticAcceptanceGate",
    "DEVICE_QUALIFIER_TERMS",
    "CANONICAL_RELATION_VOCABULARY",
]
