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
from hunting.contracts.semantic_graph import (
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)

DEVICE_QUALIFIER_TERMS = {
    "macbook", "macbook pro", "macbook air", "mac", "air13",
    "laptop", "desktop", "workstation", "pc", "computer",
    "iphone", "android", "phone", "mobile", "tablet", "device",
}

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


@dataclass
class GoalGraphValidationResult:
    """Outcome of deterministic SemanticGoalGraph validation."""
    valid: bool
    validated_graph: SemanticGoalGraph
    diagnostics: list[str] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    pruned_goal_ids: list[str] = field(default_factory=list)


class SemanticGoalGraphValidator:
    """Deterministic validator for SemanticGoalGraph proposals.

    Enforces Step C rules from 08 Master Plan:
    1. Entity Preservation: User-named entities must not be mutated (e.g. Mallory cannot become Alice).
    2. Invented Proper Nouns: Proper nouns not in request content or request entities are rejected or unbound.
    3. Device Qualifiers: 'MacBook' / laptop / PC is a device qualifier, never a hostname.
    4. Answer Utility: Every downstream relation goal must reduce or constrain an answer slot.
    5. Acyclic DAG: Dependencies must be acyclic.
    6. GATE validation: GATE dependencies require explicit gate_condition.
    7. Query Isolation: No native query syntax (SPL/KQL/SQL, index=, sourcetype=) in acceptance rules or constraints.
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

        # 1. Device Qualifiers vs Hostname & Entity Mutation Check
        rewritten_variables: list[SemanticVariable] = []
        for var in graph.variables:
            current_var = var
            var_val = var.value.strip() if var.value else None
            val_lower = var_val.casefold() if var_val else ""

            # Check: Device qualifier as hostname
            if var.entity_type.casefold() in {"host", "endpoint", "computer"} and var_val:
                is_device_term = val_lower in DEVICE_QUALIFIER_TERMS or any(
                    term in val_lower for term in ("macbook", "laptop", "desktop", "workstation", "phone", "tablet")
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
                    rewritten_variables.append(current_var)
                    continue

            # Check: Entity Mutation (e.g. Mallory -> Alice)
            if var.entity_type.casefold() in {"person", "user"} and var_val:
                if val_lower not in request_folded and val_lower not in all_explicit_values:
                    rejections.append(
                        f"Entity mutation rejected: proposed person '{var_val}' does not appear in request content."
                    )

            # Check: Invented proper noun marked as request origin
            if current_var.value_origin == "request" and var_val:
                if val_lower not in request_folded and val_lower not in all_explicit_values:
                    rejections.append(
                        f"Invented proper noun rejected: variable '{var.id}' value '{var_val}' is marked as request origin but does not appear in request."
                    )

            rewritten_variables.append(current_var)

        # 2. Check for native query leaks
        for var in rewritten_variables:
            for constraint in var.constraints:
                for term in constraint.retrieval_terms:
                    for pat in NATIVE_QUERY_PATTERNS:
                        if pat.search(str(term)):
                            rejections.append(
                                f"Native query syntax leaked into constraint retrieval terms: '{term}'"
                            )
                for pat in NATIVE_QUERY_PATTERNS:
                    if pat.search(str(constraint.value or "")):
                        rejections.append(
                            f"Native query syntax leaked into constraint value: '{constraint.value}'"
                        )

        for ac in graph.answer_contracts:
            for pat in NATIVE_QUERY_PATTERNS:
                if pat.search(ac.acceptance_rule):
                    rejections.append(
                        f"Native query syntax leaked into AnswerContract acceptance rule: '{ac.acceptance_rule}'"
                    )

        # 3. Check Acyclic Dependencies
        deps = dict(graph.dependencies)
        for rel in graph.relations:
            if rel.dependencies and rel.id not in deps:
                deps[rel.id] = list(rel.dependencies)

        visited: dict[str, int] = {}  # 0: visiting, 1: visited

        def has_cycle(node: str, path: list[str]) -> bool:
            visited[node] = 0
            for neighbor in deps.get(node, []):
                if visited.get(neighbor) == 0:
                    rejections.append(f"Cyclic dependency detected: {' -> '.join(path + [neighbor])}")
                    return True
                if neighbor not in visited:
                    if has_cycle(neighbor, path + [neighbor]):
                        return True
            visited[node] = 1
            return False

        for node in list(deps.keys()):
            if node not in visited:
                has_cycle(node, [node])

        # 4. Check GATE condition
        for rel in graph.relations:
            op = graph.dependency_kinds.get(rel.id, rel.dependency_operator).upper()
            if op == "GATE" and not rel.gate_condition:
                rejections.append(f"Goal '{rel.id}' uses GATE dependency operator but lacks gate_condition.")

        # 5. Check Provenance Spans
        for rel in graph.relations:
            span = rel.provenance_span or graph.provenance_spans.get(rel.id, "")
            if span:
                if span.casefold() not in request_folded:
                    diagnostics.append(f"Goal '{rel.id}' provenance span '{span}' does not match request content.")
            else:
                diagnostics.append(f"Goal '{rel.id}' missing explicit request provenance span.")

        # 6. Answer Slot Utility / Story Expansion Pruning
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

        validated_graph = replace(
            graph,
            variables=rewritten_variables,
            relations=validated_relations,
            qualifiers=validated_qualifiers,
            validation_diagnostics=list(diagnostics),
        )

        valid = len(rejections) == 0
        return GoalGraphValidationResult(
            valid=valid,
            validated_graph=validated_graph,
            diagnostics=diagnostics,
            rejections=rejections,
            pruned_goal_ids=pruned_goal_ids,
        )


__all__ = [
    "ValidationResult",
    "InvestigationValidator",
    "GoalGraphValidationResult",
    "SemanticGoalGraphValidator",
    "DEVICE_QUALIFIER_TERMS",
]
