"""Investigation Validator.

Deterministic Validator (Component 2 of General Cyclical Investigation Loop).
Validates schema, entity roles, provider isolation, and enforces mandatory unknowns
for unproven entity prerequisites before allowing hunt progression.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hunting.contracts.investigation_model import (
    InvestigationModel,
    InvestigationUnknown,
    NodeStatus,
    NodeType,
    RelationType,
)


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


__all__ = ["ValidationResult", "InvestigationValidator"]
