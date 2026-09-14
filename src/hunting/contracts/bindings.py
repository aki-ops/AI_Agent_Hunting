"""Controlled Candidate Binding Contracts.

Component of Phase 4 (Controlled Binding and Mixed-Initiative Control):
- Every variable is backed by a CandidateSet, never an assumed scalar string.
- Auto-bind only when exactly one candidate satisfies proof contract with zero contradictions.
- Explicit directness, contradictions, and confidence classes.
- Anti-heuristics: substring matches like 'air', edit distance, or first row never auto-bind.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConfidenceClass(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    AMBIGUOUS = "AMBIGUOUS"
    CONTRADICTED = "CONTRADICTED"


class BindingDirectness(str, Enum):
    DIRECT = "DIRECT"
    INDIRECT = "INDIRECT"
    HEURISTIC = "HEURISTIC"


@dataclass(frozen=True)
class CandidateBinding:
    """A candidate entity binding with explicit provenance, contract, and contradictions."""
    value: str
    entity_type: str
    supporting_fact_ids: tuple[str, ...] = ()
    relation_contract_id: str = ""
    directness: str = BindingDirectness.DIRECT.value
    contradictions: tuple[str, ...] = ()
    confidence_class: str = ConfidenceClass.MEDIUM.value
    status: str = "CANDIDATE"
    competing_values: tuple[str, ...] = ()
    discrimination_history: tuple[dict[str, Any], ...] = ()
    provenance: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", str(self.value).strip())
        object.__setattr__(self, "entity_type", str(self.entity_type).strip().casefold())
        if isinstance(self.supporting_fact_ids, (list, set)):
            object.__setattr__(self, "supporting_fact_ids", tuple(str(x) for x in self.supporting_fact_ids))
        if isinstance(self.contradictions, (list, set)):
            object.__setattr__(self, "contradictions", tuple(str(x) for x in self.contradictions))
        if isinstance(self.competing_values, (list, set)):
            object.__setattr__(self, "competing_values", tuple(str(x) for x in self.competing_values))
        if isinstance(self.discrimination_history, (list, set)):
            object.__setattr__(self, "discrimination_history", tuple(dict(x) for x in self.discrimination_history))
        object.__setattr__(self, "status", str(self.status).strip().upper())
        object.__setattr__(self, "provenance", str(self.provenance).strip())

    @property
    def is_valid_proof(self) -> bool:
        """True only when directly supported, verified by proof contract, with 0 contradictions."""
        return (
            bool(self.relation_contract_id)
            and len(self.supporting_fact_ids) > 0
            and len(self.contradictions) == 0
            and self.directness == BindingDirectness.DIRECT.value
            and self.confidence_class == ConfidenceClass.HIGH.value
        )

    @property
    def is_verified_binding(self) -> bool:
        return self.status == "VERIFIED_BINDING" or self.is_valid_proof

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "entity_type": self.entity_type,
            "supporting_fact_ids": list(self.supporting_fact_ids),
            "relation_contract_id": self.relation_contract_id,
            "directness": self.directness,
            "contradictions": list(self.contradictions),
            "confidence_class": self.confidence_class,
            "status": self.status,
            "competing_values": list(self.competing_values),
            "discrimination_history": [dict(x) for x in self.discrimination_history],
            "provenance": self.provenance,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CandidateBinding:
        return cls(
            value=str(data.get("value", "")),
            entity_type=str(data.get("entity_type", "entity")),
            supporting_fact_ids=tuple(str(x) for x in data.get("supporting_fact_ids", ())),
            relation_contract_id=str(data.get("relation_contract_id", "")),
            directness=str(data.get("directness", BindingDirectness.DIRECT.value)),
            contradictions=tuple(str(x) for x in data.get("contradictions", ())),
            confidence_class=str(data.get("confidence_class", ConfidenceClass.MEDIUM.value)),
            status=str(data.get("status", "CANDIDATE")),
            competing_values=tuple(str(x) for x in data.get("competing_values", ())),
            discrimination_history=tuple(dict(x) for x in data.get("discrimination_history", ())),
            provenance=str(data.get("provenance", "")),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class CandidateSet:
    """Set of candidate values for a semantic variable undergoing progressive grounding."""
    variable_id: str
    entity_type: str
    candidates: list[CandidateBinding] = field(default_factory=list)
    resolution_status: str = "UNRESOLVED"  # "UNRESOLVED" | "AUTO_BOUND" | "DISAMBIGUATED" | "NEEDS_DISAMBIGUATION"
    selected_binding: CandidateBinding | None = None
    diagnostics: list[str] = field(default_factory=list)
    cardinality: str = "singular"

    def add_candidate(self, candidate: CandidateBinding) -> None:
        existing = [c for c in self.candidates if c.value.casefold() == candidate.value.casefold()]
        if not existing:
            self.candidates.append(candidate)
        all_vals = tuple(c.value for c in self.candidates)
        for i, c in enumerate(self.candidates):
            competing = tuple(v for v in all_vals if v.casefold() != c.value.casefold())
            if c.competing_values != competing:
                self.candidates[i] = CandidateBinding(
                    value=c.value,
                    entity_type=c.entity_type,
                    supporting_fact_ids=c.supporting_fact_ids,
                    relation_contract_id=c.relation_contract_id,
                    directness=c.directness,
                    contradictions=c.contradictions,
                    confidence_class=c.confidence_class,
                    status=c.status,
                    competing_values=competing,
                    discrimination_history=c.discrimination_history,
                    provenance=c.provenance,
                    metadata=c.metadata,
                )

    @property
    def valid_candidates(self) -> list[CandidateBinding]:
        return [c for c in self.candidates if len(c.contradictions) == 0]

    @property
    def is_ambiguous(self) -> bool:
        """True if more than 1 valid candidate exists for a singular target."""
        if self.cardinality == "plural":
            return False
        return len(self.valid_candidates) > 1

    @property
    def can_autobind(self) -> bool:
        """Invariant: Auto-bind ONLY when exactly one candidate satisfies proof contract with zero contradictions,
        or for plural target when all valid candidates satisfy proof contract."""
        valid = self.valid_candidates
        if self.cardinality == "plural":
            return len(valid) > 0 and all(c.is_verified_binding for c in valid)
        if len(valid) != 1:
            return False
        return valid[0].is_verified_binding

    def try_autobind(self) -> CandidateBinding | None:
        """Attempt to auto-bind. Returns the binding if unique and proof-supported, else None."""
        if self.can_autobind:
            self.selected_binding = self.valid_candidates[0]
            self.resolution_status = "AUTO_BOUND"
            self.diagnostics.append(
                f"Auto-bound variable '{self.variable_id}' to unique proof-grounded candidate '{self.selected_binding.value}'."
            )
            return self.selected_binding

        if self.is_ambiguous:
            self.resolution_status = "NEEDS_DISAMBIGUATION"
            cand_vals = [c.value for c in self.valid_candidates]
            self.diagnostics.append(
                f"Variable '{self.variable_id}' is ambiguous across {len(self.valid_candidates)} candidates: {cand_vals}. "
                "Auto-binding prohibited; discriminator or user clarification required."
            )
        elif len(self.valid_candidates) == 0:
            self.resolution_status = "UNRESOLVED"
            self.diagnostics.append(f"Variable '{self.variable_id}' has 0 valid candidates.")

        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "variable_id": self.variable_id,
            "entity_type": self.entity_type,
            "candidates": [c.to_dict() for c in self.candidates],
            "resolution_status": self.resolution_status,
            "selected_binding": self.selected_binding.to_dict() if self.selected_binding else None,
            "diagnostics": list(self.diagnostics),
            "cardinality": self.cardinality,
            "is_ambiguous": self.is_ambiguous,
            "can_autobind": self.can_autobind,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CandidateSet:
        candidates = [CandidateBinding.from_dict(c) for c in data.get("candidates", [])]
        selected = CandidateBinding.from_dict(data["selected_binding"]) if data.get("selected_binding") else None
        return cls(
            variable_id=str(data.get("variable_id", "")),
            entity_type=str(data.get("entity_type", "entity")),
            candidates=candidates,
            resolution_status=str(data.get("resolution_status", "UNRESOLVED")),
            selected_binding=selected,
            diagnostics=[str(d) for d in data.get("diagnostics", [])],
            cardinality=str(data.get("cardinality", "singular")),
        )


__all__ = [
    "ConfidenceClass",
    "BindingDirectness",
    "CandidateBinding",
    "CandidateSet",
]
