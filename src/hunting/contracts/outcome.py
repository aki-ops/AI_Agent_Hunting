"""Canonical OutcomeContract definitions (v9).

Replaces unstructured or case-specific answer dictionaries with typed,
auditable outcome contracts across three investigation archetypes:
1. FactualAnswerContract: Specific entity or attribute lookup.
2. HypothesisVerdictContract: Competing hypothesis testing with support/refutation obligations.
3. PopulationDiscoveryContract: Enumeration and prevalence estimation over a scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Union


class OutcomeContractKind(str, Enum):
    FACTUAL_ANSWER = "FACTUAL_ANSWER"
    HYPOTHESIS_VERDICT = "HYPOTHESIS_VERDICT"
    POPULATION_DISCOVERY = "POPULATION_DISCOVERY"


class Cardinality(str, Enum):
    SINGULAR = "singular"
    PLURAL = "plural"


@dataclass(frozen=True)
class FactualAnswerContract:
    """Contract for answering factual questions with exact entity/attribute slots."""

    slots: tuple[str, ...]
    types: dict[str, str] = field(default_factory=dict)
    cardinality: dict[str, str] = field(default_factory=dict)
    qualifiers: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    contract_kind: str = OutcomeContractKind.FACTUAL_ANSWER.value

    def __post_init__(self) -> None:
        object.__setattr__(self, "slots", tuple(str(s).strip() for s in self.slots if str(s).strip()))
        if not self.slots:
            raise ValueError("FactualAnswerContract.slots must not be empty")
        types_clean = {str(k).strip(): str(v).strip().casefold() for k, v in self.types.items()}
        object.__setattr__(self, "types", types_clean)
        card_clean = {
            str(k).strip(): (Cardinality.PLURAL.value if str(v).strip().casefold() == "plural" else Cardinality.SINGULAR.value)
            for k, v in self.cardinality.items()
        }
        object.__setattr__(self, "cardinality", card_clean)
        object.__setattr__(self, "qualifiers", tuple(str(q).strip() for q in self.qualifiers if str(q).strip()))
        object.__setattr__(self, "citations", tuple(str(c).strip() for c in self.citations if str(c).strip()))

    def is_singular(self, slot: str) -> bool:
        return self.cardinality.get(slot, Cardinality.SINGULAR.value) == Cardinality.SINGULAR.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_kind": self.contract_kind,
            "slots": list(self.slots),
            "types": dict(self.types),
            "cardinality": dict(self.cardinality),
            "qualifiers": list(self.qualifiers),
            "citations": list(self.citations),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FactualAnswerContract:
        return cls(
            slots=tuple(data.get("slots", ())),
            types=dict(data.get("types", {})),
            cardinality=dict(data.get("cardinality", {})),
            qualifiers=tuple(data.get("qualifiers", ())),
            citations=tuple(data.get("citations", ())),
        )


@dataclass(frozen=True)
class HypothesisVerdictContract:
    """Contract for hypothesis testing with mandatory support/refutation conditions."""

    support_obligations: tuple[str, ...]
    refutation_obligations: tuple[str, ...] = ()
    falsification_conditions: tuple[str, ...] = ()
    scope: str = ""
    contract_kind: str = OutcomeContractKind.HYPOTHESIS_VERDICT.value

    def __post_init__(self) -> None:
        object.__setattr__(self, "support_obligations", tuple(str(o).strip() for o in self.support_obligations if str(o).strip()))
        if not self.support_obligations:
            raise ValueError("HypothesisVerdictContract.support_obligations must not be empty")
        object.__setattr__(self, "refutation_obligations", tuple(str(o).strip() for o in self.refutation_obligations if str(o).strip()))
        object.__setattr__(self, "falsification_conditions", tuple(str(c).strip() for c in self.falsification_conditions if str(c).strip()))
        object.__setattr__(self, "scope", str(self.scope).strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_kind": self.contract_kind,
            "support_obligations": list(self.support_obligations),
            "refutation_obligations": list(self.refutation_obligations),
            "falsification_conditions": list(self.falsification_conditions),
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HypothesisVerdictContract:
        return cls(
            support_obligations=tuple(data.get("support_obligations", ())),
            refutation_obligations=tuple(data.get("refutation_obligations", ())),
            falsification_conditions=tuple(data.get("falsification_conditions", ())),
            scope=str(data.get("scope", "")),
        )


@dataclass(frozen=True)
class PopulationDiscoveryContract:
    """Contract for population sweep and prevalence estimation."""

    population_unit: str
    candidate_schema: dict[str, str] = field(default_factory=dict)
    prevalence_aggregation: str = "count"
    coverage_requirement: str = "EXHAUSTIVE"
    contract_kind: str = OutcomeContractKind.POPULATION_DISCOVERY.value

    def __post_init__(self) -> None:
        unit = str(self.population_unit).strip()
        if not unit:
            raise ValueError("PopulationDiscoveryContract.population_unit must not be empty")
        object.__setattr__(self, "population_unit", unit)
        object.__setattr__(self, "candidate_schema", {str(k).strip(): str(v).strip() for k, v in self.candidate_schema.items()})
        object.__setattr__(self, "prevalence_aggregation", str(self.prevalence_aggregation).strip())
        object.__setattr__(self, "coverage_requirement", str(self.coverage_requirement).strip().upper())

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_kind": self.contract_kind,
            "population_unit": self.population_unit,
            "candidate_schema": dict(self.candidate_schema),
            "prevalence_aggregation": self.prevalence_aggregation,
            "coverage_requirement": self.coverage_requirement,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PopulationDiscoveryContract:
        return cls(
            population_unit=str(data.get("population_unit", "")),
            candidate_schema=dict(data.get("candidate_schema", {})),
            prevalence_aggregation=str(data.get("prevalence_aggregation", "count")),
            coverage_requirement=str(data.get("coverage_requirement", "EXHAUSTIVE")),
        )


OutcomeContract = Union[FactualAnswerContract, HypothesisVerdictContract, PopulationDiscoveryContract]


def outcome_contract_from_dict(data: dict[str, Any]) -> OutcomeContract:
    """Deserialize any OutcomeContract from dictionary."""
    kind = str(data.get("contract_kind", "")).upper()
    if kind == OutcomeContractKind.HYPOTHESIS_VERDICT.value:
        return HypothesisVerdictContract.from_dict(data)
    elif kind == OutcomeContractKind.POPULATION_DISCOVERY.value:
        return PopulationDiscoveryContract.from_dict(data)
    else:
        # Default to FactualAnswerContract
        return FactualAnswerContract.from_dict(data)


def outcome_contract_from_legacy_answer_contract(legacy: Any) -> FactualAnswerContract:
    """Convert legacy AnswerContract or dictionary to FactualAnswerContract."""
    if isinstance(legacy, FactualAnswerContract):
        return legacy
    if hasattr(legacy, "variable_id"):
        var_id = getattr(legacy, "variable_id", "target")
        ans_type = getattr(legacy, "answer_type", "entity")
        return FactualAnswerContract(
            slots=(var_id,),
            types={var_id: ans_type},
            cardinality={var_id: "singular"},
        )
    if isinstance(legacy, dict):
        var_id = legacy.get("variable_id", legacy.get("slot", "target"))
        ans_type = legacy.get("answer_type", legacy.get("type", "entity"))
        return FactualAnswerContract(
            slots=(str(var_id),),
            types={str(var_id): str(ans_type)},
            cardinality={str(var_id): "singular"},
        )
    return FactualAnswerContract(slots=("target",), types={"target": "entity"})


def outcome_to_dict(contract: OutcomeContract) -> dict[str, Any]:
    return contract.to_dict()


def outcome_from_dict(data: dict[str, Any]) -> OutcomeContract:
    return outcome_contract_from_dict(data)


def outcome_from_legacy_answers(
    answers: list[Any] | tuple[Any, ...] | None = None,
    answer_contracts: list[Any] | tuple[Any, ...] | None = None,
) -> FactualAnswerContract:
    """Derive a canonical FactualAnswerContract from legacy answers or answer_contracts."""
    slots: list[str] = []
    types: dict[str, str] = {}
    qualifiers: list[str] = []
    for ac in answer_contracts or ():
        slot_name = getattr(ac, "slot_name", getattr(ac, "target_variable_id", "target"))
        val_type = getattr(ac, "value_type", "value")
        slots.append(slot_name)
        types[slot_name] = val_type
        for q in getattr(ac, "required_qualifiers", ()):
            qualifiers.append(str(q))
    for a in answers or ():
        var_id = getattr(a, "variable_id", "target")
        if var_id not in slots:
            slots.append(var_id)
            types[var_id] = getattr(a, "answer_type", "value")
    if not slots:
        slots = ["target"]
        types = {"target": "value"}
    return FactualAnswerContract(
        slots=tuple(slots),
        types=types,
        qualifiers=tuple(qualifiers),
    )


__all__ = [
    "OutcomeContractKind",
    "Cardinality",
    "FactualAnswerContract",
    "HypothesisVerdictContract",
    "PopulationDiscoveryContract",
    "OutcomeContract",
    "outcome_contract_from_dict",
    "outcome_contract_from_legacy_answer_contract",
    "outcome_to_dict",
    "outcome_from_dict",
    "outcome_from_legacy_answers",
]
