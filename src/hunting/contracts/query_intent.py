"""Provider-neutral query intent emitted before native query compilation."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


@dataclass(frozen=True)
class QueryPredicateSpec:
    """Typed semantic predicate with retrieval/proof and trust provenance."""

    key: str
    operator: str = "equals"
    value: Any = None
    role: str = "proof"
    provenance: str = "semantic_graph"
    trust_class: str = "request_grounded"

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", str(self.key).strip().casefold())
        object.__setattr__(self, "operator", str(self.operator).strip().casefold())
        object.__setattr__(self, "role", str(self.role).strip().casefold())
        object.__setattr__(self, "provenance", str(self.provenance).strip().casefold())
        object.__setattr__(self, "trust_class", str(self.trust_class).strip().casefold())
        if not self.key:
            raise ValueError("predicate key must not be empty")
        if self.operator not in {"equals", "contains", "exists"}:
            raise ValueError("predicate operator must be equals, contains or exists")
        if self.role not in {"retrieval", "proof"}:
            raise ValueError("predicate role must be retrieval or proof")
        if not self.provenance or not self.trust_class:
            raise ValueError("predicate provenance and trust_class must not be empty")

    @classmethod
    def from_raw(cls, raw: "QueryPredicateSpec | dict[str, Any]") -> "QueryPredicateSpec":
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, dict):
            raise ValueError("query predicate must be an object")
        if "constraint" in raw and "key" not in raw:
            text = str(raw["constraint"])
            if "=" in text:
                key, value = text.split("=", 1)
                return cls(key=key, value=value)
            if ":" in text:
                key, value = text.split(":", 1)
                return cls(key=key, operator="exists" if value == "exists" else "equals", value=None if value == "exists" else value)
            return cls(key=text, operator="exists")
        return cls(
            key=str(raw.get("key", raw.get("role", ""))),
            operator=str(raw.get("operator", "equals")),
            value=raw.get("value"),
            role=str(raw.get("predicate_role", raw.get("semantic_role", "proof"))),
            provenance=str(raw.get("provenance", "semantic_graph")),
            trust_class=str(raw.get("trust_class", "request_grounded")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "operator": self.operator,
            "value": self.value,
            "predicate_role": self.role,
            "provenance": self.provenance,
            "trust_class": self.trust_class,
        }


class QueryIntentMode(str, Enum):
    """Execution mode declaring epistemic authority of a query intent."""
    EXPLORE = "EXPLORE"          # Bounded discovery, small sample, no negative/proof license
    DISCRIMINATE = "DISCRIMINATE"  # Narrow candidate differentiation
    PROVE = "PROVE"              # Strict role projection, proof-capable


@dataclass(frozen=True)
class QueryIntentSpec:
    """A typed request for telemetry, independent of SPL/KQL/SQL syntax."""

    goal_id: str
    operation_id: str
    source_id: str
    relation: str
    bindings: dict[str, Any] = field(default_factory=dict)
    predicates: tuple[QueryPredicateSpec | dict[str, Any], ...] = ()
    time_window: str = ""
    projection_roles: tuple[str, ...] = ()
    transform: str = "rows"
    expected_output: tuple[str, ...] = ()
    max_rows: int = 100
    expected_cost: int | None = None
    binding_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)
    retrieval_stage: str = "narrow"
    mode: str = QueryIntentMode.PROVE.value

    def __post_init__(self) -> None:
        for name in ("goal_id", "operation_id", "source_id", "relation"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be empty")
        if self.max_rows <= 0 or self.max_rows > 10000:
            raise ValueError("max_rows must be between 1 and 10000")
        if not str(self.retrieval_stage).strip():
            raise ValueError("retrieval_stage must not be empty")
        mode_val = str(self.mode or QueryIntentMode.PROVE.value).upper()
        if mode_val not in {"EXPLORE", "DISCRIMINATE", "PROVE"}:
            mode_val = QueryIntentMode.PROVE.value
        object.__setattr__(self, "mode", mode_val)
        object.__setattr__(self, "bindings", dict(self.bindings))
        object.__setattr__(self, "predicates", tuple(QueryPredicateSpec.from_raw(p) for p in self.predicates))
        object.__setattr__(self, "binding_metadata", {
            str(key): dict(value) for key, value in self.binding_metadata.items()
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "operation_id": self.operation_id,
            "source_id": self.source_id,
            "relation": self.relation,
            "mode": self.mode,
            "bindings": dict(self.bindings),
            "binding_metadata": {key: dict(value) for key, value in self.binding_metadata.items()},
            "predicates": [predicate.to_dict() for predicate in self.predicates],
            "time_window": self.time_window,
            "projection_roles": list(self.projection_roles),
            "transform": self.transform,
            "expected_output": list(self.expected_output),
            "max_rows": self.max_rows,
            "expected_cost": self.expected_cost,
            "retrieval_stage": self.retrieval_stage,
        }


__all__ = ["QueryIntentSpec", "QueryPredicateSpec", "QueryIntentMode"]
