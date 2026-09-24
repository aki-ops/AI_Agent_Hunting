"""Serializable bounded agenda for semantic execution.

The agenda orders already-declared work.  It cannot create goals, grant proof,
or choose a terminal disposition; those remain graph/proof/controller duties.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class AgendaItem:
    goal_id: str
    step_id: str
    operation_id: str
    mode: str = "EXPLORE"
    depends_on: tuple[str, ...] = ()
    mandatory: bool = True
    utility: float = 0.0
    information_gain: float = 0.0
    cost: float = 1.0
    cursor: str | None = None
    envelope_id: str = ""
    proof_method_id: str = ""
    route_id: str = ""
    bindings: tuple[tuple[str, str], ...] = ()

    @property
    def priority_key(self) -> tuple[Any, ...]:
        # Ranking is deterministic and only changes order.  Mandatory work,
        # utility and information gain precede bounded cost and stable ID.
        return (
            0 if self.mandatory else 1,
            -float(self.utility),
            -float(self.information_gain),
            float(self.cost),
            self.goal_id,
            self.step_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "step_id": self.step_id,
            "operation_id": self.operation_id,
            "mode": self.mode,
            "depends_on": list(self.depends_on),
            "mandatory": self.mandatory,
            "utility": self.utility,
            "information_gain": self.information_gain,
            "cost": self.cost,
            "cursor": self.cursor,
            "envelope_id": self.envelope_id,
            "proof_method_id": self.proof_method_id,
            "route_id": self.route_id,
            "bindings": [[key, value] for key, value in self.bindings],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgendaItem":
        return cls(
            goal_id=str(raw.get("goal_id", "")),
            step_id=str(raw.get("step_id", "")),
            operation_id=str(raw.get("operation_id", "")),
            mode=str(raw.get("mode", "EXPLORE")),
            depends_on=tuple(str(x) for x in raw.get("depends_on", ())),
            mandatory=bool(raw.get("mandatory", True)),
            utility=float(raw.get("utility", 0.0)),
            information_gain=float(raw.get("information_gain", 0.0)),
            cost=float(raw.get("cost", 1.0)),
            cursor=raw.get("cursor"),
            envelope_id=str(raw.get("envelope_id", "")),
            proof_method_id=str(raw.get("proof_method_id", "")),
            route_id=str(raw.get("route_id", "")),
            bindings=tuple(
                (str(item[0]), str(item[1]))
                for item in raw.get("bindings", ())
                if isinstance(item, (list, tuple)) and len(item) == 2
            ),
        )


@dataclass
class BoundedAgenda:
    """A deterministic, serializable queue over declared agenda items."""

    items: list[AgendaItem] = field(default_factory=list)
    dispatched: list[str] = field(default_factory=list)

    def add(self, item: AgendaItem) -> None:
        if any(existing.step_id == item.step_id for existing in self.items):
            return
        if item.step_id in self.dispatched:
            return
        self.items.append(item)

    def extend(self, items: Iterable[AgendaItem]) -> None:
        for item in items:
            self.add(item)

    def pop_next(self) -> AgendaItem | None:
        if not self.items:
            return None
        index = min(range(len(self.items)), key=lambda idx: self.items[idx].priority_key)
        item = self.items.pop(index)
        self.dispatched.append(item.step_id)
        return item

    def dispatch(self, step_id: str) -> AgendaItem | None:
        """Mark a declared step as attempted while leaving blocked work pending."""
        if step_id in self.dispatched:
            return None
        for index, item in enumerate(self.items):
            if item.step_id == step_id:
                self.items.pop(index)
                self.dispatched.append(step_id)
                return item
        return None

    def ordered(self) -> list[AgendaItem]:
        """Return a deterministic view without claiming dispatch."""
        return sorted(self.items, key=lambda item: item.priority_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "dispatched": list(self.dispatched),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BoundedAgenda":
        agenda = cls(
            items=[AgendaItem.from_dict(item) for item in raw.get("items", []) if isinstance(item, dict)],
            dispatched=[str(item) for item in raw.get("dispatched", [])],
        )
        return agenda


__all__ = ["AgendaItem", "BoundedAgenda"]
