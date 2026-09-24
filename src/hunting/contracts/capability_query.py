"""Provider-neutral capability queries derived from a semantic goal graph.

CapabilityQuery describes the shape of a route.  It does not name an index,
sourcetype, SPL, or vendor operation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from hunting.contracts.ontology import CANONICAL_RELATION_VOCABULARY, canonicalize_relation


def _norm(value: Any) -> str:
    return str(value or "").strip().casefold()


@dataclass(frozen=True)
class CapabilityQuery:
    goal_id: str
    subject_type: str
    object_type: str
    answer_role: str
    constraint_keys: tuple[str, ...] = ()
    relation_text: str = ""
    canonical_relation: str | None = None
    proposed_unregistered: bool = False
    # Searchable context is carried as a hint for source discovery.  It does
    # not grant proof and is intentionally excluded from the structural key.
    constraint_hints: tuple[dict[str, Any], ...] = ()
    qualifier_hints: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "goal_id", str(self.goal_id).strip())
        object.__setattr__(self, "subject_type", _norm(self.subject_type))
        object.__setattr__(self, "object_type", _norm(self.object_type))
        object.__setattr__(self, "answer_role", _norm(self.answer_role))
        object.__setattr__(self, "relation_text", str(self.relation_text or "").strip())
        object.__setattr__(self, "constraint_keys", tuple(sorted({
            _norm(key) for key in (self.constraint_keys or ()) if _norm(key)
        })))
        canonical = _norm(self.canonical_relation) or None
        object.__setattr__(self, "canonical_relation", canonical)
        object.__setattr__(self, "proposed_unregistered", bool(self.proposed_unregistered or canonical is None))
        object.__setattr__(self, "constraint_hints", tuple(dict(item) for item in (self.constraint_hints or ()) if isinstance(item, dict)))
        object.__setattr__(self, "qualifier_hints", tuple(dict(item) for item in (self.qualifier_hints or ()) if isinstance(item, dict)))

    @property
    def key(self) -> tuple[str, str, str, tuple[str, ...], str | None]:
        """Structural key; free-form relation wording is excluded."""
        return (
            self.subject_type,
            self.object_type,
            self.answer_role,
            self.constraint_keys,
            self.canonical_relation,
        )

    @property
    def query_key(self) -> tuple[str, str, str, tuple[str, ...], str | None]:
        return self.key

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "subject_type": self.subject_type,
            "object_type": self.object_type,
            "answer_role": self.answer_role,
            "constraint_keys": list(self.constraint_keys),
            "relation_text": self.relation_text,
            "canonical_relation": self.canonical_relation,
            "proposed_unregistered": self.proposed_unregistered,
            "constraint_hints": [dict(item) for item in self.constraint_hints],
            "qualifier_hints": [dict(item) for item in self.qualifier_hints],
            "query_key": list(self.key),
        }


def _constraint_keys(variable: Any) -> Iterable[str]:
    for constraint in getattr(variable, "constraints", ()) or ():
        key = getattr(constraint, "key", None)
        if key:
            yield str(key)


def build_capability_queries(graph: Any) -> tuple[CapabilityQuery, ...]:
    """Build one query contract per graph relation without provider heuristics."""
    variables = {item.id: item for item in getattr(graph, "variables", ())}
    answers = {
        item.variable_id: item
        for item in getattr(graph, "answers", ()) or ()
        if getattr(item, "variable_id", None)
    }
    result: list[CapabilityQuery] = []
    for relation in getattr(graph, "relations", ()) or ():
        subject = variables.get(relation.subject)
        target = variables.get(relation.object)
        if subject is None or target is None:
            continue
        keys = list(_constraint_keys(subject)) + list(_constraint_keys(target))
        constraint_hints = [
            constraint.to_dict()
            for variable in (subject, target)
            for constraint in getattr(variable, "constraints", ()) or ()
        ]
        qualifier_hints: list[dict[str, Any]] = []
        for qualifier in getattr(graph, "qualifiers", ()) or ():
            if qualifier.target_goal_id == relation.id and getattr(qualifier, "qualifier", None):
                keys.append(str(qualifier.qualifier))
                qualifier_hints.append({
                    "key": str(qualifier.qualifier),
                    "value": qualifier.expected_value,
                    "required": bool(getattr(qualifier, "required", False)),
                    "retrieval_terms": list(getattr(qualifier, "retrieval_terms", ()) or ()),
                })
        raw_relation = str(getattr(relation, "relation", ""))
        canonical = canonicalize_relation(raw_relation)
        if canonical not in CANONICAL_RELATION_VOCABULARY:
            canonical = None
        answer = answers.get(target.id)
        answer_role = ""
        if answer is not None:
            answer_role = str(getattr(answer, "answer_type", "") or "").strip()
        result.append(CapabilityQuery(
            goal_id=relation.id,
            subject_type=subject.entity_type,
            object_type=target.entity_type,
            answer_role=answer_role,
            constraint_keys=tuple(keys),
            relation_text=raw_relation,
            canonical_relation=canonical,
            proposed_unregistered=canonical is None,
            constraint_hints=tuple(constraint_hints),
            qualifier_hints=tuple(qualifier_hints),
        ))
    return tuple(result)


__all__ = ["CapabilityQuery", "build_capability_queries"]
