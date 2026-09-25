"""Assign artifact or behavior after a graph has already passed validation.

The label is deterministic. It is not taken from the language model.
"""
from __future__ import annotations

import re
from dataclasses import replace

from hunting.contracts.ontology import FILE_IDENTITY_ANSWER_TYPES

_MANNER = {"logon_type", "channel", "frequency", "protocol"}
_IDENTITY = FILE_IDENTITY_ANSWER_TYPES
_BEHAVIOR_TEXT = ("bị dùng", "tương tác", "interactive", "lạm dụng", "logon", "đăng nhập")


def named_channels(request_text: str) -> tuple[str, ...]:
    found: list[str] = []
    if re.search(r"\bRDP\b", request_text, re.IGNORECASE):
        found.append("RDP")
    if re.search(r"console", request_text, re.IGNORECASE):
        found.append("console")
    return tuple(found)


def classify_relation(relation, qualifiers, answers, request_text: str) -> str:
    own = [item for item in qualifiers if getattr(item, "target_goal_id", "") == relation.id]
    if any(str(item.qualifier).lower() in _MANNER for item in own):
        return "behavior"
    lowered = request_text.casefold()
    if any(token in lowered for token in _BEHAVIOR_TEXT):
        return "behavior"
    answer_types = {str(getattr(item, "answer_type", "")).lower() for item in answers}
    if answer_types & _IDENTITY:
        return "artifact"
    return "artifact"


def annotate_goal_classes(graph, request_text: str):
    """Return the same graph with goal_class set and named channels kept as retrieval terms."""
    channels = named_channels(request_text)
    graph.relations = [
        replace(relation, goal_class=classify_relation(relation, graph.qualifiers, graph.answers, request_text))
        for relation in graph.relations
    ]
    updated = []
    for qualifier in graph.qualifiers:
        if str(qualifier.qualifier).lower() == "logon_type" and channels:
            merged = tuple(dict.fromkeys((*qualifier.retrieval_terms, *channels)))
            updated.append(replace(qualifier, retrieval_terms=merged))
        else:
            updated.append(qualifier)
    graph.qualifiers = updated
    unlabeled = [relation.id for relation in graph.relations if relation.goal_class not in {"artifact", "behavior"}]
    if unlabeled:
        raise ValueError("goal_class missing for " + ", ".join(unlabeled))
    return graph
