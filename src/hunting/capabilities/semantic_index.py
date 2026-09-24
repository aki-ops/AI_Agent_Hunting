"""Deterministic F0/F1 capability retrieval.

F0 emits exact approved-operation identity when labels already coincide.
F1 retrieves operation, source and field documents with no LLM.  Rank never
proves a relation.  Relation wording is retrieve context, not a structural key.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterable

from hunting.contracts.capability_query import CapabilityQuery
from hunting.contracts.ontology import CANONICAL_ROLE_SYNONYMS, canonicalize_role, types_are_compatible
from hunting.contracts.queries import is_untyped_leftover_contract
from hunting.contracts.source_profile import TelemetrySourceProfile

INDEX_VERSION = "f1-dense-v1"
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_STOPWORDS = {"a", "an", "and", "by", "for", "from", "in", "is", "of", "on", "the", "to", "with"}
_VECTOR_DIM = 256


def _tokens(value: Any) -> set[str]:
    text = _CAMEL_RE.sub(" ", str(value or "").casefold())
    return {
        token for token in _TOKEN_RE.findall(text.replace("_", " ").replace(":", " ").replace("-", " "))
        if len(token) > 1 and token not in _STOPWORDS
    }


def _type_tokens(value: str) -> set[str]:
    raw = str(value or "").casefold()
    canonical = canonicalize_role(raw)
    synonyms = CANONICAL_ROLE_SYNONYMS.get(canonical, set())
    return _tokens(raw) | _tokens(canonical) | set().union(*(_tokens(item) for item in synonyms))


def _semantic_tokens(value: Any) -> set[str]:
    tokens = _tokens(value)
    expanded = set(tokens)
    for token in tokens:
        canonical = canonicalize_role(token)
        expanded.update(_tokens(canonical))
        expanded.update(
            synonym_token
            for synonym in CANONICAL_ROLE_SYNONYMS.get(canonical, set())
            for synonym_token in _tokens(synonym)
        )
    return expanded


def _char_ngrams(text: str, n: int = 3) -> list[str]:
    padded = f"^{str(text or '').casefold()}$"
    if len(padded) < n:
        return [padded]
    return [padded[index:index + n] for index in range(len(padded) - n + 1)]


def _stable_bucket(key: tuple[str, str], dim: int = _VECTOR_DIM) -> int:
    return hash(key) % dim


def _dense_vector(features: Iterable[str], *, weight: float = 1.0) -> list[float]:
    vector = [0.0] * _VECTOR_DIM
    for feature in features:
        token = str(feature or "").casefold().strip()
        if not token:
            continue
        vector[_stable_bucket(("tok", token))] += weight
        for ngram in _char_ngrams(token):
            vector[_stable_bucket(("ng", ngram))] += 0.35 * weight
    return vector


def _add_vectors(left: list[float], right: list[float]) -> list[float]:
    return [a + b for a, b in zip(left, right)]


def _cosine(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    norm_left = math.sqrt(sum(a * a for a in left))
    norm_right = math.sqrt(sum(b * b for b in right))
    if norm_left == 0.0 or norm_right == 0.0:
        return 0.0
    return dot / (norm_left * norm_right)


def _labels_coincide(query: CapabilityQuery, operation: Any) -> bool:
    relation = str(query.relation_text or "").strip().casefold()
    canonical = str(query.canonical_relation or "").strip().casefold()
    declared = {
        str(item).strip().casefold()
        for item in getattr(operation, "guaranteed_relations", ()) or ()
        if str(item).strip()
    }
    if relation and relation in declared:
        return True
    if canonical and canonical in declared:
        return True
    operation_id = str(getattr(operation, "id", "") or "").strip().casefold()
    return bool(relation and operation_id and relation == operation_id)


def _declared_mapping(operation: Any) -> bool:
    return bool(
        getattr(operation, "native_field_bindings", None)
        or getattr(operation, "output_value_bindings", None)
        or getattr(operation, "output_fields", None)
    )


def _operation_route_class(operation: Any, *, exact: bool = False) -> str:
    if is_untyped_leftover_contract(operation):
        return "DISCOVERY_ONLY"
    input_kinds = tuple(getattr(operation, "input_entity_kinds", ()) or ())
    output_kinds = tuple(getattr(operation, "output_entity_kinds", ()) or ())
    if not input_kinds or not output_kinds:
        return "DISCOVERY_ONLY"
    if exact or _declared_mapping(operation):
        return "EXECUTABLE"
    return "MAPPING_REQUIRED"


@dataclass(frozen=True)
class CapabilityHit:
    source_id: str
    score: float
    matched_terms: tuple[str, ...] = ()
    matched_field_ids: tuple[str, ...] = ()
    rank: int = 0
    document_kind: str = "source"
    document_id: str = ""
    operation_id: str | None = None
    field_id: str | None = None
    features: tuple[str, ...] = ()
    index_version: str = INDEX_VERSION
    route_class: str = "DISCOVERY_ONLY"
    frontier_stage: str = "F1_METADATA"

    @property
    def relevant(self) -> bool:
        return self.score > 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "score": round(self.score, 6),
            "matched_terms": list(self.matched_terms),
            "matched_field_ids": list(self.matched_field_ids),
            "rank": self.rank,
            "relevant": self.relevant,
            "document_kind": self.document_kind,
            "document_id": self.document_id or self.source_id,
            "operation_id": self.operation_id,
            "field_id": self.field_id,
            "features": list(self.features),
            "index_version": self.index_version,
            "route_class": self.route_class,
            "frontier_stage": self.frontier_stage,
        }


@dataclass(frozen=True)
class CapabilityRetrieval:
    query: CapabilityQuery
    hits: tuple[CapabilityHit, ...]
    unexamined_ids: tuple[str, ...]
    total_documents: int
    k: int
    deferred_ids: tuple[str, ...] = ()
    operation_hits: tuple[CapabilityHit, ...] = ()
    field_hits: tuple[CapabilityHit, ...] = ()
    index_version: str = INDEX_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query.to_dict(),
            "k": self.k,
            "total_documents": self.total_documents,
            "hits": [hit.to_dict() for hit in self.hits],
            "operation_hits": [hit.to_dict() for hit in self.operation_hits],
            "field_hits": [hit.to_dict() for hit in self.field_hits],
            "unexamined_ids": list(self.unexamined_ids),
            "deferred_ids": list(self.deferred_ids),
            "index_version": self.index_version,
            "complete": not bool(self.unexamined_ids or self.deferred_ids),
            "proof": False,
        }


class SemanticCapabilityIndex:
    """Provider-descriptor index over operations, sources and fields."""

    def __init__(self, profiles: Iterable[TelemetrySourceProfile], operations: Iterable[Any] = ()) -> None:
        self.profiles = tuple(profiles)
        self.operations = tuple(
            operation for operation in operations
            if not getattr(operation, "legacy_alias", False)
        )

    def _operation_terms(self, profile: TelemetrySourceProfile) -> set[str]:
        terms: set[str] = set()
        for operation in self.operations:
            source_id = str(getattr(operation, "runtime_source_id", "") or "")
            if source_id and source_id != profile.source_id:
                continue
            if not source_id:
                continue
            for value in (
                getattr(operation, "semantic_intents", ()),
                getattr(operation, "input_entity_kinds", ()),
                getattr(operation, "output_entity_kinds", ()),
                getattr(operation, "input_roles", ()),
                getattr(operation, "output_roles", ()),
                getattr(operation, "output_fields", ()),
                getattr(operation, "output_fact_kinds", ()),
                getattr(operation, "guaranteed_relations", ()),
            ):
                for item in value or ():
                    terms.update(_tokens(item))
        return terms

    def _query_features(self, query: CapabilityQuery) -> tuple[list[float], set[str], set[str], set[str]]:
        type_terms = _type_tokens(query.subject_type) | _type_tokens(query.object_type) | _type_tokens(query.answer_role)
        constraint_terms = set().union(*(_semantic_tokens(item) for item in query.constraint_keys)) if query.constraint_keys else set()
        relation_terms = _semantic_tokens(query.relation_text) | _semantic_tokens(query.canonical_relation)
        vector = _dense_vector(type_terms | constraint_terms, weight=1.0)
        if relation_terms:
            vector = _add_vectors(vector, _dense_vector(relation_terms, weight=0.35))
        return vector, type_terms, constraint_terms, relation_terms

    def _score_source(
        self,
        profile: TelemetrySourceProfile,
        query_vector: list[float],
        requested_types: set[str],
        constraint_terms: set[str],
        relation_terms: set[str],
    ) -> tuple[float, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        source_terms = self._operation_terms(profile)
        field_matches: list[tuple[int, str, set[str]]] = []
        field_features: list[str] = []
        for field in profile.fields:
            field_terms = _semantic_tokens(field.name)
            field_features.extend(field_terms)
            matches = field_terms & (requested_types | constraint_terms | relation_terms)
            if matches:
                field_matches.append((len(matches), field.field_id, matches))
        field_matches.sort(key=lambda value: (-value[0], value[1]))
        matched_fields = tuple(item[1] for item in field_matches)
        matched_terms = set().union(*(item[2] for item in field_matches)) if field_matches else set()
        type_overlap = source_terms & requested_types
        relation_overlap = source_terms & relation_terms
        lexical = (2.5 * len(type_overlap)) + (2.0 * len(constraint_terms & matched_terms))
        lexical += (1.25 * len(relation_overlap)) + sum(item[0] for item in field_matches[:8])
        dense = 3.0 * _cosine(query_vector, _dense_vector(source_terms | set(field_features)))
        score = (lexical + dense) if lexical > 0.0 else 0.0
        route_class = "MAPPING_REQUIRED" if score > 0.0 else "DISCOVERY_ONLY"
        return score, tuple(sorted(matched_terms)), matched_fields, (route_class,)

    def _score_operation(
        self,
        operation: Any,
        query: CapabilityQuery,
        query_vector: list[float],
        requested_types: set[str],
        constraint_terms: set[str],
        relation_terms: set[str],
    ) -> tuple[float, tuple[str, ...], str, str]:
        exact = _labels_coincide(query, operation)
        features = []
        for value in (
            getattr(operation, "semantic_intents", ()),
            getattr(operation, "input_entity_kinds", ()),
            getattr(operation, "output_entity_kinds", ()),
            getattr(operation, "input_roles", ()),
            getattr(operation, "output_roles", ()),
            getattr(operation, "output_fields", ()),
            getattr(operation, "output_fact_kinds", ()),
            getattr(operation, "supported_constraints", ()),
            getattr(operation, "guaranteed_relations", ()),
        ):
            features.extend(str(item) for item in (value or ()))
        op_terms = set().union(*(_semantic_tokens(item) for item in features)) if features else set()
        type_boost = 0.0
        input_kinds = tuple(getattr(operation, "input_entity_kinds", ()) or ())
        output_kinds = tuple(getattr(operation, "output_entity_kinds", ()) or ())
        if input_kinds and any(types_are_compatible(query.subject_type, kind) for kind in input_kinds):
            type_boost += 2.5
        if output_kinds and any(types_are_compatible(query.object_type, kind) for kind in output_kinds):
            type_boost += 2.5
        if query.answer_role and any(types_are_compatible(query.answer_role, kind) for kind in output_kinds):
            type_boost += 1.0
        type_boost += 1.25 * len(op_terms & requested_types)
        type_boost += 1.0 * len(op_terms & constraint_terms)
        type_boost += 0.5 * len(op_terms & relation_terms)
        dense = 3.0 * _cosine(query_vector, _dense_vector(features))
        structural = type_boost + (8.0 if exact else 0.0)
        score = (structural + dense) if structural > 0.0 else 0.0
        stage = "F0_CERTIFIED" if exact else "F1_METADATA"
        return score, tuple(sorted(op_terms & (requested_types | constraint_terms | relation_terms))), stage, _operation_route_class(operation, exact=exact)

    def retrieve(self, query: CapabilityQuery, *, k: int = 8) -> CapabilityRetrieval:
        if k <= 0:
            raise ValueError("k must be positive")
        query_vector, requested_types, constraint_terms, relation_terms = self._query_features(query)

        source_scored: list[tuple[float, tuple[str, ...], tuple[str, ...], str, TelemetrySourceProfile]] = []
        for profile in self.profiles:
            score, matched_terms, matched_fields, route_meta = self._score_source(
                profile, query_vector, requested_types, constraint_terms, relation_terms,
            )
            source_scored.append((score, matched_terms, matched_fields, route_meta[0], profile))
        source_scored.sort(key=lambda item: (-item[0], item[4].source_id))
        selected_sources = source_scored[:k]
        source_hits = tuple(
            CapabilityHit(
                source_id=item[4].source_id,
                score=item[0],
                matched_terms=item[1],
                matched_field_ids=item[2],
                rank=index,
                document_kind="source",
                document_id=item[4].source_id,
                features=item[1],
                route_class=item[3],
            )
            for index, item in enumerate(selected_sources, start=1)
        )

        operation_scored: list[tuple[float, tuple[str, ...], str, str, Any]] = []
        for operation in self.operations:
            score, matched_terms, stage, route_class = self._score_operation(
                operation, query, query_vector, requested_types, constraint_terms, relation_terms,
            )
            operation_scored.append((score, matched_terms, stage, route_class, operation))
        operation_scored.sort(key=lambda item: (-item[0], str(getattr(item[4], "id", ""))))
        selected_operations = operation_scored[:k]
        operation_hits = tuple(
            CapabilityHit(
                source_id=str(getattr(item[4], "runtime_source_id", "") or getattr(item[4], "id", "")),
                score=item[0],
                matched_terms=item[1],
                rank=index,
                document_kind="operation",
                document_id=str(getattr(item[4], "id", "")),
                operation_id=str(getattr(item[4], "id", "")),
                features=item[1],
                route_class=item[3],
                frontier_stage=item[2],
            )
            for index, item in enumerate(selected_operations, start=1)
        )

        field_scored: list[tuple[float, tuple[str, ...], str, str]] = []
        for profile in self.profiles:
            for field_profile in profile.fields:
                field_terms = _semantic_tokens(field_profile.name)
                matches = field_terms & (requested_types | constraint_terms | relation_terms)
                dense = 3.0 * _cosine(query_vector, _dense_vector(field_terms))
                score = (float(len(matches)) + dense) if matches else 0.0
                field_scored.append((
                    score,
                    tuple(sorted(matches)),
                    profile.source_id,
                    field_profile.field_id,
                ))
        field_scored.sort(key=lambda item: (-item[0], item[3]))
        selected_fields = field_scored[:k]
        field_hits = tuple(
            CapabilityHit(
                source_id=item[2],
                score=item[0],
                matched_terms=item[1],
                matched_field_ids=(item[3],),
                rank=index,
                document_kind="field",
                document_id=item[3],
                field_id=item[3],
                features=item[1],
                route_class="DISCOVERY_ONLY" if item[0] > 0.0 else "DISCOVERY_ONLY",
            )
            for index, item in enumerate(selected_fields, start=1)
        )

        selected_source_ids = {hit.source_id for hit in source_hits}
        return CapabilityRetrieval(
            query=query,
            hits=source_hits,
            operation_hits=operation_hits,
            field_hits=field_hits,
            unexamined_ids=tuple(
                sorted(profile.source_id for profile in self.profiles if profile.source_id not in selected_source_ids)
            ),
            total_documents=len(self.profiles) + len(self.operations) + sum(len(profile.fields) for profile in self.profiles),
            k=k,
        )


CapabilityIndex = SemanticCapabilityIndex

__all__ = [
    "CapabilityHit",
    "CapabilityRetrieval",
    "SemanticCapabilityIndex",
    "CapabilityIndex",
    "INDEX_VERSION",
]
