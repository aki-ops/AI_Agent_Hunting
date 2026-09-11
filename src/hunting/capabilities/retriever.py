"""Exhaustive, relation-scoped batching of telemetry capability profiles.

The previous implementation selected an adaptive Top-K source shortlist. That
was still a recall risk: a relevant native source could be discarded before
the LLM ever saw it. This module orders profiles for convenience, but never
removes a source or field because of its score. Every profile is delivered in
one or more bounded batches and the audit records complete/partial coverage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Iterable

from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_STOPWORDS = {
    "a", "an", "and", "after", "associated", "be", "by", "determine",
    "establish", "find", "for", "from", "get", "identify", "in", "is",
    "of", "on", "the", "to", "with", "what",
}


def _tokens(value: Any) -> set[str]:
    text = _CAMEL_RE.sub(" ", str(value or "").casefold())
    return {
        token
        for token in _TOKEN_RE.findall(text.replace("_", " ").replace(":", " "))
        if len(token) > 1 and token not in _STOPWORDS
    }


@dataclass(frozen=True)
class SourceCandidate:
    """Retrieval metadata used only to order exhaustive processing."""

    relation: str
    source_id: str
    score: float
    matched_terms: tuple[str, ...] = ()
    matched_field_ids: tuple[str, ...] = ()
    rank: int = 0
    low_confidence: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation,
            "source_id": self.source_id,
            "score": round(self.score, 6),
            "matched_terms": list(self.matched_terms),
            "matched_field_ids": list(self.matched_field_ids),
            "rank": self.rank,
            "low_confidence": self.low_confidence,
        }


@dataclass(frozen=True)
class RetrievalResult:
    """All relation profiles and the bounded batches used to process them."""

    profiles_by_relation: dict[str, tuple[TelemetrySourceProfile, ...]]
    batches_by_relation: dict[str, tuple[tuple[TelemetrySourceProfile, ...], ...]]
    candidates_by_relation: dict[str, tuple[SourceCandidate, ...]]
    audit: list[dict[str, Any]]


class CapabilityBatcher:
    """Batch every observed source profile without Top-K source selection.

    Scores affect ordering only. ``max_profiles_per_batch`` and
    ``max_fields_per_source_per_batch`` limit one prompt's size; they do not
    limit total source/field coverage for the relation.
    """

    def __init__(
        self,
        *,
        max_profiles_per_batch: int = 8,
        max_fields_per_source_per_batch: int = 48,
    ) -> None:
        if max_profiles_per_batch <= 0:
            raise ValueError("max_profiles_per_batch must be positive")
        if max_fields_per_source_per_batch <= 0:
            raise ValueError("max_fields_per_source_per_batch must be positive")
        self.max_profiles_per_batch = max_profiles_per_batch
        self.max_fields_per_source_per_batch = max_fields_per_source_per_batch

    @staticmethod
    def _requirement_terms(requirement: dict[str, Any]) -> set[str]:
        values: list[Any] = [
            requirement.get("relation"),
            requirement.get("description"),
            requirement.get("subject_type"),
            requirement.get("object_type"),
            requirement.get("answer_type"),
        ]
        values.extend(requirement.get("constraint_terms", []) or [])
        return set().union(*(_tokens(value) for value in values))

    @staticmethod
    def _score(
        profile: TelemetrySourceProfile,
        terms: set[str],
    ) -> tuple[float, tuple[str, ...], tuple[str, ...]]:
        """Return a relevance order, never an admission decision."""
        source_terms = _tokens(profile.source_id) | _tokens(profile.native_type)
        source_matches = source_terms & terms
        score = 1.5 * len(source_matches)
        matched_fields: list[tuple[float, TelemetryFieldProfile]] = []
        for field in profile.fields:
            field_terms = _tokens(field.name) | _tokens(field.field_id)
            matches = field_terms & terms
            if not matches:
                continue
            field_score = 2.0 * len(matches)
            if field.name.casefold() in terms:
                field_score += 1.0
            matched_fields.append((field_score, field))
        matched_fields.sort(key=lambda item: (-item[0], item[1].field_id))
        score += sum(item[0] for item in matched_fields[:8])
        matched_terms = tuple(sorted(source_matches | {
            token
            for _, field in matched_fields[:8]
            for token in (_tokens(field.name) & terms)
        }))
        field_ids = tuple(field.field_id for _, field in matched_fields)
        return score, matched_terms, field_ids

    def batch(
        self,
        profiles: Iterable[TelemetrySourceProfile],
        requirements: Iterable[dict[str, Any]],
    ) -> RetrievalResult:
        all_profiles = tuple(profiles)
        by_relation: dict[str, tuple[TelemetrySourceProfile, ...]] = {}
        batches_by_relation: dict[str, tuple[tuple[TelemetrySourceProfile, ...], ...]] = {}
        candidate_map: dict[str, tuple[SourceCandidate, ...]] = {}
        audit: list[dict[str, Any]] = []

        for raw_requirement in requirements:
            requirement = dict(raw_requirement)
            relation = str(requirement.get("relation", "")).strip().casefold()
            if not relation:
                continue
            terms = self._requirement_terms(requirement)
            ranked: list[tuple[float, tuple[str, ...], tuple[str, ...], TelemetrySourceProfile]] = []
            for profile in all_profiles:
                score, matched_terms, matched_fields = self._score(profile, terms)
                ranked.append((score, matched_terms, matched_fields, profile))
            ranked.sort(key=lambda item: (-item[0], item[3].source_id))

            candidates: list[SourceCandidate] = []
            ordered_profiles: list[TelemetrySourceProfile] = []
            for rank, (score, matched_terms, matched_fields, profile) in enumerate(ranked, start=1):
                candidates.append(SourceCandidate(
                    relation=relation,
                    source_id=profile.source_id,
                    score=score,
                    matched_terms=matched_terms,
                    matched_field_ids=matched_fields,
                    rank=rank,
                    low_confidence=not bool(matched_terms),
                ))
                matching_ids = set(matched_fields)
                ordered_fields = list(profile.fields)
                ordered_fields.sort(key=lambda field: (
                    0 if field.field_id in matching_ids else 1,
                    field.name.casefold(),
                    field.field_id,
                ))
                ordered_profiles.append(replace(profile, fields=tuple(ordered_fields)))

            batches: list[tuple[TelemetrySourceProfile, ...]] = []
            current: list[TelemetrySourceProfile] = []
            for profile in ordered_profiles:
                fields = list(profile.fields) or [None]
                for start in range(0, len(fields), self.max_fields_per_source_per_batch):
                    field_chunk = fields[start:start + self.max_fields_per_source_per_batch]
                    fragment = replace(
                        profile,
                        fields=tuple(field for field in field_chunk if field is not None),
                    )
                    if len(current) >= self.max_profiles_per_batch:
                        batches.append(tuple(current))
                        current = []
                    current.append(fragment)
            if current:
                batches.append(tuple(current))

            by_relation[relation] = tuple(ordered_profiles)
            batches_by_relation[relation] = tuple(batches)
            candidate_map[relation] = tuple(candidates)
            audit.append({
                "relation": relation,
                "query_terms": sorted(terms),
                "profile_count": len(all_profiles),
                "candidate_count": len(candidates),
                "candidates": [candidate.to_dict() for candidate in candidates],
                "selected_source_ids": [candidate.source_id for candidate in candidates],
                "source_coverage": {
                    "discovered": len(all_profiles),
                    "scheduled": len({profile.source_id for profile in ordered_profiles}),
                    "complete": len(ordered_profiles) == len(all_profiles),
                },
                "field_coverage": {
                    "discovered": sum(len(profile.fields) for profile in all_profiles),
                    "scheduled": sum(len(profile.fields) for profile in ordered_profiles),
                    "complete": sum(len(profile.fields) for profile in ordered_profiles)
                    == sum(len(profile.fields) for profile in all_profiles),
                },
                "batch_count": len(batches),
                "max_profiles_per_batch": self.max_profiles_per_batch,
                "max_fields_per_source_per_batch": self.max_fields_per_source_per_batch,
                "ordering_only": True,
            })

        return RetrievalResult(
            profiles_by_relation=by_relation,
            batches_by_relation=batches_by_relation,
            candidates_by_relation=candidate_map,
            audit=audit,
        )

    # Compatibility method for callers outside the engine. It now performs
    # exhaustive batching and never Top-K selection.
    retrieve = batch


# Backwards-compatible import name. It deliberately points to the exhaustive
# implementation and no longer exposes source-count selection parameters.
CapabilityRetriever = CapabilityBatcher


__all__ = ["CapabilityBatcher", "CapabilityRetriever", "RetrievalResult", "SourceCandidate"]
