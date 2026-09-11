"""Lexical and semantic indexing of SourceCard catalog.

Component of Phase 3 (Progressive Frontier):
- Scores affect ordering only; candidates are never discarded permanently based on rank alone.
- Multi-component transparent scoring function from 08 Master Plan:
  priority = contract_match + required_role_coverage + time_and_permission_fit
             + lexical_semantic_similarity + observed_joinability
             - estimated_scan_cost - ambiguity_penalty
- Full audit log of score components and thresholds for ablation.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from hunting.capabilities.source_card_store import SourceCard, SourceCardStore

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_STOPWORDS = {
    "a", "an", "and", "after", "associated", "be", "by", "determine",
    "establish", "find", "for", "from", "get", "identify", "in", "is",
    "of", "on", "the", "to", "with", "what",
}


def _tokenize(text: str) -> set[str]:
    expanded = _CAMEL_RE.sub(" ", str(text or "").casefold())
    return {
        token
        for token in _TOKEN_RE.findall(expanded.replace("_", " ").replace(":", " ").replace("-", " "))
        if len(token) > 1 and token not in _STOPWORDS
    }


@dataclass(frozen=True)
class ScoredSourceCandidate:
    """Scored candidate source with transparent score breakdown."""
    source_id: str
    card: SourceCard
    total_score: float
    score_components: dict[str, float]
    matched_terms: tuple[str, ...]
    matched_roles: tuple[str, ...]
    above_threshold: bool
    rejection_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "total_score": round(self.total_score, 4),
            "score_components": {k: round(v, 4) for k, v in self.score_components.items()},
            "matched_terms": list(self.matched_terms),
            "matched_roles": list(self.matched_roles),
            "above_threshold": self.above_threshold,
            "rejection_reasons": list(self.rejection_reasons),
        }


class CatalogIndex:
    """Indexes SourceCards and computes calibrated ordering scores."""

    def __init__(
        self,
        card_store: SourceCardStore,
        *,
        default_threshold: float = 0.25,
    ) -> None:
        self.card_store = card_store
        self.default_threshold = default_threshold

    def search(
        self,
        *,
        relation: str,
        required_roles: tuple[str, ...] = (),
        search_terms: tuple[str, ...] = (),
        approved_contracts: tuple[str, ...] = (),
        threshold: float | None = None,
    ) -> list[ScoredSourceCandidate]:
        """Score all SourceCards for a given relation and roles.

        INVARIANT: Scores affect ordering only. No candidate is removed;
        all registered sources are returned, ordered by priority score.
        """
        active_threshold = self.default_threshold if threshold is None else threshold
        req_tokens = set().union(*(_tokenize(t) for t in search_terms))
        req_tokens.update(_tokenize(relation))
        norm_roles = {r.casefold() for r in required_roles if str(r).strip()}

        candidates: list[ScoredSourceCandidate] = []

        for card in self.card_store.list_cards():
            score_components: dict[str, float] = {}
            matched_terms_set: set[str] = set()
            matched_roles_set: set[str] = set()
            rejections: list[str] = []

            # 1. Contract Match
            # If relation matches an approved proof contract or card field roles match
            contract_score = 0.0
            if relation in approved_contracts:
                contract_score += 1.0
            score_components["contract_match"] = contract_score

            # 2. Required Role Coverage (Evaluates actual field roles, NOT source name)
            role_score = 0.0
            card_roles = {r.casefold() for r in card.field_roles.values()}
            for f in card.fields:
                card_roles.update(r.casefold() for r in f.field_roles)

            if norm_roles:
                overlap_roles = norm_roles.intersection(card_roles)
                matched_roles_set.update(overlap_roles)
                role_score = len(overlap_roles) / len(norm_roles) * 2.0
                if len(overlap_roles) == 0:
                    rejections.append(f"Missing required roles: {sorted(norm_roles)}")
            else:
                role_score = 0.5  # Neutral default when no roles specified
            score_components["required_role_coverage"] = role_score

            # 3. Time & Scope Fit
            time_fit = 0.5 if card.event_count > 0 else 0.0
            score_components["time_and_permission_fit"] = time_fit

            # 4. Lexical Semantic Similarity on FIELDS & SAMPLES (Field-first, not name-first)
            field_tokens: set[str] = set()
            for f in card.fields:
                field_tokens.update(_tokenize(f.name))
                for s in f.sample_values:
                    field_tokens.update(_tokenize(str(s)))

            term_overlap = req_tokens.intersection(field_tokens)
            matched_terms_set.update(term_overlap)
            lexical_score = (len(term_overlap) / max(len(req_tokens), 1)) * 1.5
            score_components["lexical_semantic_similarity"] = lexical_score

            # 5. Observed Joinability
            join_keys = {"host", "user", "account", "src_ip", "dest_ip", "process_id"}
            has_join = bool(card.field_names.intersection(join_keys))
            join_score = 0.3 if has_join else 0.0
            score_components["observed_joinability"] = join_score

            # 6. Estimated Scan Cost Penalty
            count = max(card.event_count, 1)
            cost_penalty = (math.log10(count) / 10.0) * 0.2
            score_components["estimated_scan_cost"] = -cost_penalty

            # 7. Ambiguity Penalty
            ambiguity_penalty = 0.0
            if norm_roles and len(matched_roles_set) == 0:
                ambiguity_penalty = 0.5
            score_components["ambiguity_penalty"] = -ambiguity_penalty

            total = (
                score_components["contract_match"]
                + score_components["required_role_coverage"]
                + score_components["time_and_permission_fit"]
                + score_components["lexical_semantic_similarity"]
                + score_components["observed_joinability"]
                + score_components["estimated_scan_cost"]
                + score_components["ambiguity_penalty"]
            )

            above = (total >= active_threshold) and (len(rejections) == 0)
            candidates.append(
                ScoredSourceCandidate(
                    source_id=card.source_id,
                    card=card,
                    total_score=total,
                    score_components=score_components,
                    matched_terms=tuple(sorted(matched_terms_set)),
                    matched_roles=tuple(sorted(matched_roles_set)),
                    above_threshold=above,
                    rejection_reasons=tuple(rejections),
                )
            )

        # Sort descending by priority score
        candidates.sort(key=lambda c: c.total_score, reverse=True)
        return candidates


__all__ = [
    "ScoredSourceCandidate",
    "CatalogIndex",
]
