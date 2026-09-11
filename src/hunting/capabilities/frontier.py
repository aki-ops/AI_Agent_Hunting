"""5-Stage Progressive Frontier for Telemetry Capability Discovery.

Component of Phase 3 (Progressive Frontier):
- F0 Certified -> F1 Metadata -> F2 Adjacent -> F3 Bounded Profiling -> F4 Approved Exhaustive.
- Shortlist NEVER proves absence: unexamined_source_ids tracked in CoverageManifest.
- Bounded token pack: 25 sources / 617 fields never appear in a single prompt.
- Field-first selection: Misleading source name with correct fields is selected;
  deceptive source name with wrong fields is rejected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from hunting.capabilities.catalog_index import CatalogIndex
from hunting.capabilities.source_card_store import SourceCard, SourceCardStore


class FrontierStage(str, Enum):
    F0_CERTIFIED = "F0_CERTIFIED"
    F1_METADATA = "F1_METADATA"
    F2_ADJACENT = "F2_ADJACENT"
    F3_BOUNDED_PROFILING = "F3_BOUNDED_PROFILING"
    F4_APPROVED_EXHAUSTIVE = "F4_APPROVED_EXHAUSTIVE"


@dataclass
class CoverageManifest:
    """Explicit accounting of source coverage gaps."""
    total_sources: int
    considered_source_ids: list[str] = field(default_factory=list)
    examined_source_ids: list[str] = field(default_factory=list)
    rejected_source_ids: dict[str, str] = field(default_factory=dict)
    unexamined_source_ids: list[str] = field(default_factory=list)
    stage_audit: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_coverage_gaps(self) -> bool:
        return len(self.unexamined_source_ids) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_sources": self.total_sources,
            "considered_source_ids": list(self.considered_source_ids),
            "examined_source_ids": list(self.examined_source_ids),
            "rejected_source_ids": dict(self.rejected_source_ids),
            "unexamined_source_ids": list(self.unexamined_source_ids),
            "stage_audit": list(self.stage_audit),
        }


class ProgressiveFrontier:
    """Executes the 5-stage progressive expansion for an unresolved goal."""

    def __init__(
        self,
        card_store: SourceCardStore,
        catalog_index: CatalogIndex,
        *,
        max_batch_cards: int = 8,
        max_batch_fields: int = 32,
    ) -> None:
        self.card_store = card_store
        self.catalog_index = catalog_index
        self.max_batch_cards = max_batch_cards
        self.max_batch_fields = max_batch_fields

    def pack_cards_for_prompt(
        self,
        cards: Iterable[SourceCard],
    ) -> list[list[dict[str, Any]]]:
        """Pack SourceCards into strictly bounded token batches for LLM consumption.

        INVARIANT: 25 sources / 617 fields never appear in a single prompt.
        """
        batches: list[list[dict[str, Any]]] = []
        current_batch: list[dict[str, Any]] = []

        for card in cards:
            if len(current_batch) >= self.max_batch_cards:
                batches.append(current_batch)
                current_batch = []
            current_batch.append(card.compact_summary(max_fields=self.max_batch_fields))

        if current_batch:
            batches.append(current_batch)
        return batches

    def expand(
        self,
        *,
        relation: str,
        required_roles: tuple[str, ...] = (),
        search_terms: tuple[str, ...] = (),
        approved_contracts: tuple[str, ...] = (),
        allow_exhaustive: bool = False,
    ) -> tuple[list[SourceCard], CoverageManifest]:
        """Progressively discover candidate sources through stages F0 to F4."""
        all_source_ids = set(self.card_store.all_source_ids())
        considered: set[str] = set()
        examined: set[str] = set()
        rejected: dict[str, str] = {}
        stage_audit: list[dict[str, Any]] = []

        selected_cards: list[SourceCard] = []

        # -------------------------------------------------------------
        # Stage F0: Certified Frontier (pre-approved proof contracts)
        # -------------------------------------------------------------
        f0_cards: list[SourceCard] = []
        for sid in sorted(all_source_ids):
            card = self.card_store.get_card(sid)
            if card is None:
                continue
            # If relation matches an approved proof contract and card has required roles
            if relation in approved_contracts:
                card_roles = {r.casefold() for r in card.field_roles.values()}
                for f in card.fields:
                    card_roles.update(r.casefold() for r in f.field_roles)
                if all(r.casefold() in card_roles for r in required_roles):
                    f0_cards.append(card)
                    considered.add(sid)
                    examined.add(sid)

        stage_audit.append({
            "stage": FrontierStage.F0_CERTIFIED.value,
            "discovered_sources": [c.source_id for c in f0_cards],
            "count": len(f0_cards),
        })
        selected_cards.extend(f0_cards)

        # -------------------------------------------------------------
        # Stage F1: Metadata Frontier (lexical + semantic index)
        # -------------------------------------------------------------
        scored = self.catalog_index.search(
            relation=relation,
            required_roles=required_roles,
            search_terms=search_terms,
            approved_contracts=approved_contracts,
        )

        f1_cards: list[SourceCard] = []
        for cand in scored:
            considered.add(cand.source_id)
            if cand.source_id in examined:
                continue

            if cand.above_threshold:
                # Candidate has matching fields/roles above threshold
                f1_cards.append(cand.card)
                examined.add(cand.source_id)
            else:
                if cand.rejection_reasons:
                    rejected[cand.source_id] = "; ".join(cand.rejection_reasons)
                else:
                    rejected[cand.source_id] = f"Below score threshold (score={cand.total_score:.4f})"

        stage_audit.append({
            "stage": FrontierStage.F1_METADATA.value,
            "discovered_sources": [c.source_id for c in f1_cards],
            "count": len(f1_cards),
        })
        selected_cards.extend(f1_cards)

        # -------------------------------------------------------------
        # Stage F2: Adjacent Expansion (partition keys, join keys, neighbors)
        # -------------------------------------------------------------
        f2_cards: list[SourceCard] = []
        currently_examined = list(examined)
        for sid in currently_examined:
            card = self.card_store.get_card(sid)
            if not card:
                continue
            for adj_id in card.adjacent_source_ids:
                if adj_id in all_source_ids and adj_id not in examined:
                    adj_card = self.card_store.get_card(adj_id)
                    if adj_card:
                        considered.add(adj_id)
                        examined.add(adj_id)
                        f2_cards.append(adj_card)

        stage_audit.append({
            "stage": FrontierStage.F2_ADJACENT.value,
            "discovered_sources": [c.source_id for c in f2_cards],
            "count": len(f2_cards),
        })
        selected_cards.extend(f2_cards)

        # -------------------------------------------------------------
        # Stage F3: Bounded Profiling (bounded batch for dynamic LLM)
        # -------------------------------------------------------------
        f3_cards: list[SourceCard] = []
        if not selected_cards:
            remaining_candidates = [
                cand for cand in scored
                if cand.source_id not in examined and cand.source_id not in rejected
            ]
            for cand in remaining_candidates[: self.max_batch_cards]:
                f3_cards.append(cand.card)
                examined.add(cand.source_id)
                considered.add(cand.source_id)

        stage_audit.append({
            "stage": FrontierStage.F3_BOUNDED_PROFILING.value,
            "discovered_sources": [c.source_id for c in f3_cards],
            "count": len(f3_cards),
        })
        selected_cards.extend(f3_cards)

        # -------------------------------------------------------------
        # Stage F4: Approved Exhaustive (only if authorized)
        # -------------------------------------------------------------
        f4_cards: list[SourceCard] = []
        if allow_exhaustive:
            for sid in sorted(all_source_ids):
                if sid not in examined:
                    card = self.card_store.get_card(sid)
                    if card:
                        f4_cards.append(card)
                        examined.add(sid)
                        considered.add(sid)

            stage_audit.append({
                "stage": FrontierStage.F4_APPROVED_EXHAUSTIVE.value,
                "discovered_sources": [c.source_id for c in f4_cards],
                "count": len(f4_cards),
            })
            selected_cards.extend(f4_cards)

        # Unexamined sources: Explicit coverage gaps
        unexamined = sorted(all_source_ids - examined)

        manifest = CoverageManifest(
            total_sources=len(all_source_ids),
            considered_source_ids=sorted(considered),
            examined_source_ids=sorted(examined),
            rejected_source_ids=rejected,
            unexamined_source_ids=unexamined,
            stage_audit=stage_audit,
        )

        return selected_cards, manifest


__all__ = [
    "FrontierStage",
    "CoverageManifest",
    "ProgressiveFrontier",
]
