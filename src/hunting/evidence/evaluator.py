"""Evidence Evaluator — hypothesis compatibility and bounded batch evaluation.

Enforces:
- Deterministic compatibility checking of EvidenceCards against Hypotheses.
- Ambiguous or novel cards are evaluated in micro-batches (max 1 LLM call per epoch).
- LLM receives card summaries/deltas, NEVER the full raw ledger.
"""
from __future__ import annotations

import json
from typing import Callable

from hunting.contracts.hunt import EvidenceCard, Hypothesis


class EvidenceEvaluator:
    """Evaluates compatibility between compressed EvidenceCards and Hypotheses."""

    def __init__(self, llm_caller: Callable[[str], str] | None = None) -> None:
        self.llm_caller = llm_caller
        self.llm_calls_made = 0

    def evaluate_cards(
        self,
        cards: list[EvidenceCard],
        hypotheses: list[Hypothesis],
    ) -> dict[str, list[str]]:
        """Evaluate which hypotheses each EvidenceCard is compatible with.

        Returns mapping: card_id -> list of hypothesis_ids.
        """
        compatibility: dict[str, list[str]] = {}
        ambiguous_cards: list[EvidenceCard] = []

        # 1. Deterministic evaluation by fact type and keywords
        for card in cards:
            compatible_hypotheses: list[str] = []
            for h in hypotheses:
                h_text = h.statement.lower()
                # Check if card fact type or cmdlines match hypothesis context
                if card.fact_type == "process_execution" and ("process" in h_text or "exploit" in h_text or "powershell" in h_text):
                    compatible_hypotheses.append(h.id)
                elif card.fact_type == "network_connection" and ("c2" in h_text or "network" in h_text or "beacon" in h_text):
                    compatible_hypotheses.append(h.id)
                elif card.fact_type == "persistence_change" and ("task" in h_text or "persist" in h_text):
                    compatible_hypotheses.append(h.id)
                elif card.fact_type == "file_modification" and ("file" in h_text or "webshell" in h_text):
                    compatible_hypotheses.append(h.id)

            if compatible_hypotheses:
                compatibility[card.id] = compatible_hypotheses
            else:
                ambiguous_cards.append(card)

        # 2. Batch ambiguous cards together (NO per-event or per-card individual calls!)
        if ambiguous_cards and self.llm_caller is not None:
            if self.llm_calls_made < 1:
                batch_compat = self._batch_llm_evaluate(ambiguous_cards, hypotheses)
                compatibility.update(batch_compat)
            else:
                for card in ambiguous_cards:
                    compatibility[card.id] = []
        else:
            for card in ambiguous_cards:
                compatibility[card.id] = []

        return compatibility

    def _batch_llm_evaluate(
        self,
        cards: list[EvidenceCard],
        hypotheses: list[Hypothesis],
    ) -> dict[str, list[str]]:
        """Batch evaluate ambiguous cards in exactly 1 LLM call using card summaries."""
        self.llm_calls_made += 1

        card_summaries = [
            {
                "card_id": c.id,
                "fact_type": c.fact_type,
                "count": c.count,
                "entity_summary": c.entity_summary,
                "field_summary": c.field_summary,
            }
            for c in cards
        ]

        hypo_summaries = [{"id": h.id, "statement": h.statement} for h in hypotheses]

        prompt = (
            f"Evaluate compatibility of the following evidence cards against hypotheses.\n"
            f"Evidence Cards: {json.dumps(card_summaries)}\n"
            f"Hypotheses: {json.dumps(hypo_summaries)}\n\n"
            f"Respond with strict JSON mapping: {{\"card_id\": [\"hypo_id\", ...]}}"
        )

        raw_resp = self.llm_caller(prompt)
        try:
            res = json.loads(raw_resp)
            if isinstance(res, dict):
                return {k: list(v) for k, v in res.items()}
        except Exception:
            pass

        return {c.id: [] for c in cards}


__all__ = ["EvidenceEvaluator"]
