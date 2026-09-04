"""Evidence Evaluator — hypothesis compatibility and bounded batch evaluation.

Enforces:
- Deterministic compatibility checking of EvidenceCards against Hypotheses.
- Ambiguous or novel cards are evaluated in micro-batches (max 1 LLM call per epoch).
- LLM receives card summaries/deltas, NEVER the full raw ledger.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Callable

from hunting.contracts.entities import AnyEntity
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    FieldOp,
    FieldPredicate,
)
from hunting.contracts.hunt import EvidenceCard, Hypothesis
from hunting.controller.reasoning import evaluate_field_predicate

REQ_FACT_MAP: dict[EvidenceRequirement, set[str]] = {
    EvidenceRequirement.PROCESS_ANCESTRY: {"process_execution"},
    EvidenceRequirement.AUTHENTICATION_ACTIVITY: {"authentication_activity"},
    EvidenceRequirement.NETWORK_CONNECTION: {"network_connection"},
    EvidenceRequirement.FILE_MODIFICATION: {"file_modification"},
    EvidenceRequirement.DNS_ACTIVITY: {"dns_activity"},
    EvidenceRequirement.PERSISTENCE_CHANGE: {"persistence_change"},
    EvidenceRequirement.SCOPE_RECORDS: {
        "process_execution",
        "authentication_activity",
        "network_connection",
        "file_modification",
        "dns_activity",
        "persistence_change",
        "telemetry",
    },
}


class EvidenceEvaluator:
    """Evaluates compatibility between compressed EvidenceCards and Hypotheses."""

    def __init__(self, llm_caller: Callable[[str], str] | None = None) -> None:
        self.llm_caller = llm_caller
        self.llm_calls_made = 0

    def evaluate_card_against_expectation(
        self,
        card: EvidenceCard,
        expectation: Expectation,
    ) -> bool:
        """Deterministically evaluate whether an EvidenceCard satisfies an Expectation."""
        # 1. Fact type compatibility
        allowed_facts = REQ_FACT_MAP.get(expectation.evidence_requirement, {"telemetry"})
        if card.fact_type not in allowed_facts:
            return False

        # 2. Entity match (if expectation has a specific entity ref)
        if expectation.entity_ref and not isinstance(expectation.entity_ref, AnyEntity):
            ent_name = (
                getattr(expectation.entity_ref, "name", None)
                or getattr(expectation.entity_ref, "username", None)
                or getattr(expectation.entity_ref, "address", None)
            )
            if ent_name:
                ent_lower = str(ent_name).strip().lower()
                all_card_entities = [
                    str(e).strip().lower()
                    for ent_list in card.entity_summary.values()
                    for e in (ent_list if isinstance(ent_list, list) else [ent_list])
                ]
                if all_card_entities and ent_lower not in all_card_entities:
                    return False

        # 3. Field predicate match (if expectation has a field predicate)
        if expectation.field_predicate is not None:
            pred = expectation.field_predicate
            f_name = pred.field.lower()
            candidates: list[Any] = []

            for k, v in card.field_summary.items():
                if k.lower() in (f_name, f"{f_name}s", f_name.rstrip("s")):
                    if isinstance(v, list):
                        candidates.extend(v)
                    else:
                        candidates.append(v)

            if not candidates and card.relations:
                for rel in card.relations:
                    if f_name in rel:
                        candidates.append(rel[f_name])

            if pred.op == FieldOp.ABSENT:
                if any(evaluate_field_predicate(c, FieldPredicate(field=f_name, op=FieldOp.EXISTS)) for c in candidates):
                    return False
                return True

            if not candidates:
                return False

            if not any(evaluate_field_predicate(c, pred) for c in candidates):
                return False

        return True

    def _matches_heuristic(self, card: EvidenceCard, h: Hypothesis) -> bool:
        """Deterministic keyword heuristic for legacy/fallback evaluation."""
        h_text = h.statement.lower()
        if card.fact_type == "process_execution" and ("process" in h_text or "exploit" in h_text or "powershell" in h_text):
            return True
        elif card.fact_type == "network_connection" and ("c2" in h_text or "network" in h_text or "beacon" in h_text):
            return True
        elif card.fact_type == "persistence_change" and ("task" in h_text or "persist" in h_text):
            return True
        elif card.fact_type == "file_modification" and ("file" in h_text or "webshell" in h_text):
            return True
        elif card.fact_type == "authentication_activity" and ("auth" in h_text or "logon" in h_text):
            return True
        elif card.fact_type == "dns_activity" and ("dns" in h_text or "domain" in h_text):
            return True
        return False

    def evaluate_cards(
        self,
        cards: list[EvidenceCard],
        hypotheses: list[Hypothesis],
        expectations: list[Expectation] | None = None,
    ) -> dict[str, list[str]]:
        """Evaluate which hypotheses each EvidenceCard is compatible with.

        Returns mapping: card_id -> list of hypothesis_ids.
        """
        compatibility: dict[str, list[str]] = {}
        ambiguous_cards: list[EvidenceCard] = []

        if expectations:
            exp_by_owner: dict[str, list[Expectation]] = defaultdict(list)
            for exp in expectations:
                exp_by_owner[exp.owner_explanation_id].append(exp)

            for card in cards:
                matched_hypo_ids: list[str] = []
                for h in hypotheses:
                    h_exps = exp_by_owner.get(h.id, [])
                    if h_exps:
                        if any(self.evaluate_card_against_expectation(card, exp) for exp in h_exps):
                            matched_hypo_ids.append(h.id)
                    else:
                        if self._matches_heuristic(card, h):
                            matched_hypo_ids.append(h.id)

                if matched_hypo_ids:
                    compatibility[card.id] = matched_hypo_ids
                else:
                    ambiguous_cards.append(card)
        else:
            for card in cards:
                compatible_hypotheses = [h.id for h in hypotheses if self._matches_heuristic(card, h)]
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
        if self.llm_caller is None:
            return {c.id: [] for c in cards}
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
