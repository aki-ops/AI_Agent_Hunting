"""Evidence Evaluator — hypothesis compatibility and bounded batch evaluation.

Enforces:
- Deterministic compatibility checking of EvidenceCards against Hypotheses.
        - Ambiguous or novel cards are evaluated in micro-batches (max 1 LLM call per epoch).
- LLM receives card summaries/deltas, NEVER the full raw ledger.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, Callable

from hunting.contracts.entities import AnyEntity
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    FieldOp,
    FieldPredicate,
)
from hunting.contracts.hunt import EvidenceAssessment, EvidenceCard, Hypothesis
from hunting.controller.reasoning import evaluate_field_predicate

logger = logging.getLogger(__name__)

REQ_FACT_MAP: dict[EvidenceRequirement, set[str]] = {
    EvidenceRequirement.PROCESS_ANCESTRY: {"process_execution"},
    EvidenceRequirement.AUTHENTICATION_ACTIVITY: {"authentication_activity"},
    EvidenceRequirement.NETWORK_CONNECTION: {"network_connection"},
    EvidenceRequirement.FILE_MODIFICATION: {"file_modification"},
    EvidenceRequirement.DNS_ACTIVITY: {"dns_activity"},
    EvidenceRequirement.PERSISTENCE_CHANGE: {"persistence_change"},
    EvidenceRequirement.WEB_REQUEST: {"web_request", "web_activity", "http_traffic"},
    EvidenceRequirement.SCOPE_RECORDS: {
        "process_execution",
        "authentication_activity",
        "network_connection",
        "file_modification",
        "dns_activity",
        "persistence_change",
        "web_request",
        "web_activity",
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
                ent_root = ent_lower[4:] if ent_lower.startswith("www.") else ent_lower
                all_card_entities = [
                    str(e).strip().lower()
                    for ent_list in card.entity_summary.values()
                    for e in (ent_list if isinstance(ent_list, list) else [ent_list])
                ]
                if all_card_entities and not (ent_lower in all_card_entities or ent_root in all_card_entities):
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
                    # No expectation means there is no typed semantic basis for
                    # deterministic attribution. It must remain ambiguous and
                    # go through the bounded batch evaluator below.

                if matched_hypo_ids:
                    compatibility[card.id] = matched_hypo_ids
                else:
                    ambiguous_cards.append(card)
        else:
            ambiguous_cards.extend(cards)

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

        valid_card_ids = {c.id for c in cards}
        valid_hypo_ids = {h.id for h in hypotheses}
        validated_compat: dict[str, list[str]] = {c.id: [] for c in cards}

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
                # Check if wrapped in "evaluations" list
                if "evaluations" in res and isinstance(res["evaluations"], list):
                    for item in res["evaluations"]:
                        if isinstance(item, dict) and "card_id" in item:
                            cid = str(item["card_id"]).strip()
                            hyps = item.get("compatible_hypotheses") or item.get("hypotheses") or []
                            if not hyps and "hypothesis_evaluations" in item:
                                hyps = [
                                    he.get("hypothesis_id")
                                    for he in item["hypothesis_evaluations"]
                                    if isinstance(he, dict) and he.get("hypothesis_id")
                                ]
                            if cid in valid_card_ids and isinstance(hyps, list):
                                validated_compat[cid] = [
                                    str(h_id).strip()
                                    for h_id in hyps
                                    if str(h_id).strip() in valid_hypo_ids
                                ]
                else:
                    for k, v in res.items():
                        k_str = str(k).strip()
                        if k_str in valid_card_ids and isinstance(v, list):
                            # Filter out hallucinated hypothesis IDs
                            filtered_hypos = [str(h_id).strip() for h_id in v if str(h_id).strip() in valid_hypo_ids]
                            validated_compat[k_str] = filtered_hypos
                return validated_compat
        except Exception as e:
            logger.debug(f"LLM evidence evaluation parse error: {e}")

        return validated_compat

    def evaluate_evidence_advisory(
        self,
        card: EvidenceCard,
        hypotheses: list[Hypothesis],
        expectations: list[Expectation] | None = None,
    ) -> EvidenceAssessment:
        """Produce advisory semantic assessment for an EvidenceCard."""
        expectations_by_hypothesis: dict[str, list[Expectation]] = defaultdict(list)
        for expectation in expectations or []:
            expectations_by_hypothesis[expectation.owner_explanation_id].append(expectation)

        # Advisory output is grounded only in typed expectations. With no
        # expectation, the correct result is unknown—not a keyword guess.
        compatible = [
            h.id
            for h in hypotheses
            if any(
                self.evaluate_card_against_expectation(card, expectation)
                for expectation in expectations_by_hypothesis.get(h.id, [])
            )
        ]
        confidence = 0.85 if compatible else 0.0
        if compatible:
            reason = f"EvidenceCard fact_type '{card.fact_type}' matches {len(compatible)} hypotheses"
        elif expectations:
            reason = "EvidenceCard did not satisfy any typed expectation"
        else:
            reason = "No typed expectation was available; attribution remains unknown"
        missing = [] if compatible else [h.id for h in hypotheses]
        source_refs = getattr(card, "source_refs", None)
        if source_refs is None:
            source_refs = list(getattr(card, "representative_observation_ids", []))
        else:
            source_refs = list(source_refs)

        return EvidenceAssessment(
            card_id=card.id,
            compatible_hypotheses=compatible,
            confidence=confidence,
            reason=reason,
            missing_evidence=missing,
            source_refs=source_refs,
        )


__all__ = ["EvidenceEvaluator", "REQ_FACT_MAP"]
