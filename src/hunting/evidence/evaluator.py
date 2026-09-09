"""Evidence Evaluator — hypothesis compatibility and bounded batch evaluation.

Enforces:
- Deterministic compatibility checking of EvidenceCards against Hypotheses.
        - Ambiguous or novel cards are evaluated in micro-batches (max 1 LLM call per epoch).
- LLM receives card summaries/deltas, NEVER the full raw ledger.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import defaultdict
from enum import Enum
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


class ParseStatus(str, Enum):
    SUCCESS = "SUCCESS"
    INVALID_JSON = "INVALID_JSON"
    SCHEMA_REJECTED = "SCHEMA_REJECTED"
    TIMEOUT = "TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"

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

    def generate_deterministic_explanation(
        self,
        cards: list[EvidenceCard],
        hypotheses: list[Hypothesis],
        answer_spec: dict[str, Any] | None = None,
        question: str = "",
    ) -> dict[str, Any]:
        """Generate deterministic, evidence-grounded explanation when LLM is unavailable or times out."""
        spec = answer_spec or {}
        answer_type = str(spec.get("answer_type", "value")).lower()

        # v6: artifact_name from answer_spec or card data — no keyword scanning
        artifact_name = str(spec.get("artifact_name", "") or spec.get("object_name", "")).strip()
        artifact_host = ""
        has_artifact = False
        observed_versions: list[str] = []
        matching_card_ids: list[str] = []
        matching_obs_ids: list[str] = []

        name_lower = artifact_name.lower() if artifact_name else ""
        for c in cards:
            hosts = [str(h) for h in c.entity_summary.get("hosts", []) if str(h).strip()]
            if hosts and not artifact_host:
                artifact_host = hosts[0]
            fps = [str(x) for x in c.field_summary.get("file_paths", [])]
            imgs = [str(x) for x in c.field_summary.get("process_names", []) or c.field_summary.get("images", [])]
            vers = [str(x) for x in c.field_summary.get("software_versions", []) if str(x).strip()]
            if vers:
                observed_versions.extend(vers)
            has_name_match = name_lower and any(name_lower in s.lower() for s in (fps + imgs + [c.summary]))
            if c.fact_type in ("process_execution", "software_artifact", "file_modification") or has_name_match:
                has_artifact = True
                matching_card_ids.append(c.id)
                matching_obs_ids.extend(c.representative_observation_ids)
                # Derive artifact name from first matching file path if still unknown
                if not artifact_name and fps:
                    import os
                    artifact_name = os.path.basename(fps[0])


        evaluations: list[dict[str, Any]] = []
        compatibility: dict[str, list[str]] = {}
        for c in cards:
            c_interp = c.why_it_matters or f"Observed {c.fact_type} telemetry on {artifact_host or 'host'}."
            supp_h = [h.id for h in hypotheses if h.hypothesis_class != "benign_baseline"]
            evaluations.append({
                "card_id": c.id,
                "interpretation": c_interp,
                "supporting_hypotheses": supp_h,
                "contradicting_hypotheses": [],
                "confidence": 0.85 if c.confidence == "HIGH" else 0.65,
                "observation_ids": c.representative_observation_ids,
            })
            compatibility[c.id] = supp_h

        if has_artifact:
            if observed_versions:
                v_str = ", ".join(sorted(list(set(observed_versions))))
                expl = f"Deterministic explanation: {artifact_name or 'Artifact'} process evidence was found on {artifact_host or 'target host'} with software version {v_str}."
                ans_status = "ANSWERED"
                ans_val = observed_versions[0]
            else:
                expl = f"Deterministic explanation: {artifact_name or 'Artifact'} process evidence was found on {artifact_host or 'target host'}. No populated {answer_type.replace('_', ' ')} field was observed."
                ans_status = "PARTIALLY_SUPPORTED"
                ans_val = None
        elif cards:
            expl = f"Deterministic explanation: {len(cards)} telemetry evidence cards collected, but no definitive artifact matching the hypothesis was confirmed."
            ans_status = "INCONCLUSIVE"
            ans_val = None
        else:
            expl = "Deterministic explanation: No telemetry events matching the requested criteria were observed."
            ans_status = "NOT_FOUND"
            ans_val = None

        return {
            "explanation": expl,
            "answer": {
                "status": ans_status,
                "value": ans_val,
                "explanation": expl,
                "card_ids": matching_card_ids,
                "observation_ids": matching_obs_ids[:5],
            },
            "evaluations": evaluations,
            "missing_evidence": [answer_type] if (has_artifact and not observed_versions) else [],
            "compatibility": compatibility,
        }

    def analyze_batch(
        self,
        cards: list[EvidenceCard],
        hypotheses: list[Hypothesis],
        question: str = "",
        answer_spec: dict[str, Any] | None = None,
        max_cards: int = 40,
        identity_resolved: bool = True,
        queries_complete: bool = True,
        identity_required: bool = False,
        subgraph: Any | None = None,
    ) -> dict[str, Any]:
        """Ask the LLM to interpret a bounded card batch and propose an answer.

        The LLM may explain semantics, identify supporting/contradicting cards,
        and propose a cited answer. It cannot create observations or introduce
        IDs: every card, hypothesis, and observation ID is filtered against the
        local state before the result is returned.
        """
        if not cards:
            return {
                "parse_status": "EMPTY",
                "error_message": "No cards provided",
                "answer": {},
                "evaluations": [],
                "missing_evidence": [],
                "compatibility": {},
            }

        if self.llm_caller is None or self.llm_calls_made >= 1:
            det_res = self.generate_deterministic_explanation(cards, hypotheses, answer_spec, question)
            return {
                "parse_status": "OFFLINE_DETERMINISTIC",
                "answer": det_res["answer"],
                "evaluations": det_res["evaluations"],
                "missing_evidence": det_res["missing_evidence"],
                "compatibility": det_res["compatibility"],
                "deterministic_explanation": det_res["explanation"],
            }

        # Filter out noise cards (ad networks, web trackers, CDNs)
        noise_domains = (
            "cnn.com", "doubleclick", "rubiconproject", "outbrain", "adnxs",
            "fwmrm.net", "krxd.net", "gigya.com", "doubleverify", "sharethrough",
            "akamai", "afy11.net", "tapad.com", "wayfair.com", "chartbeat.net",
            "symcd.com", "microsoft.com",
        )

        def _is_noise_card(c: EvidenceCard) -> bool:
            f_str = str(c.field_summary).lower()
            return any(d in f_str for d in noise_domains)

        subgraph_provenance = ""
        if subgraph is not None:
            subgraph_obs = set(getattr(subgraph, "cited_observation_ids", []))
            causal_cards = [
                c for c in cards
                if c.id.startswith("card-edge-")
                or any(oid in subgraph_obs for oid in c.representative_observation_ids)
            ]
            other_clean_cards = [c for c in cards if c not in causal_cards and not _is_noise_card(c)]
            selected_cards = (causal_cards + sorted(other_clean_cards, key=lambda c: (-c.count, c.id)))[:max_cards]
            if hasattr(subgraph, "render_provenance_path"):
                subgraph_provenance = (
                    f"Proven Causal Provenance Subgraph:\n{subgraph.render_provenance_path()}\n\n"
                    "CRITICAL: Restrict your explanation, findings, and answer strictly to this verified subgraph and its cited observations.\n\n"
                )
        else:
            clean_cards = [c for c in cards if not _is_noise_card(c)] or cards
            selected_cards = sorted(clean_cards, key=lambda card: (-card.count, card.id))[:max_cards]

        valid_card_ids = {card.id for card in selected_cards}
        valid_hypothesis_ids = {hypothesis.id for hypothesis in hypotheses}
        valid_observation_ids = {
            observation_id
            for card in selected_cards
            for observation_id in card.representative_observation_ids
        }
        if subgraph is not None and getattr(subgraph, "cited_observation_ids", None):
            valid_observation_ids.update(subgraph.cited_observation_ids)

        card_context = [
            {
                "card_id": card.id,
                "fact_type": card.fact_type,
                "summary": card.summary,
                "count": card.count,
                "confidence": card.confidence,
                "entity_summary": card.entity_summary,
                "time_summary": card.time_summary,
                "field_summary": {
                    key: value
                    for key, value in card.field_summary.items()
                    if key not in {"raw", "raw_log", "payload", "_raw", "_hidden", "Message"}
                },
                "relations": card.relations,
                "query_ids": card.query_ids,
                "representative_observation_ids": card.representative_observation_ids[:3],
                "completeness": card.completeness,
            }
            for card in selected_cards
        ]
        hypothesis_context = [{"id": h.id, "statement": h.statement} for h in hypotheses]
        prompt = (
            "You are the evidence analysis layer of a threat-hunting agent.\n"
            "Analyze the bounded evidence cards against the question and hypotheses.\n"
            f"{subgraph_provenance}"
            "You may explain what the evidence means, propose an answer, identify contradictions, "
            "and list missing evidence. You must cite existing card_ids and observation_ids only.\n"
            "Do not invent events, fields, IDs, queries, entities, or causal links not supported by the cards.\n"
            "Treat the user claim as unverified. A web request alone does not prove compromise.\n\n"
            f"Question: {question}\n"
            f"Answer specification: {json.dumps(answer_spec or {}, ensure_ascii=False)}\n"
            f"Hypotheses: {json.dumps(hypothesis_context, ensure_ascii=False)}\n"
            f"Evidence cards: {json.dumps(card_context, ensure_ascii=False)}\n\n"
            "Return strict JSON with this shape:\n"
            "{\n"
            '  "answer": {"status": "ANSWERED" | "NOT_FOUND" | "INCONCLUSIVE", "value": null, "explanation": "", "card_ids": [], "observation_ids": []},\n'
            '  "evaluations": [{"card_id": "", "interpretation": "", "supporting_hypotheses": [], "contradicting_hypotheses": [], "confidence": 0.0, "answer_candidates": [], "missing_evidence": [], "observation_ids": []}],\n'
            '  "missing_evidence": [],\n'
            '  "next_action": "STOP_RESOLVED" | "TEST" | "EXPAND" | "INCONCLUSIVE"\n'
            "}"
        )

        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
        t0 = time.perf_counter()
        raw_response = ""
        parse_status = ParseStatus.SUCCESS
        err_msg = ""
        parsed: dict[str, Any] = {}

        self.llm_calls_made += 1
        try:
            raw_response = self.llm_caller(prompt)
            cleaned = raw_response.strip()
            if "```json" in cleaned:
                start = cleaned.find("```json") + 7
                end = cleaned.find("```", start)
                cleaned = cleaned[start:end].strip() if end != -1 else cleaned[start:].strip()
            elif "```" in cleaned:
                start = cleaned.find("```") + 3
                end = cleaned.find("```", start)
                cleaned = cleaned[start:end].strip() if end != -1 else cleaned[start:].strip()

            if not cleaned.startswith("{") and "{" in cleaned and "}" in cleaned:
                start = cleaned.find("{")
                end = cleaned.rfind("}") + 1
                cleaned = cleaned[start:end].strip()

            parsed = json.loads(cleaned)
            if not isinstance(parsed, dict):
                parse_status = ParseStatus.SCHEMA_REJECTED
                err_msg = "LLM response is not a JSON object"
        except json.JSONDecodeError as jde:
            parse_status = ParseStatus.INVALID_JSON
            err_msg = f"Failed to decode JSON: {jde}"
            logger.warning("LLM evidence analysis invalid JSON: %s", jde)
        except Exception as exc:
            err_str = str(exc).lower()
            if "timeout" in err_str or "timed out" in err_str:
                parse_status = ParseStatus.TIMEOUT
            else:
                parse_status = ParseStatus.PROVIDER_ERROR
            err_msg = str(exc)
            logger.warning("LLM evidence analysis call failed: %s", exc)

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        response_hash = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()[:16] if raw_response else ""

        if parse_status != ParseStatus.SUCCESS:
            logger.info(
                "[LLM_OBSERVABILITY] phase=evaluator prompt_hash=%s selected_operation=evaluate_cards search_terms=[] validation_result=%s",
                prompt_hash,
                parse_status.value,
            )
            det_result = self.generate_deterministic_explanation(
                selected_cards,
                hypotheses,
                answer_spec=answer_spec,
                question=question,
            )
            return {
                "parse_status": parse_status.value,
                "prompt_hash": prompt_hash,
                "response_hash": response_hash,
                "latency_ms": elapsed_ms,
                "error_message": err_msg,
                "answer": det_result["answer"],
                "evaluations": det_result["evaluations"],
                "missing_evidence": det_result["missing_evidence"],
                "compatibility": det_result["compatibility"],
                "deterministic_explanation": det_result["explanation"],
                "explanation_unavailable": False,
            }

        compatibility: dict[str, list[str]] = {}
        evaluations: list[dict[str, Any]] = []
        for item in parsed.get("evaluations", []):
            if not isinstance(item, dict):
                continue
            card_id = str(item.get("card_id", "")).strip()
            if card_id not in valid_card_ids:
                continue
            supporting = [
                str(value).strip()
                for value in item.get("supporting_hypotheses", [])
                if str(value).strip() in valid_hypothesis_ids
            ]
            contradicting = [
                str(value).strip()
                for value in item.get("contradicting_hypotheses", [])
                if str(value).strip() in valid_hypothesis_ids
            ]
            cited_observations = [
                str(value).strip()
                for value in item.get("observation_ids", [])
                if str(value).strip() in valid_observation_ids
            ]
            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0
            evaluation = {
                "card_id": card_id,
                "interpretation": str(item.get("interpretation", "")).strip(),
                "supporting_hypotheses": supporting,
                "contradicting_hypotheses": contradicting,
                "confidence": confidence,
                "answer_candidates": [str(value).strip() for value in item.get("answer_candidates", []) if str(value).strip()],
                "missing_evidence": [str(value).strip() for value in item.get("missing_evidence", []) if str(value).strip()],
                "observation_ids": cited_observations,
            }
            evaluations.append(evaluation)
            if supporting:
                compatibility[card_id] = supporting

        answer = parsed.get("answer") if isinstance(parsed.get("answer"), dict) else {}
        answer_card_ids = [str(value).strip() for value in answer.get("card_ids", []) if str(value).strip() in valid_card_ids]
        answer_observation_ids = [
            str(value).strip()
            for value in answer.get("observation_ids", [])
            if str(value).strip() in valid_observation_ids
        ]
        answer_status = str(answer.get("status", "INCONCLUSIVE")).upper()
        if answer_status not in {"ANSWERED", "NOT_FOUND", "INCONCLUSIVE"}:
            answer_status = "INCONCLUSIVE"
        validated_answer = {
            "status": answer_status,
            "value": answer.get("value"),
            "explanation": str(answer.get("explanation", "")).strip(),
            "card_ids": answer_card_ids,
            "observation_ids": answer_observation_ids,
        }
        if answer_status == "ANSWERED" and not answer_card_ids:
            validated_answer["status"] = "INCONCLUSIVE"
            validated_answer["value"] = None

        if answer_status == "NOT_FOUND":
            if identity_required and not identity_resolved:
                validated_answer["status"] = "INCONCLUSIVE"
                validated_answer["reason"] = "IDENTITY_UNRESOLVED"
                validated_answer["explanation"] = "Cannot conclude NOT_FOUND because subject identity was not resolved to an endpoint or client IP."
            elif not queries_complete:
                validated_answer["status"] = "INCONCLUSIVE"
                validated_answer["reason"] = "COVERAGE_INCOMPLETE"
                validated_answer["explanation"] = "Cannot conclude NOT_FOUND because one or more telemetry queries were incomplete or truncated."

        res = {
            "parse_status": ParseStatus.SUCCESS.value,
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "latency_ms": elapsed_ms,
            "error_message": "",
            "answer": validated_answer,
            "evaluations": evaluations,
            "missing_evidence": [str(value).strip() for value in parsed.get("missing_evidence", []) if str(value).strip()],
            "next_action": str(parsed.get("next_action", "INCONCLUSIVE")).strip(),
            "compatibility": compatibility,
            "cards_truncated": len(cards) > max_cards,
            "explanation_unavailable": False,
        }
        logger.info(
            "[LLM_OBSERVABILITY] phase=evaluator prompt_hash=%s selected_operation=evaluate_cards search_terms=[] validation_result=VALID answer_status=%s",
            prompt_hash,
            validated_answer.get("status"),
        )
        return res

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
