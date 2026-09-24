"""OutcomeVerifier: Deterministic verification of OutcomeContract variants before terminal stop.

Operationalizes Gate G requirement G4:
- Dispatches to factual, hypothesis, or population verifiers.
- Emits OutcomeVerificationResult with verified, status, slot_values, citations, and diagnostics.
- Only when OutcomeVerifier verifies all required obligations/slots can STOP_ANSWERED or
  resolved hypothesis status be emitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.outcome import (
    FactualAnswerContract,
    HypothesisVerdictContract,
    OutcomeContract,
    OutcomeContractKind,
    PopulationDiscoveryContract,
)


@dataclass(frozen=True)
class OutcomeVerificationResult:
    """Immutable result of verifying an OutcomeContract."""

    verified: bool
    status: str
    """Canonical verdict: ANSWERED, REFUTED, NOT_FOUND, AMBIGUOUS, INCONCLUSIVE."""
    slot_values: dict[str, Any] = field(default_factory=dict)
    citations: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    missing_slots: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "status": self.status,
            "slot_values": dict(self.slot_values),
            "citations": list(self.citations),
            "diagnostics": list(self.diagnostics),
            "missing_slots": list(self.missing_slots),
        }


class OutcomeVerifier:
    """Central authority for verifying outcome contracts against executed goal state."""

    @classmethod
    def verify(
        cls,
        contract: OutcomeContract,
        bound_variables: dict[str, Any] | None = None,
        candidate_sets: dict[str, Any] | None = None,
        observations: list[Any] | None = None,
        cards: list[Any] | None = None,
        verified_goals: list[str] | None = None,
        coverage_complete: bool = True,
        proof_results: list[Any] | None = None,
    ) -> OutcomeVerificationResult:
        """Dispatch to the contract-specific verifier."""
        kind = getattr(contract, "contract_kind", OutcomeContractKind.FACTUAL_ANSWER.value)

        if kind == OutcomeContractKind.FACTUAL_ANSWER.value or isinstance(contract, FactualAnswerContract):
            return cls._verify_factual(
                contract=contract,  # type: ignore[arg-type]
                bound_variables=bound_variables or {},
                candidate_sets=candidate_sets or {},
                observations=observations or [],
                cards=cards or [],
                coverage_complete=coverage_complete,
                proof_results=proof_results or [],
            )
        elif kind == OutcomeContractKind.HYPOTHESIS_VERDICT.value or isinstance(contract, HypothesisVerdictContract):
            return cls._verify_hypothesis(
                contract=contract,  # type: ignore[arg-type]
                verified_goals=verified_goals or [],
                bound_variables=bound_variables or {},
                coverage_complete=coverage_complete,
            )
        elif kind == OutcomeContractKind.POPULATION_DISCOVERY.value or isinstance(contract, PopulationDiscoveryContract):
            return cls._verify_population(
                contract=contract,  # type: ignore[arg-type]
                candidate_sets=candidate_sets or {},
                coverage_complete=coverage_complete,
            )
        return OutcomeVerificationResult(
            verified=False,
            status="INCONCLUSIVE",
            diagnostics=(f"Unknown contract kind: {kind}",),
        )

    @classmethod
    def _verify_factual(
        cls,
        contract: FactualAnswerContract,
        bound_variables: dict[str, Any],
        candidate_sets: dict[str, Any],
        observations: list[Any],
        cards: list[Any],
        coverage_complete: bool,
        proof_results: list[Any] | None = None,
    ) -> OutcomeVerificationResult:
        slot_values: dict[str, Any] = {}
        missing_slots: list[str] = []
        diagnostics: list[str] = []
        citations: list[str] = []
        all_proven = True

        for slot in contract.slots:
            val = bound_variables.get(slot)
            # Check candidate sets if bound_variables doesn't have it
            if val in (None, "", "?") and slot in candidate_sets:
                cset = candidate_sets[slot]
                cands = getattr(cset, "candidates", ()) or ()
                active_cands = [
                    c for c in cands
                    if getattr(c, "status", "") in ("ACTIVE", "CANDIDATE", "VERIFIED", "VERIFIED_BINDING")
                ]
                if active_cands:
                    val = [c.value for c in active_cands] if len(active_cands) > 1 else active_cands[0].value

            if val in (None, "", "?", []):
                missing_slots.append(slot)
                diagnostics.append(f"Slot '{slot}' has no bound value")
                continue

            # Check cardinality
            if contract.is_singular(slot):
                if isinstance(val, (list, tuple, set)) and len(val) > 1:
                    proven_only = [
                        item for item in val
                        if cls._value_is_proof_backed(str(item), proof_results or [], candidate_sets.get(slot))
                    ]
                    if len(proven_only) == 1:
                        val = proven_only[0]
                    else:
                        diagnostics.append(f"Slot '{slot}' is singular but holds multiple candidates: {val}")
                        return OutcomeVerificationResult(
                            verified=False,
                            status="AMBIGUOUS",
                            slot_values={slot: list(val)},
                            missing_slots=tuple(missing_slots),
                            diagnostics=tuple(diagnostics),
                        )
                # Ranking is not a tie-break. Multiple verified bindings stay ambiguous.
                if slot in candidate_sets:
                    cset = candidate_sets[slot]
                    verified_cands = [
                        c for c in getattr(cset, "candidates", ())
                        if getattr(c, "status", "") in ("VERIFIED", "VERIFIED_BINDING")
                        or getattr(c, "is_verified_binding", False)
                    ]
                    if len(verified_cands) > 1:
                        diagnostics.append(f"Slot '{slot}' has multiple verified bindings requiring discrimination")
                        return OutcomeVerificationResult(
                            verified=False,
                            status="AMBIGUOUS",
                            slot_values={slot: val},
                            missing_slots=tuple(missing_slots),
                            diagnostics=tuple(diagnostics),
                        )
                single_val = val[0] if isinstance(val, (list, tuple)) else val
                slot_values[slot] = str(single_val)
                target_vals = [str(single_val)]
            else:
                list_vals = list(val) if isinstance(val, (list, tuple, set)) else [str(val)]
                slot_values[slot] = list_vals
                target_vals = [str(x) for x in list_vals]

            # Enforce proof backing for each target value
            for t_val in target_vals:
                t_norm = t_val.strip().casefold()
                val_proven = False

                # 1. Check verified ProofResults
                if proof_results:
                    for pr in proof_results:
                        if not getattr(pr, "proved", getattr(pr, "verified", False)):
                            continue
                        pr_bindings = dict(getattr(pr, "bindings", {}) or {})
                        pr_cited_fields = dict(getattr(pr, "cited_fields", {}) or {})
                        pr_vals = [
                            getattr(pr, "subject_binding", ""),
                            getattr(pr, "object_binding", ""),
                            *pr_bindings.values(),
                            *pr_cited_fields.values(),
                        ]
                        if any(t_norm == str(pv).strip().casefold() for pv in pr_vals if pv):
                            val_proven = True
                            pr_cits = getattr(pr, "cited_observation_ids", getattr(pr, "citations", ()))
                            if pr_cits:
                                citations.extend(str(c) for c in pr_cits)
                            elif getattr(pr, "contract_id", None):
                                citations.append(str(pr.contract_id))
                            break

                # 2. Check CandidateSets
                if not val_proven and slot in candidate_sets:
                    cset = candidate_sets[slot]
                    for c in getattr(cset, "candidates", ()):
                        if str(c.value).strip().casefold() == t_norm:
                            is_verif = getattr(c, "status", "") in ("VERIFIED", "VERIFIED_BINDING") or getattr(c, "is_verified_binding", False)
                            no_contra = not bool(getattr(c, "contradictions", ()))
                            if is_verif and no_contra:
                                val_proven = True
                                for f_id in getattr(c, "supporting_fact_ids", ()):
                                    citations.append(str(f_id))
                                if getattr(c, "provenance", ""):
                                    citations.append(str(c.provenance))
                                break

                # Slot values must strictly be proven by verified ProofResults or verified CandidateSets
                if not val_proven:
                    all_proven = False
                    diagnostics.append(f"Slot '{slot}' value '{t_val}' is not verified by proof results or candidate sets")

        if not citations and cards:
            for card in cards:
                c_id = getattr(card, "id", None)
                if c_id:
                    citations.append(str(c_id))

        if missing_slots:
            status = "INCONCLUSIVE" if not coverage_complete else "NOT_FOUND"
            return OutcomeVerificationResult(
                verified=False,
                status=status,
                slot_values=slot_values,
                missing_slots=tuple(missing_slots),
                diagnostics=tuple(diagnostics),
                citations=tuple(list(dict.fromkeys(citations))[:10]),
            )

        if not all_proven:
            return OutcomeVerificationResult(
                verified=False,
                status="UNPROVEN",
                slot_values=slot_values,
                missing_slots=(),
                diagnostics=tuple(diagnostics),
                citations=tuple(list(dict.fromkeys(citations))[:10]),
            )

        return OutcomeVerificationResult(
            verified=True,
            status="ANSWERED",
            slot_values=slot_values,
            missing_slots=(),
            diagnostics=tuple(diagnostics),
            citations=tuple(list(dict.fromkeys(citations))[:10]),
        )

    @classmethod
    def _value_is_proof_backed(
        cls,
        value: str,
        proof_results: list[Any],
        candidate_set: Any | None,
    ) -> bool:
        t_norm = str(value).strip().casefold()
        if not t_norm:
            return False
        for pr in proof_results:
            if not getattr(pr, "proved", getattr(pr, "verified", False)):
                continue
            pr_bindings = dict(getattr(pr, "bindings", {}) or {})
            pr_cited_fields = dict(getattr(pr, "cited_fields", {}) or {})
            pr_vals = [
                getattr(pr, "subject_binding", ""),
                getattr(pr, "object_binding", ""),
                *pr_bindings.values(),
                *pr_cited_fields.values(),
            ]
            if any(t_norm == str(pv).strip().casefold() for pv in pr_vals if pv):
                return True
        if candidate_set is not None:
            for cand in getattr(candidate_set, "candidates", ()):
                if str(getattr(cand, "value", "")).strip().casefold() != t_norm:
                    continue
                if getattr(cand, "status", "") in ("VERIFIED", "VERIFIED_BINDING") or getattr(cand, "is_verified_binding", False):
                    return not bool(getattr(cand, "contradictions", ()))
        return False

    @classmethod
    def _verify_hypothesis(
        cls,
        contract: HypothesisVerdictContract,
        verified_goals: list[str],
        bound_variables: dict[str, Any],
        coverage_complete: bool,
    ) -> OutcomeVerificationResult:
        verified_set = set(verified_goals)

        # 1. Check refutation obligations
        if contract.refutation_obligations:
            refuted = any(r in verified_set for r in contract.refutation_obligations)
            if refuted:
                return OutcomeVerificationResult(
                    verified=True,
                    status="REFUTED",
                    diagnostics=("Refutation obligation proven",),
                )

        # 2. Check support obligations
        support_met = set(contract.support_obligations).issubset(verified_set)
        if support_met:
            return OutcomeVerificationResult(
                verified=True,
                status="SUPPORTED",
                diagnostics=("All support obligations verified",),
            )

        missing = [o for o in contract.support_obligations if o not in verified_set]
        return OutcomeVerificationResult(
            verified=False,
            status="INCONCLUSIVE" if not coverage_complete else "NOT_FOUND",
            diagnostics=(f"Unverified support obligations: {missing}",),
            missing_slots=tuple(missing),
        )

    @classmethod
    def _verify_population(
        cls,
        contract: PopulationDiscoveryContract,
        candidate_sets: dict[str, Any],
        coverage_complete: bool,
    ) -> OutcomeVerificationResult:
        unit = contract.population_unit
        cset = candidate_sets.get(unit)
        candidates = list(getattr(cset, "candidates", ()) or []) if cset else []
        values = [getattr(c, "value", str(c)) for c in candidates]
        if getattr(cset, "cardinality", "plural") == "singular" and len(values) > 1:
            return OutcomeVerificationResult(
                verified=False,
                status="AMBIGUOUS",
                slot_values={unit: values},
                diagnostics=("Population unit was coerced to a singular slot",),
            )

        if not coverage_complete and contract.coverage_requirement == "EXHAUSTIVE":
            return OutcomeVerificationResult(
                verified=False,
                status="INCONCLUSIVE",
                slot_values={
                    unit: values,
                    "prevalence": len(values),
                    "prevalence_aggregation": contract.prevalence_aggregation,
                    "coverage": "PARTIAL",
                },
                diagnostics=("Exhaustive coverage required but scan incomplete",),
            )

        coverage_label = "COMPLETE" if coverage_complete else "PARTIAL"
        return OutcomeVerificationResult(
            verified=True,
            status="ANSWERED",
            slot_values={
                unit: values,
                "prevalence": len(values),
                "prevalence_aggregation": contract.prevalence_aggregation,
                "coverage": coverage_label,
            },
            diagnostics=(f"Discovered population of {len(values)} items",),
        )


__all__ = [
    "OutcomeVerificationResult",
    "OutcomeVerifier",
]
