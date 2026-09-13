"""Deterministic Recovery Controller (The Deterministic Triad).

Operationalizes:
1. classify(attempt, proof_contract, ledger, envelope) -> ObservationClass
2. choose_next_action(classification, envelope, loop_guard, ...) -> ControllerNextAction
3. evaluate_stop(obligations, verified_obligations, coverage, ...) -> StoppingDecision

Invariants:
- LLMs never decide when to stop or whether proof is complete.
- PARTIAL + 0 rows != BOUNDED_NOT_FOUND.
- Contradictory observations are quarantined; never averaged.
- Candidate fanout exceeding envelope limits triggers NEEDS_DISAMBIGUATION.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.hunt import StoppingDecision
from hunting.contracts.observation_class import (
    CoverageStatus,
    ObservationClass,
)
from hunting.contracts.proof_contract import ProofContract
from hunting.contracts.search_envelope import SearchEnvelope
from hunting.controller.loop_guard import LoopGuard


@dataclass
class ControllerNextAction:
    """The deterministic next action emitted by RecoveryController."""

    action_type: str
    """Type of action: RELAX_HINT, SWITCH_ROUTE, PAGINATE, REPAIR_QUERY,
    DISCRIMINATE, QUARANTINE_CONTRADICTION, SEEK_PROOF, EMIT_VERIFIED,
    EXHAUST_ROUTE, STOP_BOUNDED_NOT_FOUND, STOP_BUDGET_EXHAUSTED, NEEDS_DISAMBIGUATION."""
    new_envelope: SearchEnvelope | None = None
    target_source: str | None = None
    target_op: str | None = None
    reason: str = ""
    quarantined_facts: list[str] = field(default_factory=list)
    candidate_bindings: list[dict[str, Any]] = field(default_factory=list)


class RecoveryController:
    """Deterministic triad orchestrator for query classification, recovery, and stopping."""

    def classify(
        self,
        attempt: Any,
        proof_contract: ProofContract | None = None,
        ledger: Any = None,
        envelope: SearchEnvelope | None = None,
        extracted_candidates: list[dict[str, Any]] | None = None,
        conflict_detected: bool = False,
    ) -> ObservationClass:
        """Classify a query outcome through the 8-rung precedence ladder.

        Precedence:
        1. QUERY_INVALID
        2. QUERY_FAILURE
        3. PARTIAL (CRITICAL INVARIANT: complete=False with 0 rows is PARTIAL, NOT EMPTY)
        4. EMPTY
        5. CONTRADICTORY
        6. AMBIGUOUS
        7. PROOF_GAP
        8. VERIFIED / CANDIDATES
        """
        # 1. QUERY_INVALID: AST, safety, or role violations
        if hasattr(attempt, "diagnostic_errors") and attempt.diagnostic_errors:
            errors_str = " ".join(str(e) for e in attempt.diagnostic_errors).lower()
            if any(k in errors_str for k in ("ast", "safety", "policy", "unauthorized", "invalid")):
                return ObservationClass.QUERY_INVALID

        # 2. QUERY_FAILURE: Adapter crash or execution failure
        executed_ok = getattr(attempt, "executed_ok", True)
        status_val = str(getattr(attempt, "status", "")).upper()
        if not executed_ok or status_val in ("FAILED", "ERROR", "CRASHED"):
            return ObservationClass.QUERY_FAILURE

        # 3. PARTIAL: Truncation, timeout, limit hit, partition
        completed = getattr(attempt, "completed", True)
        hit_limit = getattr(attempt, "hit_limit", False)
        truncated = getattr(attempt, "truncated", False)
        if not completed or hit_limit or truncated:
            # INVARIANT: Even if row_count == 0, incomplete execution is PARTIAL
            return ObservationClass.PARTIAL

        # 4. EMPTY: Completed execution with 0 rows
        row_count = getattr(attempt, "row_count", 0)
        if row_count == 0:
            return ObservationClass.EMPTY

        # 5. CONTRADICTORY: Direct conflict with immutable hard constraints or verified facts
        if conflict_detected:
            return ObservationClass.CONTRADICTORY

        candidates = extracted_candidates or []
        if envelope and envelope.hard_constraints:
            for cand in candidates:
                for role, val in envelope.hard_constraints.verified_bindings:
                    if cand.get("role") == role and cand.get("value") and cand.get("value") != val:
                        return ObservationClass.CONTRADICTORY

        # 6. AMBIGUOUS: Multiple viable candidates without deterministic tie-breaker
        if len(candidates) > 1:
            # Check if candidates have distinct values for the same target role
            distinct_values = {c.get("value") for c in candidates if c.get("value")}
            if len(distinct_values) > 1:
                return ObservationClass.AMBIGUOUS

        # 7 & 8. PROOF_GAP vs VERIFIED: ProofContract evaluation
        if proof_contract is not None:
            if not proof_contract.is_approved:
                return ObservationClass.PROOF_GAP

            is_conforming = getattr(attempt, "proof_conforming", False)
            if not is_conforming:
                return ObservationClass.PROOF_GAP

            return ObservationClass.VERIFIED

        if candidates:
            return ObservationClass.CANDIDATES

        return ObservationClass.PROOF_GAP

    def choose_next_action(
        self,
        classification: ObservationClass,
        envelope: SearchEnvelope,
        loop_guard: LoopGuard,
        available_routes: list[tuple[str, str]] | None = None,
        current_route: tuple[str, str] | None = None,
        has_negative_license: bool = False,
        candidates: list[dict[str, Any]] | None = None,
    ) -> ControllerNextAction:
        """Deterministically determine the next recovery or progression action."""
        # Check budget envelope first
        if envelope.budgets.is_exhausted:
            return ControllerNextAction(
                action_type="STOP_BUDGET_EXHAUSTED",
                reason="Quantitative budget envelope exhausted",
            )

        cands = candidates or []
        routes = available_routes or []

        if classification in (ObservationClass.QUERY_INVALID, ObservationClass.QUERY_FAILURE):
            # Try alternate route or repair
            remaining_routes = [r for r in routes if r != current_route and not loop_guard.is_route_exhausted(r[0], r[1])]
            if remaining_routes:
                nxt = remaining_routes[0]
                return ControllerNextAction(
                    action_type="SWITCH_ROUTE",
                    target_source=nxt[0],
                    target_op=nxt[1],
                    reason=f"Current route {current_route} failed or invalid ({classification.value}); switching route",
                )
            return ControllerNextAction(
                action_type="REPAIR_QUERY",
                reason=f"Action failed with {classification.value}; attempting deterministic repair",
            )

        elif classification == ObservationClass.PARTIAL:
            return ControllerNextAction(
                action_type="PAGINATE",
                reason="Partial result received; paginating cursor or subdividing time window",
            )

        elif classification == ObservationClass.EMPTY:
            # 1. Can we expand declared retrieval hints?
            if envelope.retrieval_hints.can_expand():
                new_env = envelope.derive_next(
                    new_hints=envelope.retrieval_hints,
                    reason=f"Expanding retrieval hints to level {envelope.retrieval_hints.current_expansion_level + 1}",
                )
                return ControllerNextAction(
                    action_type="RELAX_HINT",
                    new_envelope=new_env,
                    reason="Query returned EMPTY; relaxing retrieval hints within declared bounds",
                )

            # 2. Can we switch to another available route?
            remaining_routes = [r for r in routes if r != current_route and not loop_guard.is_route_exhausted(r[0], r[1])]
            if remaining_routes:
                nxt = remaining_routes[0]
                return ControllerNextAction(
                    action_type="SWITCH_ROUTE",
                    target_source=nxt[0],
                    target_op=nxt[1],
                    reason=f"Hints exhausted on {current_route}; switching to route {nxt}",
                )

            # 3. All routes and hints exhausted
            if current_route:
                loop_guard.mark_route_exhausted(current_route[0], current_route[1], "Empty result with all hints exhausted")

            if has_negative_license:
                return ControllerNextAction(
                    action_type="STOP_BOUNDED_NOT_FOUND",
                    reason="All routes and hints exhausted with verified absence license",
                )
            return ControllerNextAction(
                action_type="EXHAUST_ROUTE",
                reason="Route exhausted with no negative license granted",
            )

        elif classification == ObservationClass.CONTRADICTORY:
            quarantined = [str(c.get("value")) for c in cands if c.get("value")]
            return ControllerNextAction(
                action_type="QUARANTINE_CONTRADICTION",
                quarantined_facts=quarantined,
                reason="Contradictory observations detected; isolating facts and dispatching 1 re-check probe",
            )

        elif classification == ObservationClass.AMBIGUOUS:
            if not envelope.validate_candidate_fanout(len(cands)):
                return ControllerNextAction(
                    action_type="NEEDS_DISAMBIGUATION",
                    candidate_bindings=cands,
                    reason=f"Candidate fanout {len(cands)} exceeds envelope limit {envelope.max_candidate_fanout}",
                )
            return ControllerNextAction(
                action_type="DISCRIMINATE",
                candidate_bindings=cands,
                reason="Ambiguous candidates detected; running semantic discriminator",
            )

        elif classification == ObservationClass.PROOF_GAP:
            return ControllerNextAction(
                action_type="SEEK_PROOF",
                candidate_bindings=cands,
                reason="Candidates present but ProofContract not satisfied; seeking directional transition proof",
            )

        elif classification == ObservationClass.VERIFIED:
            return ControllerNextAction(
                action_type="EMIT_VERIFIED",
                candidate_bindings=cands,
                reason="ProofContract verified by native event semantics",
            )

        # Default fallback
        return ControllerNextAction(
            action_type="SEEK_PROOF",
            candidate_bindings=cands,
            reason="Processing candidate observations",
        )

    def evaluate_stop(
        self,
        obligations: list[str],
        verified_obligations: list[str],
        coverage: CoverageStatus,
        contradictions: list[str],
        budgets: Any,
        routes_exhausted: bool = False,
        negative_license_granted: bool = False,
    ) -> StoppingDecision:
        """Evaluate terminal stopping decision strictly according to taxonomy."""
        # 1. Budget exhausted
        is_budget_exhausted = getattr(budgets, "is_exhausted", False)
        if is_budget_exhausted:
            return StoppingDecision.STOP_EXHAUSTED_BY_BUDGET

        # 2. Contradiction unresolved
        if contradictions:
            return StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN

        # 3. All obligations satisfied
        if obligations and set(obligations).issubset(set(verified_obligations)):
            return StoppingDecision.STOP_RESOLVED

        # 4. Routes exhausted
        if routes_exhausted:
            if negative_license_granted and coverage == CoverageStatus.COMPLETE:
                return StoppingDecision.STOP_BOUNDED
            return StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP

        return StoppingDecision.STOP_INSUFFICIENT
