"""Deterministic Recovery Controller (The Deterministic Triad).

Operationalizes:
1. classify(attempt, proof_contract, ledger, envelope) -> ObservationClass
2. choose_next_action(classification, envelope, loop_guard, ...) -> ControllerNextAction
3. evaluate_stop(obligations, verified_obligations, coverage, ...) -> StoppingDecision

Invariants:
- LLMs never decide when to stop or whether proof is complete.
- PARTIAL + 0 rows != BOUNDED_NOT_FOUND.
- Contradictory observations are quarantined; never averaged.
- Ambiguous candidates try DISCRIMINATE while discriminator budget remains.
- NEEDS_DISAMBIGUATION is emitted only after that budget is exhausted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.hunt import StoppingDecision
from hunting.contracts.observation_class import (
    ControllerAttempt,
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
    RECORD_CANDIDATE, PRESERVE_CANDIDATE_LIMITATION, EXHAUST_ROUTE,
    STOP_BOUNDED_NOT_FOUND, STOP_BUDGET_EXHAUSTED, NEEDS_DISAMBIGUATION."""
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
        attempt: ControllerAttempt | Any,
        proof_contract: ProofContract | None = None,
        ledger: Any = None,
        envelope: SearchEnvelope | None = None,
        extracted_candidates: list[dict[str, Any]] | None = None,
        conflict_detected: bool = False,
        cardinality: str = "singular",
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
        complete = getattr(attempt, "complete", getattr(attempt, "completed", True))
        hit_limit = getattr(attempt, "hit_limit", False)
        truncated = getattr(attempt, "truncated", False)
        if not complete or hit_limit or truncated:
            # INVARIANT: Even if row_count == 0, incomplete execution is PARTIAL
            return ObservationClass.PARTIAL

        # 4. EMPTY: Completed execution with 0 rows
        rows = getattr(attempt, "rows", None)
        row_count = getattr(attempt, "row_count", 0)
        if rows is not None and len(rows) > 0 and row_count == 0:
            row_count = len(rows)
        if row_count == 0:
            return ObservationClass.EMPTY

        # 5. CONTRADICTORY: Direct conflict with immutable hard constraints or verified facts
        if conflict_detected or getattr(attempt, "conflict_detected", False):
            return ObservationClass.CONTRADICTORY

        candidates = extracted_candidates or getattr(attempt, "candidate_delta", None) or []
        if envelope and envelope.hard_constraints:
            for cand in candidates:
                for role, val in envelope.hard_constraints.verified_bindings:
                    if cand.get("role") == role and cand.get("value"):
                        cand_val = cand.get("value")
                        if isinstance(cand_val, (list, tuple)):
                            if val not in cand_val:
                                return ObservationClass.CONTRADICTORY
                        elif cand_val != val:
                            return ObservationClass.CONTRADICTORY

        # 6. AMBIGUOUS: Multiple viable candidates for a singular target only.
        # Plural populations keep every admissible value; ranking is not a tie-break.
        card = str(cardinality or "singular").strip().casefold()
        if card != "plural" and len(candidates) > 1:
            values_by_role: dict[str, set[str]] = {}
            for c in candidates:
                role = str(c.get("role", "")).strip().casefold()
                val = c.get("value")
                if val not in (None, "", [], {}):
                    val_items = val if isinstance(val, (list, tuple)) else [val]
                    for item in val_items:
                        values_by_role.setdefault(role, set()).add(str(item))
            if any(len(vals) > 1 for vals in values_by_role.values()):
                return ObservationClass.AMBIGUOUS

        # 7 & 8. PROOF_GAP vs VERIFIED: ProofContract evaluation
        is_conforming = getattr(attempt, "proof_conforming", False)
        if hasattr(attempt, "proof_result") and attempt.proof_result is not None:
            is_conforming = bool(getattr(attempt.proof_result, "verified", False))

        if proof_contract is not None:
            if not proof_contract.is_approved:
                return ObservationClass.PROOF_GAP

            if not is_conforming:
                return ObservationClass.PROOF_GAP

            return ObservationClass.VERIFIED

        if is_conforming:
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
        mode: str = "EXPLORE",
        has_proof_capable_route: bool = False,
        declared_discriminator: bool = False,
        cardinality: str = "singular",
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
            if str(cardinality or "singular").strip().casefold() == "plural":
                return ControllerNextAction(
                    action_type="RECORD_CANDIDATE",
                    candidate_bindings=cands,
                    reason="Plural candidate population preserved; ranking is not a singular bind",
                )
            budgets = getattr(envelope, "budgets", None)
            remaining = (
                getattr(budgets, "consumed_discriminators", 0)
                < getattr(budgets, "max_discriminators", 0)
            ) if budgets is not None else False
            if declared_discriminator and remaining:
                return ControllerNextAction(
                    action_type="DISCRIMINATE",
                    candidate_bindings=cands,
                    reason="Ambiguous singular candidates; evaluating declared differentiating evidence",
                )
            return ControllerNextAction(
                action_type="NEEDS_DISAMBIGUATION",
                candidate_bindings=cands,
                reason=(
                    "Ambiguous singular candidates remain; declared discriminator "
                    "unavailable or discriminator budget exhausted"
                ),
            )

        elif classification == ObservationClass.PROOF_GAP:
            return self._mode_aware_candidate_action(
                mode=mode,
                candidates=cands,
                has_proof_capable_route=has_proof_capable_route,
                declared_discriminator=declared_discriminator,
                envelope=envelope,
                proof_gap=True,
            )

        elif classification == ObservationClass.VERIFIED:
            return ControllerNextAction(
                action_type="EMIT_VERIFIED",
                candidate_bindings=cands,
                reason="ProofContract verified by native event semantics",
            )

        elif classification == ObservationClass.CANDIDATES:
            return self._mode_aware_candidate_action(
                mode=mode,
                candidates=cands,
                has_proof_capable_route=has_proof_capable_route,
                declared_discriminator=declared_discriminator,
                envelope=envelope,
                proof_gap=False,
            )

        return self._mode_aware_candidate_action(
            mode=mode,
            candidates=cands,
            has_proof_capable_route=has_proof_capable_route,
            declared_discriminator=declared_discriminator,
            envelope=envelope,
            proof_gap=False,
        )

    def _mode_aware_candidate_action(
        self,
        *,
        mode: str,
        candidates: list[dict[str, Any]],
        has_proof_capable_route: bool,
        declared_discriminator: bool,
        envelope: SearchEnvelope,
        proof_gap: bool,
    ) -> ControllerNextAction:
        """EXPLORE records candidates; PROVE may seek a proof route; never auto-prove."""
        resolved_mode = str(mode or "EXPLORE").strip().upper()
        if resolved_mode not in {"EXPLORE", "DISCRIMINATE", "PROVE"}:
            resolved_mode = "EXPLORE"

        if resolved_mode == "PROVE":
            if has_proof_capable_route:
                return ControllerNextAction(
                    action_type="SEEK_PROOF",
                    candidate_bindings=candidates,
                    reason="PROVE mode with an approved proof-capable route; seeking contract evidence",
                )
            return ControllerNextAction(
                action_type="PRESERVE_CANDIDATE_LIMITATION",
                candidate_bindings=candidates,
                reason="No approved ProofContract or proof-capable route; retrieval-only candidates preserved",
            )

        if resolved_mode == "DISCRIMINATE":
            budgets = getattr(envelope, "budgets", None)
            remaining = (
                getattr(budgets, "consumed_discriminators", 0)
                < getattr(budgets, "max_discriminators", 0)
            ) if budgets is not None else False
            if declared_discriminator and remaining:
                return ControllerNextAction(
                    action_type="DISCRIMINATE",
                    candidate_bindings=candidates,
                    reason="DISCRIMINATE mode restricted to declared differentiating evidence",
                )
            return ControllerNextAction(
                action_type="NEEDS_DISAMBIGUATION",
                candidate_bindings=candidates,
                reason="DISCRIMINATE requires declared differentiating evidence or remaining discriminator budget",
            )

        if proof_gap:
            return ControllerNextAction(
                action_type="PRESERVE_CANDIDATE_LIMITATION",
                candidate_bindings=candidates,
                reason="EXPLORE proof gap: candidates retained as retrieval-only with explicit limitation",
            )
        return ControllerNextAction(
            action_type="RECORD_CANDIDATE",
            candidate_bindings=candidates,
            reason="EXPLORE recorded candidate evidence; retrieval is not proof",
        )

    def evaluate_stop(
        self,
        obligations: list[str] | None = None,
        verified_obligations: list[str] | None = None,
        coverage: CoverageStatus = CoverageStatus.COMPLETE,
        contradictions: list[str] | None = None,
        budgets: Any = None,
        routes_exhausted: bool = False,
        negative_license_granted: bool = False,
        needs_clarification: bool = False,
        needs_user_decision: bool = False,
        unsupported: bool = False,
        unreachable: bool = False,
        error: bool = False,
        aborted_by_user: bool = False,
        outcome_verified: bool | None = None,
        unexamined_sources: bool = False,
    ) -> StoppingDecision:
        """Evaluate terminal stopping decision strictly according to v9 taxonomy.

        No engine branch directly sets a terminal state.
        Precedence:
        1. Explicit error / abortion / unreachability
        2. Budget exhaustion
        3. Clarification / Ambiguity / User decision
        4. Unsupported capability (prohibited if unexamined sources remain)
        5. Unresolved contradiction
        6. Verified obligations + outcome verification
        7. Bounded negative (routes exhausted + negative license + complete coverage, prohibited if unexamined sources remain)
        8. Inconclusive (unproven, partial scan, unexamined sources, or unverified outcome)
        """
        # 1. Error / abortion / unreachable
        if error:
            return StoppingDecision.STOP_ERROR
        if aborted_by_user:
            return StoppingDecision.STOP_ABORTED_BY_USER
        if unreachable:
            return StoppingDecision.STOP_UNREACHABLE

        # 2. Budget exhausted
        is_budget_exhausted = getattr(budgets, "is_exhausted", False)
        if is_budget_exhausted:
            return StoppingDecision.STOP_BUDGET

        # 3. Clarification / user decision required
        if needs_user_decision:
            return StoppingDecision.STOP_NEEDS_USER_DECISION
        if needs_clarification:
            return StoppingDecision.STOP_NEEDS_CLARIFICATION

        # 4. Unsupported capability (never valid when unexamined sources remain)
        if unsupported and not unexamined_sources:
            return StoppingDecision.STOP_UNSUPPORTED

        # 5. Contradiction unresolved
        if contradictions:
            return StoppingDecision.STOP_INCONCLUSIVE

        # 6. All obligations satisfied
        ob_list = obligations or []
        ver_list = verified_obligations or []
        if ob_list and set(ob_list).issubset(set(ver_list)):
            if outcome_verified is False:
                return StoppingDecision.STOP_INCONCLUSIVE
            return StoppingDecision.STOP_ANSWERED

        # 7. Routes exhausted (never valid when unexamined sources remain)
        if routes_exhausted and not unexamined_sources:
            if negative_license_granted and coverage == CoverageStatus.COMPLETE:
                return StoppingDecision.STOP_NOT_FOUND_BOUNDED
            return StoppingDecision.STOP_INCONCLUSIVE

        return StoppingDecision.STOP_INCONCLUSIVE
