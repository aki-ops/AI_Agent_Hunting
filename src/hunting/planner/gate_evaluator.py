"""Deterministic GATE evaluator for semantic graph execution.

Inspects only verified runtime state and declared coverage/proof fields.
Native query text, SQL/SPL fragments, and LLM prose are not executable gate expressions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunting.contracts.observation_class import (
    CoverageStatus,
    ExecutionStatus,
    ProofStatus,
)
from hunting.contracts.state import GoalRuntimeState


@dataclass(frozen=True)
class GateEvaluationResult:
    """Outcome of evaluating a gate condition."""
    passed: bool
    reason: str
    evaluated_predicates: tuple[str, ...] = ()


class GateEvaluator:
    """Deterministic evaluation of gate predicates against verified runtime state.

    Rules:
    - Inspects ONLY verified runtime state and declared coverage/proof fields.
    - Native query text, SQL/SPL fragments, and LLM prose are NOT executable gate expressions.
    - An empty gate condition passes trivially.
    - Supported predicate syntax on a goal:
        - '<goal_id>:verified' -> proof_status is PROVEN
        - '<goal_id>:proven' -> proof_status is PROVEN
        - '<goal_id>:refuted' -> proof_status is REFUTED
        - '<goal_id>:completed' -> execution_status is COMPLETED
        - '<goal_id>:has_candidate' -> candidate_set is not None and has candidates
        - '<goal_id>:proof_status=<STATUS>' -> proof_status matches STATUS
        - '<goal_id>:coverage_status=<STATUS>' -> coverage_status matches STATUS
        - '<goal_id>:execution_status=<STATUS>' -> execution_status matches STATUS
        - '<goal_id>' alone -> defaults to proof_status is PROVEN
    - Predicates can be combined with AND / OR.
    """

    @classmethod
    def evaluate(
        cls,
        gate_condition: str | None,
        goal_states: dict[str, GoalRuntimeState | Any],
    ) -> GateEvaluationResult:
        if not gate_condition or not gate_condition.strip():
            return GateEvaluationResult(
                passed=True,
                reason="No gate condition specified",
                evaluated_predicates=(),
            )

        cond = gate_condition.strip()
        forbidden = ("select ", "| table", "| search", "drop ", "exec ", "prompt", "eval(")
        if any(bad in cond.lower() for bad in forbidden):
            return GateEvaluationResult(
                passed=False,
                reason=f"Gate condition contains forbidden expression: '{cond}'",
                evaluated_predicates=(cond,),
            )

        if " or " in cond.lower():
            sub_conds = [c.strip() for c in cond.split(" OR ") if c.strip()]
            if len(sub_conds) == 1:
                sub_conds = [c.strip() for c in cond.split(" or ") if c.strip()]
            sub_results = [cls._eval_single_and(sub, goal_states) for sub in sub_conds]
            passed = any(r.passed for r in sub_results)
            reason = " OR ".join(r.reason for r in sub_results)
            all_preds = tuple(p for r in sub_results for p in r.evaluated_predicates)
            return GateEvaluationResult(passed=passed, reason=reason, evaluated_predicates=all_preds)

        return cls._eval_single_and(cond, goal_states)

    @classmethod
    def _eval_single_and(
        cls,
        condition: str,
        goal_states: dict[str, GoalRuntimeState | Any],
    ) -> GateEvaluationResult:
        if " and " in condition.lower():
            parts = [p.strip() for p in condition.split(" AND ") if p.strip()]
            if len(parts) == 1:
                parts = [p.strip() for p in condition.split(" and ") if p.strip()]
        elif "," in condition:
            parts = [p.strip() for p in condition.split(",") if p.strip()]
        else:
            parts = [condition.strip()]

        evaluated: list[str] = []
        for part in parts:
            evaluated.append(part)
            passed, reason = cls._eval_atomic(part, goal_states)
            if not passed:
                return GateEvaluationResult(
                    passed=False,
                    reason=reason,
                    evaluated_predicates=tuple(evaluated),
                )

        return GateEvaluationResult(
            passed=True,
            reason=f"All gate predicates passed: {', '.join(parts)}",
            evaluated_predicates=tuple(evaluated),
        )

    @classmethod
    def _eval_atomic(
        cls,
        predicate: str,
        goal_states: dict[str, GoalRuntimeState | Any],
    ) -> tuple[bool, str]:
        if ":" not in predicate:
            goal_id = predicate.strip()
            check = "verified"
        else:
            goal_id, check = [s.strip() for s in predicate.split(":", 1)]

        state = goal_states.get(goal_id)
        if state is None:
            return False, f"Gate prerequisite goal '{goal_id}' has no runtime state"

        if isinstance(state, dict):
            proof_val = str(state.get("proof_status", state.get("status", ""))).upper()
            exec_val = str(state.get("execution_status", "")).upper()
            cov_val = str(state.get("coverage_status", "")).upper()
            candidate_set = state.get("candidate_set")
        else:
            proof_status = getattr(state, "proof_status", None)
            if isinstance(proof_status, ProofStatus):
                proof_val = proof_status.value.upper()
            else:
                proof_val = str(proof_status or getattr(state, "status", "")).upper()

            execution_status = getattr(state, "execution_status", None)
            if isinstance(execution_status, ExecutionStatus):
                exec_val = execution_status.value.upper()
            else:
                exec_val = str(execution_status or "").upper()

            coverage_status = getattr(state, "coverage_status", None)
            if isinstance(coverage_status, CoverageStatus):
                cov_val = coverage_status.value.upper()
            else:
                cov_val = str(coverage_status or "").upper()

            candidate_set = getattr(state, "candidate_set", None)

        check_lower = check.lower()
        if check_lower in ("verified", "proven"):
            if proof_val in ("PROVEN", "VERIFIED"):
                return True, f"Goal '{goal_id}' is verified/proven"
            return False, f"Goal '{goal_id}' proof_status is '{proof_val}', expected PROVEN"

        if check_lower == "refuted":
            if proof_val == "REFUTED":
                return True, f"Goal '{goal_id}' is refuted"
            return False, f"Goal '{goal_id}' proof_status is '{proof_val}', expected REFUTED"

        if check_lower == "completed":
            if exec_val in ("COMPLETED", "EXECUTED"):
                return True, f"Goal '{goal_id}' execution is completed"
            return False, f"Goal '{goal_id}' execution_status is '{exec_val}', expected COMPLETED"

        if check_lower == "has_candidate":
            candidates = getattr(candidate_set, "candidates", None)
            if isinstance(candidate_set, (list, tuple, set)):
                candidates = candidate_set
            if candidates and len(candidates) > 0:
                return True, f"Goal '{goal_id}' has {len(candidates)} candidate(s)"
            return False, f"Goal '{goal_id}' has no candidates"

        if check_lower.startswith("proof_status="):
            target = check.split("=", 1)[1].strip().upper()
            if proof_val == target:
                return True, f"Goal '{goal_id}' proof_status matches {target}"
            return False, f"Goal '{goal_id}' proof_status is '{proof_val}', expected '{target}'"

        if check_lower.startswith("coverage_status="):
            target = check.split("=", 1)[1].strip().upper()
            if cov_val == target:
                return True, f"Goal '{goal_id}' coverage_status matches {target}"
            return False, f"Goal '{goal_id}' coverage_status is '{cov_val}', expected '{target}'"

        if check_lower.startswith("execution_status="):
            target = check.split("=", 1)[1].strip().upper()
            if exec_val == target:
                return True, f"Goal '{goal_id}' execution_status matches {target}"
            return False, f"Goal '{goal_id}' execution_status is '{exec_val}', expected '{target}'"

        return False, f"Unknown gate predicate format: '{predicate}'"


__all__ = ["GateEvaluationResult", "GateEvaluator"]
