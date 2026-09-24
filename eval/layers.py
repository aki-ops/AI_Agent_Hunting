"""Independent hunt-layer metrics derived from executed run accounts.

A correct final answer with an invalid proof path is reported as wrong-path.
Scores are never copied from expected fixture fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _as_dict(item: Any) -> dict[str, Any]:
    if item is None:
        return {}
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "to_dict"):
        return dict(item.to_dict())
    return {}


def _proof_records(account: Any, state: Any) -> list[dict[str, Any]]:
    records = []
    for source in (account, state):
        for item in getattr(source, "proof_results", None) or []:
            records.append(_as_dict(item) or {
                "verified": bool(getattr(item, "verified", False)),
                "verdict": str(getattr(item, "verdict", "") or ""),
                "contract_id": str(getattr(item, "contract_id", "") or ""),
                "citations": list(getattr(item, "citations", []) or []),
            })
        if records:
            break
    analysis = dict(getattr(account, "semantic_analysis", None) or getattr(state, "semantic_analysis", None) or {})
    for item in analysis.get("proof_results") or []:
        if isinstance(item, dict):
            records.append(dict(item))
    return records


def _query_count(state: Any, account: Any) -> int:
    queries = getattr(state, "queries", None) or getattr(account, "queries", None) or []
    return len(list(queries))


def _stop_is_abstention(pred_stop: str) -> bool:
    token = str(pred_stop or "").upper()
    return any(part in token for part in (
        "INCONCLUSIVE", "ABSTAIN", "BUDGET", "UNSUPPORTED", "COVERAGE",
        "AMBIGUOUS", "CLARIFY", "QUARANTINE", "DEGRADED",
    ))


@dataclass
class LayeredHuntMetrics:
    request_to_graph: float = 0.0
    retrieve: float = 0.0
    query: float = 0.0
    proof: float = 0.0
    binding: float = 0.0
    outcome: float = 0.0
    abstention: float = 0.0
    cost_usd: float = 0.0
    answer_correct: bool = False
    proof_path_correct: bool = False
    wrong_path: bool = False
    query_count: int = 0
    zero_query: bool = False
    time_to_first_query_ms: float = 0.0
    time_to_first_evidence_ms: float = 0.0
    false_proof: bool = False
    proof_gap: bool = False
    wrong_binding: bool = False
    labelled: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_to_graph": self.request_to_graph,
            "retrieve": self.retrieve,
            "query": self.query,
            "proof": self.proof,
            "binding": self.binding,
            "outcome": self.outcome,
            "abstention": self.abstention,
            "cost_usd": self.cost_usd,
            "answer_correct": self.answer_correct,
            "proof_path_correct": self.proof_path_correct,
            "wrong_path": self.wrong_path,
            "query_count": self.query_count,
            "zero_query": self.zero_query,
            "time_to_first_query_ms": self.time_to_first_query_ms,
            "time_to_first_evidence_ms": self.time_to_first_evidence_ms,
            "false_proof": self.false_proof,
            "proof_gap": self.proof_gap,
            "wrong_binding": self.wrong_binding,
            "labelled": dict(self.labelled),
        }


def layered_metrics_from_execution(
    *,
    scenario: dict[str, Any],
    account: Any,
    state: Any,
    pred_answer: Any,
    gold_values: list[Any],
    pred_stop: str,
    elapsed_ms: float,
    cost_usd: float,
    evidence_precision: float = 0.0,
    evidence_precision_labelled: bool = False,
) -> LayeredHuntMetrics:
    """Score each hunt layer from the executed account, not from expected_stop."""
    required_goals = list(scenario.get("required_goals") or [])
    goal_graph = getattr(account, "semantic_goal_graph", None) or getattr(state, "semantic_goal_graph", None)
    graph_present = goal_graph is not None
    request_to_graph = 1.0 if graph_present else 0.0
    if required_goals and graph_present:
        relations = list(getattr(goal_graph, "relations", []) or [])
        matched = 0
        for goal in required_goals:
            needle = str(goal.get("relation") or goal.get("attribute") or "").casefold()
            if needle and any(needle in str(getattr(item, "relation", item)).casefold() for item in relations):
                matched += 1
        request_to_graph = matched / len(required_goals)

    query_count = _query_count(state, account)
    zero_query = query_count == 0
    query_required = scenario.get("answer_contract", {}).get("no_query_required") is not True
    query_score = 0.0 if (query_required and zero_query) else (1.0 if query_count else 0.0)

    proofs = _proof_records(account, state)
    admissible = {
        str(item) for item in (scenario.get("admissible_proof_contract_ids") or []) if str(item).strip()
    }
    labelled_bindings = {
        str(key): [str(value) for value in values]
        for key, values in dict(scenario.get("labelled_bindings") or {}).items()
    }
    verified = [item for item in proofs if bool(item.get("verified"))]
    proof_gap = any(str(item.get("verdict", "")).upper() in {"PROOF_GAP", "NOT_PROOF"} for item in proofs) or (
        bool(gold_values) and not verified
    )
    false_proof = any(
        bool(item.get("verified")) and admissible and str(item.get("contract_id") or "") not in admissible
        for item in proofs
    )
    if admissible:
        proof_path_correct = bool(verified) and all(
            str(item.get("contract_id") or "") in admissible for item in verified
        ) and not false_proof
        proof_labelled = True
    elif proofs:
        proof_path_correct = bool(verified) and not proof_gap and not false_proof
        proof_labelled = True
    else:
        proof_path_correct = False
        proof_labelled = bool(admissible)

    answer_correct = bool(gold_values) and pred_answer in gold_values
    if not gold_values:
        answer_correct = pred_answer in (None, [], "")
    wrong_path = bool(answer_correct) and not proof_path_correct

    candidate_sets = dict(getattr(account, "candidate_sets", None) or getattr(state, "candidate_sets", None) or {})
    wrong_binding = False
    binding_score = 1.0
    if labelled_bindings:
        binding_score = 0.0
        matched_vars = 0
        for variable_id, allowed in labelled_bindings.items():
            cset = candidate_sets.get(variable_id)
            selected = []
            if cset is not None:
                selected = [str(getattr(item, "value", item)) for item in getattr(cset, "valid_candidates", ()) or ()]
                if getattr(cset, "selected", None):
                    selected = [str(getattr(cset, "selected", ""))]
            if selected and all(item in allowed for item in selected):
                matched_vars += 1
            elif selected and any(item not in allowed for item in selected):
                wrong_binding = True
        binding_score = matched_vars / len(labelled_bindings) if labelled_bindings else 1.0
        if wrong_binding:
            binding_score = 0.0
    elif any(getattr(item, "is_ambiguous", False) for item in candidate_sets.values()):
        binding_score = 0.0
        wrong_binding = True

    outcome_score = 1.0 if answer_correct and proof_path_correct else (0.5 if answer_correct else 0.0)
    abstention_expected = str(scenario.get("expected_stopping_decision") or "").upper()
    abstention_labelled = any(part in abstention_expected for part in (
        "INCONCLUSIVE", "COVERAGE", "BUDGET", "UNSUPPORTED", "QUARANTINE", "DEGRADED", "AMBIGUOUS",
    ))
    abstention_score = 1.0 if (_stop_is_abstention(pred_stop) == abstention_labelled or not abstention_labelled) and _stop_is_abstention(pred_stop) else 0.0
    if abstention_labelled:
        abstention_score = 1.0 if _stop_is_abstention(pred_stop) else 0.0

    citations = list(getattr(account, "observation_citations", []) or [])
    time_to_query = elapsed_ms if query_count else 0.0
    time_to_evidence = elapsed_ms if citations else 0.0

    return LayeredHuntMetrics(
        request_to_graph=request_to_graph,
        retrieve=evidence_precision if evidence_precision_labelled else 0.0,
        query=query_score,
        proof=1.0 if proof_path_correct else 0.0,
        binding=binding_score,
        outcome=outcome_score,
        abstention=abstention_score,
        cost_usd=float(cost_usd or 0.0),
        answer_correct=bool(answer_correct),
        proof_path_correct=bool(proof_path_correct),
        wrong_path=bool(wrong_path),
        query_count=query_count,
        zero_query=zero_query,
        time_to_first_query_ms=time_to_query,
        time_to_first_evidence_ms=time_to_evidence,
        false_proof=bool(false_proof),
        proof_gap=bool(proof_gap),
        wrong_binding=bool(wrong_binding),
        labelled={
            "proof": proof_labelled,
            "retrieve": evidence_precision_labelled,
            "binding": bool(labelled_bindings),
            "answer": bool(gold_values),
        },
    )


__all__ = ["LayeredHuntMetrics", "layered_metrics_from_execution"]
