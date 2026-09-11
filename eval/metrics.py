"""Layer metrics and evaluation data models for benchmark evaluation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlanningMetrics:
    claim_precision: float = 1.0
    claim_recall: float = 1.0
    claim_f1: float = 1.0
    unsupported_expansion_rate: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "claim_precision": self.claim_precision,
            "claim_recall": self.claim_recall,
            "claim_f1": self.claim_f1,
            "unsupported_expansion_rate": self.unsupported_expansion_rate,
        }


@dataclass
class RetrievalMetrics:
    evidence_precision: float = 1.0
    evidence_recall_at_k: float = 1.0
    completeness_accuracy: float = 1.0

    def to_dict(self) -> dict[str, float]:
        return {
            "evidence_precision": self.evidence_precision,
            "evidence_recall_at_k": self.evidence_recall_at_k,
            "completeness_accuracy": self.completeness_accuracy,
        }


@dataclass
class CorrelationMetrics:
    edge_precision: float = 1.0
    edge_recall: float = 1.0
    edge_f1: float = 1.0
    transition_validity: float = 1.0

    def to_dict(self) -> dict[str, float]:
        return {
            "edge_precision": self.edge_precision,
            "edge_recall": self.edge_recall,
            "edge_f1": self.edge_f1,
            "transition_validity": self.transition_validity,
        }


@dataclass
class AnswerMetrics:
    exact_match: float = 1.0
    value_f1: float = 1.0
    citation_grounding_rate: float = 1.0

    def to_dict(self) -> dict[str, float]:
        return {
            "exact_match": self.exact_match,
            "value_f1": self.value_f1,
            "citation_grounding_rate": self.citation_grounding_rate,
        }


@dataclass
class OperationalMetrics:
    decision_coverage: float = 1.0
    waste_ratio: float = 0.0
    mean_time_to_verdict_ms: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "decision_coverage": self.decision_coverage,
            "waste_ratio": self.waste_ratio,
            "mean_time_to_verdict_ms": self.mean_time_to_verdict_ms,
        }


@dataclass
class ScenarioEvaluationResult:
    scenario_id: str
    split: str
    architecture_mode: str
    predicted_stopping_state: str
    expected_stopping_state: str
    stopping_state_correct: bool
    predicted_answer: Any
    answer_correct: bool
    planning: PlanningMetrics = field(default_factory=PlanningMetrics)
    retrieval: RetrievalMetrics = field(default_factory=RetrievalMetrics)
    correlation: CorrelationMetrics = field(default_factory=CorrelationMetrics)
    answer: AnswerMetrics = field(default_factory=AnswerMetrics)
    operations: OperationalMetrics = field(default_factory=OperationalMetrics)
    cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "split": self.split,
            "architecture_mode": self.architecture_mode,
            "predicted_stopping_state": self.predicted_stopping_state,
            "expected_stopping_state": self.expected_stopping_state,
            "stopping_state_correct": self.stopping_state_correct,
            "predicted_answer": self.predicted_answer,
            "answer_correct": self.answer_correct,
            "planning": self.planning.to_dict(),
            "retrieval": self.retrieval.to_dict(),
            "correlation": self.correlation.to_dict(),
            "answer": self.answer.to_dict(),
            "operations": self.operations.to_dict(),
            "cost_usd": self.cost_usd,
        }


__all__ = [
    "PlanningMetrics",
    "RetrievalMetrics",
    "CorrelationMetrics",
    "AnswerMetrics",
    "OperationalMetrics",
    "ScenarioEvaluationResult",
]
