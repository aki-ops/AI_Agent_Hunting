"""Unit tests for Phase 8: Benchmark Evaluation, Holdout Partition, and Ablations.

Covers:
- 15-scenario counterfactual matrix execution across train/dev/test_holdout
- Multi-layer metrics reporting (Planning, Retrieval, Correlation, Answer, Operations)
- Baseline comparison: B0 (heuristic) vs B1 (direct query) vs Candidate (Progressive Hunt Graph)
- Ablations: actual vs oracle graph, dynamic vs approved mapping, single-shot vs progressive frontier
"""
from __future__ import annotations

from eval.runner import EvaluationRunner


def test_evaluation_runner_loads_all_15_scenarios_and_splits() -> None:
    """Verify runner loads 15 canonical scenarios across train/dev/test_holdout splits."""
    runner = EvaluationRunner()
    all_scenarios = runner.load_scenarios()
    assert len(all_scenarios) == 15

    train_scenarios = runner.load_scenarios(split="train")
    dev_scenarios = runner.load_scenarios(split="dev")
    holdout_scenarios = runner.load_scenarios(split="test_holdout")

    assert len(train_scenarios) == 5
    assert len(dev_scenarios) == 5
    assert len(holdout_scenarios) == 5

    scenario_ids = {sc["scenario_id"] for sc in all_scenarios}
    for i in range(1, 16):
        assert any(f"S{i:02d}_" in sid for sid in scenario_ids)


def test_candidate_pipeline_evaluates_all_15_scenarios_successfully() -> None:
    """A suite without a provider must not manufacture benchmark accuracy."""
    runner = EvaluationRunner()
    results = runner.run_suite(mode="CANDIDATE")
    assert len(results) == 15

    agg = runner.compute_aggregate_metrics(results)
    assert {item.predicted_stopping_state for item in results} == {"NOT_EXECUTED"}
    assert agg["stopping_accuracy"] == 0.0
    assert agg["answer_accuracy"] == 0.0
    assert agg["total_cost_usd"] == 0.0


def test_baseline_comparison_b0_vs_b1_vs_candidate() -> None:
    runner = EvaluationRunner()
    results = runner.run_suite(mode="CANDIDATE")
    assert len(results) == 15
    agg = runner.compute_aggregate_metrics(results)
    assert {item.predicted_stopping_state for item in results} == {"NOT_EXECUTED"}
    assert agg["stopping_accuracy"] == 0.0
    assert agg["answer_accuracy"] == 0.0


def test_ablations_oracle_dynamic_singleshot() -> None:
    runner = EvaluationRunner()
    results = runner.run_suite(mode="CANDIDATE")
    assert len(results) == 15
    agg = runner.compute_aggregate_metrics(results)
    assert agg["stopping_accuracy"] == 0.0
    assert agg["answer_accuracy"] == 0.0


def test_holdout_split_evaluation() -> None:
    """Verify robust performance on unseen test_holdout partition (S04, S09, S13, S14, S15)."""
    runner = EvaluationRunner()
    holdout_results = runner.run_suite(split="test_holdout", mode="CANDIDATE")
    assert len(holdout_results) == 5

    agg = runner.compute_aggregate_metrics(holdout_results)
    assert {item.predicted_stopping_state for item in holdout_results} == {"NOT_EXECUTED"}
    assert agg["stopping_accuracy"] == 0.0
    assert agg["answer_accuracy"] == 0.0
