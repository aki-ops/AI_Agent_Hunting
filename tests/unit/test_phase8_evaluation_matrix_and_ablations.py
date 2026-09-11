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
    """Verify Candidate pipeline achieves high accuracy and low waste across all 15 scenarios."""
    runner = EvaluationRunner()
    results = runner.run_suite(mode="CANDIDATE")
    assert len(results) == 15

    agg = runner.compute_aggregate_metrics(results)
    assert agg["stopping_accuracy"] == 1.0
    assert agg["answer_accuracy"] == 1.0

    # Verify layer metrics
    assert agg["planning"]["claim_f1"] == 1.0
    assert agg["planning"]["unsupported_expansion_rate"] == 0.0
    assert agg["retrieval"]["completeness_accuracy"] == 1.0
    assert agg["correlation"]["transition_validity"] == 1.0
    assert agg["answer"]["citation_grounding_rate"] == 1.0
    assert agg["operations"]["waste_ratio"] < 0.10


def test_baseline_comparison_b0_vs_b1_vs_candidate() -> None:
    """Verify Candidate outperforms legacy B0 and single-shot B1 baselines."""
    runner = EvaluationRunner()
    res_b0 = runner.run_suite(mode="B0_BASELINE")
    res_b1 = runner.run_suite(mode="B1_DIRECT_QUERY")
    res_cand = runner.run_suite(mode="CANDIDATE")

    agg_b0 = runner.compute_aggregate_metrics(res_b0)
    agg_b1 = runner.compute_aggregate_metrics(res_b1)
    agg_cand = runner.compute_aggregate_metrics(res_cand)

    # Candidate has superior stopping and answer accuracy
    assert agg_cand["stopping_accuracy"] > agg_b0["stopping_accuracy"]
    assert agg_cand["answer_accuracy"] > agg_b0["answer_accuracy"]
    assert agg_cand["stopping_accuracy"] >= agg_b1["stopping_accuracy"]

    # Candidate has significantly lower waste ratio
    assert agg_cand["operations"]["waste_ratio"] < agg_b1["operations"]["waste_ratio"]
    assert agg_b1["operations"]["waste_ratio"] < agg_b0["operations"]["waste_ratio"]

    # Candidate has higher citation grounding
    assert agg_cand["answer"]["citation_grounding_rate"] > agg_b0["answer"]["citation_grounding_rate"]


def test_ablations_oracle_dynamic_singleshot() -> None:
    """Verify ablations demonstrate necessary value of each architectural component."""
    runner = EvaluationRunner()

    # 1. Dynamic mapping only (without approved proof contracts) fails closed on novel relations
    res_dynamic = runner.run_suite(mode="CANDIDATE", ablation="dynamic_mapping_only")
    agg_dynamic = runner.compute_aggregate_metrics(res_dynamic)
    assert agg_dynamic["stopping_accuracy"] < 1.0
    assert agg_dynamic["correlation"]["edge_precision"] < 1.0

    # 2. Single-shot query (without progressive frontier F0–F4) increases waste dramatically
    res_singleshot = runner.run_suite(mode="CANDIDATE", ablation="single_shot_query")
    agg_singleshot = runner.compute_aggregate_metrics(res_singleshot)
    assert agg_singleshot["operations"]["waste_ratio"] > 0.30
    assert agg_singleshot["retrieval"]["evidence_precision"] < 0.70

    # 3. Oracle graph confirms semantic compilation preserves plan fidelity
    res_oracle = runner.run_suite(mode="CANDIDATE", ablation="oracle_graph")
    agg_oracle = runner.compute_aggregate_metrics(res_oracle)
    assert agg_oracle["planning"]["claim_f1"] == 1.0


def test_holdout_split_evaluation() -> None:
    """Verify robust performance on unseen test_holdout partition (S04, S09, S13, S14, S15)."""
    runner = EvaluationRunner()
    holdout_results = runner.run_suite(split="test_holdout", mode="CANDIDATE")
    assert len(holdout_results) == 5

    agg = runner.compute_aggregate_metrics(holdout_results)
    assert agg["stopping_accuracy"] == 1.0
    assert agg["answer_accuracy"] == 1.0
    assert agg["operations"]["waste_ratio"] < 0.10
