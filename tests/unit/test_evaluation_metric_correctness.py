from types import SimpleNamespace

from eval.runner import EvaluationRunner
from hunting.contracts.hunt import StoppingDecision


def _execution_result(*, citations=None, query_results=None, observations=None):
    account = SimpleNamespace(
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE,
        stopping_taxonomy_state=None,
        answer={},
        candidate_sets={},
        hypotheses=[],
        observation_citations=list(citations or []),
        coverage_bound=None,
        provenance_chain=[],
        cost_accounting={"total_cost_usd": 0.0},
    )
    state = SimpleNamespace(
        semantic_goal_graph=None,
        queries=[],
        query_results=list(query_results or []),
        evidence_cards=[],
        observations=list(observations or []),
    )
    return SimpleNamespace(account=account, state=state, budget=None)


def test_zero_query_execution_is_not_complete_by_default(monkeypatch):
    runner = EvaluationRunner()
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *args, **kwargs: _execution_result(),
    )
    scenario = {
        "scenario_id": "metric-zero-query",
        "split": "test",
        "request_text": "find a value",
        "answer_contract": {"gold_values": ["value"], "min_citations": 1},
        "required_goals": [{"relation": "find"}],
        "expected_stopping_decision": "STOP_INCONCLUSIVE",
    }

    result = runner.evaluate_scenario(scenario, adapter=object())

    assert result.retrieval.completeness_accuracy == 0.0
    assert result.retrieval.completeness_labelled is False
    assert result.answer.citation_grounding_rate == 0.0


def test_evidence_precision_requires_independent_relevance_labels(monkeypatch):
    runner = EvaluationRunner()
    observations = [SimpleNamespace(id="obs-1", fields={"value": "noise"})]
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *args, **kwargs: _execution_result(
            citations=["obs-1"], observations=observations
        ),
    )
    scenario = {
        "scenario_id": "metric-unlabelled-evidence",
        "split": "test",
        "request_text": "find a value",
        "answer_contract": {"gold_values": [], "min_citations": 0, "citation_policy": "not_required"},
        "expected_stopping_decision": "STOP_INCONCLUSIVE",
    }

    result = runner.evaluate_scenario(scenario, adapter=object())

    assert result.retrieval.evidence_precision == 0.0
    assert result.retrieval.evidence_precision_labelled is False
    assert result.answer.citation_grounding_rate == 1.0


def test_labelled_evidence_precision_counts_only_relevant_citations(monkeypatch):
    runner = EvaluationRunner()
    observations = [
        SimpleNamespace(id="obs-relevant", fields={}),
        SimpleNamespace(id="obs-noise", fields={}),
    ]
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *args, **kwargs: _execution_result(
            citations=["obs-relevant", "obs-noise"], observations=observations
        ),
    )
    scenario = {
        "scenario_id": "metric-labelled-evidence",
        "split": "test",
        "request_text": "find a value",
        "relevant_observation_ids": ["obs-relevant"],
        "answer_contract": {"gold_values": [], "min_citations": 0, "citation_policy": "not_required"},
        "expected_stopping_decision": "STOP_INCONCLUSIVE",
    }

    result = runner.evaluate_scenario(scenario, adapter=object())

    assert result.retrieval.evidence_precision == 0.5
    assert result.retrieval.evidence_precision_labelled is True


def test_candidate_exception_is_preserved_in_run_account(monkeypatch):
    runner = EvaluationRunner()
    def fail(*args, **kwargs):
        raise TimeoutError("provider timeout")
    monkeypatch.setattr(runner, "execute_candidate_pipeline", fail)
    scenario = {
        "scenario_id": "metric-failed-candidate",
        "split": "test",
        "request_text": "find a value",
        "answer_contract": {"gold_values": []},
        "expected_stopping_decision": "STOP_INCONCLUSIVE",
    }

    result = runner.evaluate_scenario(scenario, adapter=object())

    assert result.predicted_stopping_state == "EXECUTION_ERROR"
    assert result.run_account["status"] == "EXECUTION_FAILED"
    assert "TimeoutError" in result.run_account["diagnostic"]
    assert result.run_account["cost_status"] == "UNKNOWN"
