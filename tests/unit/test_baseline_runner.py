from eval.runner import EvaluationRunner
from hunting.m5_adapter.cdb_adapter import CdbAdapter


def _scenario() -> dict:
    return {
        "scenario_id": "S01_tor_version",
        "split": "train",
        "request_text": "What version of Tor Browser was observed?",
        "answer_contract": {"gold_values": ["7.0.4"]},
        "expected_stopping_decision": "ANSWER_PROVED",
    }


def test_b1_executes_reviewed_direct_query_and_serializes_run_account() -> None:
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "software",
        "raw_ref": "Tor Browser version 7.0.4",
    }])
    result = EvaluationRunner().evaluate_scenario(_scenario(), mode="B1_DIRECT_QUERY", adapter=adapter)
    assert result.predicted_stopping_state == "EXECUTED"
    assert result.run_account is not None
    assert result.run_account["row_count"] == 1
    assert result.run_account["complete"] is True


def test_b0_executes_the_reviewed_curated_baseline_and_serializes_run_account() -> None:
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "software",
        "raw_ref": "Tor Browser version 7.0.4",
    }])
    result = EvaluationRunner().evaluate_scenario(_scenario(), mode="B0_BASELINE", adapter=adapter)
    assert result.predicted_stopping_state == "EXECUTED"
    assert result.run_account is not None
    assert result.run_account["mode"] == "B0_BASELINE"
    assert result.run_account["row_count"] == 1
    assert result.run_account["complete"] is True


def test_baseline_without_spec_is_truthfully_not_configured() -> None:
    scenario = dict(_scenario(), scenario_id="S99_unconfigured")
    result = EvaluationRunner().evaluate_scenario(scenario, mode="B1_DIRECT_QUERY", adapter=CdbAdapter(":memory:"))
    assert result.predicted_stopping_state == "NOT_CONFIGURED"
    assert result.run_account["diagnostic"] == "no reviewed baseline spec"


def test_baseline_provider_failure_is_not_collapsed_to_zero_score() -> None:
    class BrokenAdapter:
        provider_id = "cdb"

        def get_capability_descriptor(self):
            return type("Descriptor", (), {"operations": (type("Op", (), {"id": "search_text"})(),)})()

        def execute_query(self, **_: object):
            raise TimeoutError("fixture timeout")

    result = EvaluationRunner().evaluate_scenario(_scenario(), mode="B1_DIRECT_QUERY", adapter=BrokenAdapter())
    assert result.predicted_stopping_state == "EXECUTION_FAILED"
    assert "TimeoutError" in result.run_account["diagnostic"]
