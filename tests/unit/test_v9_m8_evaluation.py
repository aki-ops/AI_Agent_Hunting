"""M8 evaluation: layered metrics from executed accounts, not ideal scores."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.live_probe import probe_bots_v2
from eval.runner import EvaluationRunner
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, StoppingDecision
from hunting.contracts.queries import ProviderOperation
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from tests.unit.test_v9_m5_package_f0 import _approved_registry, _PackageAdapter
from tests.unit.test_v9_open_vocabulary_production import _vocab_mismatch_graph


def _execution_result(*, answer=None, citations=None, queries=None, proof_results=None, observations=None):
    account = SimpleNamespace(
        stopping_decision=StoppingDecision.STOP_ANSWERED,
        stopping_taxonomy_state=None,
        answer={"value": answer},
        candidate_sets={},
        hypotheses=[],
        observation_citations=list(citations or []),
        coverage_bound=None,
        provenance_chain=[],
        cost_accounting={"total_cost_usd": 0.01},
        semantic_goal_graph=SimpleNamespace(relations=[SimpleNamespace(relation="observed")]),
        proof_results=list(proof_results or []),
        queries=list(queries or []),
    )
    state = SimpleNamespace(
        semantic_goal_graph=account.semantic_goal_graph,
        queries=list(queries or []),
        query_results=[],
        evidence_cards=[],
        observations=list(observations or []),
        proof_results=list(proof_results or []),
    )
    return SimpleNamespace(account=account, state=state, budget=None)


def test_correct_answer_with_unverified_proof_is_wrong_path(monkeypatch):
    runner = EvaluationRunner()
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *args, **kwargs: _execution_result(
            answer="7.0.4",
            citations=["obs-1"],
            queries=["q-1"],
            proof_results=[{
                "verified": False,
                "verdict": "PROOF_GAP",
                "contract_id": "unapproved",
                "citations": ["obs-1"],
            }],
            observations=[SimpleNamespace(id="obs-1", fields={"version": "7.0.4"})],
        ),
    )
    scenario = {
        "scenario_id": "m8-wrong-path",
        "split": "test",
        "request_text": "What version was observed?",
        "answer_contract": {"gold_values": ["7.0.4"], "min_citations": 1},
        "admissible_proof_contract_ids": ["proof.observed.v1"],
        "required_goals": [{"relation": "observed"}],
        "expected_stopping_decision": "ANSWER_PROVED",
    }
    result = runner.evaluate_scenario(scenario, adapter=object())
    assert result.answer_correct is True
    assert result.layers.proof_path_correct is False
    assert result.layers.wrong_path is True
    assert result.run_account is not None
    assert result.predicted_stopping_state != scenario["expected_stopping_decision"] or result.layers.wrong_path


def test_verified_admissible_proof_is_not_wrong_path(monkeypatch):
    runner = EvaluationRunner()
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *args, **kwargs: _execution_result(
            answer="7.0.4",
            citations=["obs-1"],
            queries=["q-1"],
            proof_results=[{
                "verified": True,
                "verdict": "PROVEN",
                "contract_id": "proof.observed.v1",
                "citations": ["obs-1"],
            }],
        ),
    )
    scenario = {
        "scenario_id": "m8-right-path",
        "split": "test",
        "request_text": "What version was observed?",
        "answer_contract": {"gold_values": ["7.0.4"], "min_citations": 1},
        "admissible_proof_contract_ids": ["proof.observed.v1"],
        "required_goals": [{"relation": "observed"}],
        "expected_stopping_decision": "ANSWER_PROVED",
    }
    result = runner.evaluate_scenario(scenario, adapter=object())
    assert result.answer_correct is True
    assert result.layers.proof_path_correct is True
    assert result.layers.wrong_path is False


def test_b0_b1_candidate_share_matched_envelope() -> None:
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "software",
        "raw_ref": "Tor Browser version 7.0.4",
    }])
    scenario = {
        "scenario_id": "S01_tor_version",
        "split": "train",
        "request_text": "What version of Tor Browser was observed?",
        "answer_contract": {"gold_values": ["7.0.4"]},
        "kind": "QUESTION",
        "expected_stopping_decision": "ANSWER_PROVED",
        "budget": {"llm_calls": 2},
    }
    matched = EvaluationRunner().evaluate_matched(scenario, adapter=adapter)
    envelope = matched["envelope"]
    assert envelope["request_id"] == "S01_tor_version"
    assert envelope["time_window"]
    assert envelope["provider_id"] == "cdb"
    for mode in ("CANDIDATE", "B0_BASELINE", "B1_DIRECT_QUERY"):
        result = matched[mode]
        assert result.envelope["request_id"] == envelope["request_id"]
        assert result.envelope["time_window"] == envelope["time_window"]
        assert result.envelope["provider_id"] == envelope["provider_id"]
        assert result.run_account is not None
        assert result.run_account["envelope"]["request_id"] == envelope["request_id"]
    assert matched["B0_BASELINE"].predicted_stopping_state == "EXECUTED"
    assert matched["B1_DIRECT_QUERY"].predicted_stopping_state == "EXECUTED"
    assert matched["CANDIDATE"].predicted_stopping_state not in {"NOT_EXECUTED"}


def test_failed_and_abstained_remain_in_cohort_cost(monkeypatch):
    runner = EvaluationRunner()
    monkeypatch.setattr(runner, "execute_candidate_pipeline", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("backend")))
    failed = runner.evaluate_scenario(
        {
            "scenario_id": "m8-fail",
            "split": "test",
            "request_text": "find a value",
            "answer_contract": {"gold_values": []},
            "expected_stopping_decision": "STOP_INCONCLUSIVE",
        },
        adapter=object(),
    )
    ok = runner.evaluate_scenario(
        {
            "scenario_id": "m8-ok",
            "split": "test",
            "request_text": "find a value",
            "answer_contract": {"gold_values": [], "citation_policy": "not_required"},
            "expected_stopping_decision": "STOP_INCONCLUSIVE",
        },
        adapter=object(),
    )
    # Force the second call through the monkeypatched failure as well; rebuild ok without raise.
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *a, **k: _execution_result(answer=None, queries=["q-1"]),
    )
    ok = runner.evaluate_scenario(
        {
            "scenario_id": "m8-ok",
            "split": "test",
            "request_text": "find a value",
            "answer_contract": {"gold_values": [], "citation_policy": "not_required"},
            "expected_stopping_decision": "STOP_INCONCLUSIVE",
        },
        adapter=object(),
    )
    aggregate = runner.compute_aggregate_metrics([failed, ok])
    assert aggregate["cohort_n"] == 2
    assert aggregate["failed_or_abstained"] >= 1
    assert "cohort_cost_usd" in aggregate


def test_candidate_does_not_copy_expected_stop_or_gold(monkeypatch):
    runner = EvaluationRunner()
    monkeypatch.setattr(
        runner,
        "execute_candidate_pipeline",
        lambda *a, **k: _execution_result(answer="wrong", queries=["q-1"], proof_results=[]),
    )
    result = runner.evaluate_scenario(
        {
            "scenario_id": "m8-no-copy",
            "split": "test",
            "request_text": "What version?",
            "answer_contract": {"gold_values": ["7.0.4"]},
            "expected_stopping_decision": "ANSWER_PROVED",
        },
        adapter=object(),
    )
    assert result.predicted_stopping_state != "ANSWER_PROVED" or result.answer_correct is False
    assert result.predicted_answer != "7.0.4"
    assert result.answer_correct is False


def test_factual_hypothesis_population_slices_execute_on_default_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    adapter = _PackageAdapter(
        "pkg_provider",
        [
            ProviderOperation(
                id="read_health",
                provider_id="pkg_provider",
                scope_ids=("scope",),
                input_entity_kinds=("sensor",),
                output_entity_kinds=("health",),
                output_fields=("sensor_status",),
            )
        ],
    )
    engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph()),
        configured_adapters=[adapter],
        content_registry=_approved_registry(),
    )
    factual = engine.execute_hunt(
        HuntRequest(id="m8-factual", kind=HuntRequestKind.QUESTION, content="Which process ran on HOST-1?", provider_hints=("pkg_provider",)),
        adapter=adapter,
    )
    hypothesis_engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph()),
        configured_adapters=[adapter],
        content_registry=_approved_registry(),
    )
    hypothesis = hypothesis_engine.execute_hunt(
        HuntRequest(id="m8-hyp", kind=HuntRequestKind.HYPOTHESIS, content="Was a process observed on HOST-1?", provider_hints=("pkg_provider",)),
        adapter=adapter,
    )
    population_engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_a, **_k: _vocab_mismatch_graph()),
        configured_adapters=[adapter],
        content_registry=_approved_registry(),
    )
    population = population_engine.execute_hunt(
        HuntRequest(id="m8-pop", kind=HuntRequestKind.QUESTION, content="Which processes ran on HOST-1?", provider_hints=("pkg_provider",)),
        adapter=adapter,
    )
    assert factual.account.stopping_decision is not None
    assert hypothesis.account.stopping_decision is not None
    assert population.account.stopping_decision is not None
    assert factual.account.semantic_goal_graph is not None
    assert hypothesis.account.semantic_goal_graph is not None
    assert population.account.semantic_goal_graph is not None


def test_bots_v2_live_probe_never_skips_and_does_not_claim_readiness():
    probe = probe_bots_v2()
    payload = probe.to_dict()
    assert payload["splunk_url"]
    assert payload["bots_index"]
    if not probe.available:
        assert probe.live_claim_allowed is False
        assert probe.blocker
        return

    from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter

    adapter = SplunkLiveAdapter(
        splunk_url=probe.splunk_url,
        auth=("admin", os.environ.get("SPLUNK_PASSWORD", "12345678")),
        index=probe.bots_index,
        manifest_path=str(Path("configs/splunk_botsv2.yaml")),
        verify_ssl=False,
    )
    engine = HypothesisHuntEngine(configured_adapters=[adapter])
    result = engine.execute_hunt(
        HuntRequest(
            id="m8-botsv2-live",
            kind=HuntRequestKind.QUESTION,
            content="Which process ran on an observed host?",
            provider_hints=("splunk",),
        ),
        adapter=adapter,
    )
    assert result.account.stopping_decision is not None
    assert result.account.queries is not None
    assert result.account.coverage_bound is not None or result.account.semantic_analysis
