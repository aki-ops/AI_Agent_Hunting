"""Unit tests for Phase 7 & 8: PARTIALLY_SUPPORTED verdict, citation provenance, and deterministic evaluator fallback."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hunting.contracts.cells import ProviderScope
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.evidence_state import (
    AnswerAttributeState,
    ArtifactEvidence,
    EvidenceState,
)
from hunting.contracts.hunt import (
    AnswerStatus,
    EvidenceCard,
    FinalHuntAccount,
    HuntObjective,
    HuntOutcome,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.contracts.observations import (
    EpistemicType,
    Observation,
    Provenance,
)
from hunting.evidence.answer_verifier import verify_answer
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.evidence.grouping import EvidenceGroupBuilder
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_analyst_report


def _make_obs(
    obs_id: str,
    fields: dict,
    query_id: str = "qp-discovery-0",
    sem_type: str = "process_execution",
) -> Observation:
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv2"})
    prov = Provenance(
        query_id=query_id,
        collector="splunk",
        ingest_time="2026-09-08T12:00:00Z",
    )
    return Observation(
        id=obs_id,
        provider_scope=scope,
        cell_id="splunk-main",
        timestamp="2026-09-08T12:00:00Z",
        native_type="WinEventLog:Security:4688",
        epistemic_type=EpistemicType.OBSERVED,
        semantic_type=sem_type,
        fields=fields,
        provenance=prov,
        query_id=query_id,
    )


class TestPhase7AnswerVerifier:
    def test_artifact_detected_missing_version_yields_partially_supported(self):
        evidence_state = EvidenceState()
        evidence_state.artifact = ArtifactEvidence(
            type="software",
            name="Tor Browser",
            host="wrk-aturing",
            path=r"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe",
            detected=True,
            observation_ids=["obs-discovery-1"],
        )
        evidence_state.set_attribute(
            "software_version",
            AnswerAttributeState.NOT_OBSERVED,
            values=[],
            obs_ids=["obs-discovery-1"],
        )

        card = SimpleNamespace(
            id="c-tor-1",
            fact_type="process_execution",
            field_summary={"Path": [r"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe"]},
            entity_summary={"hosts": ["wrk-aturing"]},
            representative_observation_ids=["obs-discovery-1"],
            query_ids=["qp-discovery-0"],
        )

        obs = _make_obs(
            "obs-discovery-1",
            {"Path": r"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe", "host": "wrk-aturing"},
            query_id="qp-discovery-0",
        )

        result = verify_answer(
            answer={"status": "ANSWERED", "value": "unknown", "card_ids": ["c-tor-1"]},
            answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
            cards=[card],
            query_complete=True,
            evidence_state=evidence_state,
            observations=[obs],
        )

        assert result["status"] == "PARTIALLY_SUPPORTED"
        assert result["reason"] == "VERSION_UNAVAILABLE"
        assert result["artifact_detected"] is True
        assert "Tor Browser was observed on wrk-aturing" in result["explanation"]
        assert "Requested version: Not available in the retrieved telemetry." in result["explanation"]
        assert result["claim"] == (
            "Tor Browser was observed on wrk-aturing. Requested version: Not available in the retrieved telemetry."
        )

    def test_citation_provenance_structure_and_text(self):
        evidence_state = EvidenceState()
        evidence_state.artifact = ArtifactEvidence(
            type="software",
            name="Tor Browser",
            host="wrk-aturing",
            path=r"C:\Tor\firefox.exe",
            detected=True,
            observation_ids=["obs-discovery-1", "obs-discovery-2"],
        )
        evidence_state.set_attribute("software_version", AnswerAttributeState.NOT_OBSERVED)

        card = SimpleNamespace(
            id="c1",
            fact_type="process_execution",
            field_summary={"Path": [r"C:\Tor\firefox.exe"]},
            entity_summary={"hosts": ["wrk-aturing"]},
            representative_observation_ids=["obs-discovery-1", "obs-discovery-2"],
            query_ids=["qp-discovery-0"],
        )
        obs = _make_obs(
            "obs-discovery-1",
            {"Path": r"C:\Tor\firefox.exe", "host": "wrk-aturing", "raw_event": "proc start"},
            query_id="qp-discovery-0",
        )

        result = verify_answer(
            answer={"status": "ANSWERED", "value": "unknown", "card_ids": ["c1"]},
            answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
            cards=[card],
            query_complete=True,
            evidence_state=evidence_state,
            observations=[obs],
        )

        assert len(result["citations"]) == 1
        citation = result["citations"][0]
        assert "Tor Browser executed on wrk-aturing" in citation["claim"]
        assert "obs-discovery-1" in citation["observation_ids"]
        assert "qp-discovery-0" in citation["query_ids"]
        assert any(f in citation["fields"] for f in ("Path", "raw_event"))

        assert "Evidence: obs-discovery-1" in result["citation_text"]
        assert "Query: qp-discovery-0" in result["citation_text"]

    def test_empty_or_none_version_is_not_observed(self):
        evidence_state = EvidenceState()
        evidence_state.artifact = ArtifactEvidence(type="software", name="Tor Browser", host="wrk-aturing")
        card = SimpleNamespace(
            id="c1",
            field_summary={"Path": [r"C:\Tor\firefox.exe"]},
            entity_summary={"hosts": ["wrk-aturing"]},
            representative_observation_ids=["obs-1"],
            query_ids=["q-1"],
        )

        # Candidate claims version is empty string
        result = verify_answer(
            answer={"status": "ANSWERED", "value": "", "card_ids": ["c1"]},
            answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
            cards=[card],
            query_complete=True,
            evidence_state=evidence_state,
        )
        assert result["status"] == "PARTIALLY_SUPPORTED"
        assert result["reason"] == "VERSION_UNAVAILABLE"


class TestPhase7Grouping:
    def test_tor_browser_process_summary_format(self):
        obs1 = _make_obs(
            "obs-tor-1",
            {
                "host": "wrk-aturing",
                "Image": "firefox.exe",
                "Path": r"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe",
                "CommandLine": r'"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe"',
            },
        )
        cards = EvidenceGroupBuilder().build_cards([obs1])
        assert len(cards) >= 1
        tor_card = cards[0]
        assert tor_card.fact_type == "process_execution"
        assert "Process: firefox.exe" in tor_card.summary
        assert r"Path: C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe" in tor_card.summary
        assert "Host: wrk-aturing" in tor_card.summary


class TestPhase8EvaluatorFallback:
    def test_deterministic_fallback_on_llm_failure(self):
        def failing_llm(_prompt: str) -> str:
            raise RuntimeError("LLM service timeout or offline")

        evaluator = EvidenceEvaluator(llm_caller=failing_llm)

        card = EvidenceCard(
            id="card-tor-1",
            fingerprint="fp-tor-1",
            fact_type="process_execution",
            summary="Process: firefox.exe Path: C:\\Tor\\firefox.exe Host: wrk-aturing",
            count=1,
            representative_observation_ids=["obs-1"],
            query_ids=["qp-0"],
            entity_summary={"hosts": ["wrk-aturing"]},
            field_summary={"images": ["firefox.exe"], "file_paths": [r"C:\Tor\firefox.exe"]},
        )
        hyp = Hypothesis(
            id="hyp-1",
            statement="Amber Turing installed Tor Browser on wrk-aturing",
            status=HypothesisStatus.LIVE,
        )

        res = evaluator.analyze_batch(
            cards=[card],
            hypotheses=[hyp],
            answer_spec={"answer_type": "software_version"},
            question="What is the version of Tor Browser?",
        )

        assert res["parse_status"] in ("TIMEOUT", "PROVIDER_ERROR")
        assert res["explanation_unavailable"] is False
        assert "deterministic_explanation" in res
        assert "Tor Browser" in res["deterministic_explanation"]
        assert "wrk-aturing" in res["deterministic_explanation"]
        # Preserves card evaluations
        assert len(res["evaluations"]) >= 1
        assert res["evaluations"][0]["card_id"] == "card-tor-1"


class TestPhase7ReporterBuilderAndRenderer:
    def test_builder_and_render_analyst_report_partially_supported(self):
        obs = _make_obs(
            "obs-tor-1",
            {
                "Path": r"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe",
                "host": "wrk-aturing",
                "Image": "firefox.exe",
            },
            query_id="qp-discovery-0",
        )
        evidence_state = EvidenceState()
        evidence_state.artifact = ArtifactEvidence(
            type="software",
            name="Tor Browser",
            host="wrk-aturing",
            path=r"C:\Users\Amber\Desktop\Tor Browser\Browser\firefox.exe",
            detected=True,
            observation_ids=["obs-tor-1"],
        )
        evidence_state.set_attribute("software_version", AnswerAttributeState.NOT_OBSERVED)

        cards = EvidenceGroupBuilder().build_cards([obs])

        obj = HuntObjective(
            request_id="req-tor-1",
            statement="What is the version of Tor Browser?",
            answer_spec={"mode": "lookup", "answer_type": "software_version", "required_fields": ["ProductVersion"]},
        )
        hyp = Hypothesis(
            id="hyp-1",
            statement="Amber Turing installed Tor Browser on wrk-aturing",
            status=HypothesisStatus.LIVE,
        )
        state = HuntState(
            objective=obj,
            hypotheses=[hyp],
            evidence_cards=cards,
            evidence_state=evidence_state,
            observations=[obs],
            stopping_decision=StoppingDecision.STOP_RESOLVED,
        )

        ledger = ObservationLedger()
        ledger.add_observation(obs)

        account = build_final_hunt_account(state, ledger=ledger)

        assert account.outcome == HuntOutcome.PARTIALLY_SUPPORTED
        assert account.answer_status == AnswerStatus.PARTIALLY_SUPPORTED
        assert "Tor Browser was observed on wrk-aturing" in account.answer.get("explanation", "")
        assert "Requested version: Not available in the retrieved telemetry." in account.answer.get("explanation", "")

        report = render_analyst_report(account)

        assert "**Result:** `PARTIALLY_SUPPORTED`" in report
        assert "**Answer Status:** `PARTIALLY_SUPPORTED`" in report
        assert "Tor Browser was observed on wrk-aturing" in report
        assert "Requested version: Not available in the retrieved telemetry." in report
        assert "**Evidence Citation:**" in report
        assert "Evidence: obs-tor-1" in report
        assert "INCONCLUSIVE" not in report
