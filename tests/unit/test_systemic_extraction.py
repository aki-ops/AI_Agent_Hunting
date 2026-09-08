"""End-to-end integration tests for systemic telemetry attribute extraction and answer derivation."""
from __future__ import annotations

import pytest

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, FinalHuntAccount, AnswerStatus
from hunting.contracts.observations import EpistemicType, Observation, Provenance
from hunting.evidence.grouping import EvidenceGroupBuilder
from hunting.reporter.builder import _derive_answer, build_final_hunt_account
from hunting.evidence.answer_verifier import verify_answer
from hunting.contracts.hunt import HuntState, HuntRequest, HuntRequestKind


def _make_obs(fields: dict, obs_id: str = "obs-001", query_id: str = "q-001") -> Observation:
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv2"}, scope_id="splunk_botsv2")
    return Observation(
        id=obs_id,
        cell_id="cell-1",
        query_id=query_id,
        timestamp="2017-08-24T04:20:44.000Z",
        provider_scope=scope,
        native_type="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        epistemic_type=EpistemicType.OBSERVED,
        fields=fields,
        provenance=Provenance(query_id=query_id, collector="splunk", ingest_time="2017-08-24T04:20:44.000Z"),
    )


def test_systemic_tor_version_derivation_from_installer_filename() -> None:
    """Ensure that an event with version in TargetFilename yields an ANSWERED verdict with value 7.0.4."""
    # 1. Simulate Sysmon event where version is in TargetFilename, no ProductVersion column
    obs1 = _make_obs({
        "host": "wrk-aturing",
        "TargetFilename": r"C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe",
        "Image": r"C:\Windows\explorer.exe",
    }, obs_id="obs-101", query_id="qp-discovery-0")

    obs2 = _make_obs({
        "host": "wrk-aturing",
        "Path": r"C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe",
        "Image": r"firefox.exe",
    }, obs_id="obs-102", query_id="qp-discovery-0")

    # 2. Build EvidenceCards via EvidenceGroupBuilder
    builder = EvidenceGroupBuilder()
    cards = builder.build_cards([obs1, obs2])
    assert len(cards) >= 1

    # Verify that card captures version or has all_observation_ids
    assert any("obs-101" in card.all_observation_ids for card in cards)

    # 3. Derive Answer
    objective = HuntObjective(
        request_id="test-req",
        statement="What is the Tor Browser version?",
        answer_spec={
            "mode": "lookup",
            "answer_type": "software_version",
            "required_fields": ["ProductVersion"],
            "question": "What is the Tor Browser version?",
        },
    )
    answer = _derive_answer(objective, cards, [obs1, obs2])
    assert answer["status"] == "ANSWERED"
    assert answer["value"] == "7.0.4"
    assert len(answer["card_ids"]) >= 1

    # 4. Verify Answer
    verified = verify_answer(
        answer=answer,
        answer_spec=objective.answer_spec,
        cards=cards,
        observations=[obs1, obs2],
        query_complete=True,
    )
    assert verified["status"] == "ANSWERED"
    assert verified["value"] == "7.0.4"
