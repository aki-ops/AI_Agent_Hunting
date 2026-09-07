"""Unit tests for Phase 5: Strict UTF-8 Encoding Integrity and Vietnamese text handling."""
from __future__ import annotations

from pathlib import Path

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    EvidenceCard,
    EvidenceRequirementV4,
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.engine import persist_hunt_artifacts
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_final_hunt_account


def test_vietnamese_hunt_request_and_artifacts_have_zero_mojibake(tmp_path: Path):
    """Vietnamese hunt request 'Tôi thấy website bị tấn công' must render and persist without mojibake."""
    vn_text = "Tôi thấy website bị tấn công và có dấu hiệu tải webshell"
    vn_host = "máy-chủ-web-01"

    request = HuntRequest(
        id="hunt-vn-001",
        kind=HuntRequestKind.NL_QUESTION,
        content=vn_text,
    )

    scope = ProviderScope(provider_id="splunk", native_partition={"index": "main"})
    ledger = ObservationLedger()

    obs = Observation(
        id="obs-vn-1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": vn_host, "cmdline": "cmd.exe /c echo 'bị tấn công'"},
        raw_event={"thông_báo": "Phát hiện tiến trình độc hại trên máy chủ"},
        query_id="q-vn-1",
    )
    ledger.add_observation(obs)

    hyp = Hypothesis(
        id="hyp-vn-1",
        statement="Kẻ tấn công đã chiếm quyền điều khiển máy chủ web",
        status=HypothesisStatus.SUPPORTED,
    )
    req = EvidenceRequirementV4(
        id="req-vn-1",
        description="Thực thi lệnh shell bất thường trên máy chủ web",
        evidence_type="process_execution",
    )
    card = EvidenceCard(
        id="card-vn-1",
        fingerprint="fp-vn",
        fact_type="process_execution",
        summary=f"Tiến trình lạ thực thi trên {vn_host}",
        why_it_matters="Dấu hiệu kẻ tấn công leo thang đặc quyền",
        count=1,
        entity_summary={"hosts": [vn_host]},
        field_summary={"cmdlines": ["cmd.exe /c echo 'bị tấn công'"]},
    )

    state = HuntState(
        objective=HuntObjective(request_id="hunt-vn-001", statement=vn_text),
        hypotheses=[hyp],
        requirements=[req],
        evidence_cards=[card],
        observations=[obs],
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )

    account = build_final_hunt_account(state, ledger=ledger)
    report = render_final_hunt_account(account)

    # 1. Report UTF-8 check
    assert "Tôi thấy website bị tấn công" in report
    assert "Kẻ tấn công đã chiếm quyền điều khiển máy chủ web" in report
    assert "máy-chủ-web-01" in report
    assert "bá»‹ tÃ¢n cÃ´ng" not in report
    assert "chiáº¿m quyá»n" not in report

    # 2. Artifact persistence check
    artifact_dir = tmp_path / "artifacts" / "hunt-vn-001"
    persist_hunt_artifacts(artifact_dir, request, state, ledger, account, report)

    assert (artifact_dir / "request.json").exists()
    assert (artifact_dir / "hypotheses.json").exists()
    assert (artifact_dir / "observations.jsonl").exists()
    assert (artifact_dir / "final_report.md").exists()

    # Read back files with utf-8 encoding and verify NO mojibake or escaped unicode
    raw_req = (artifact_dir / "request.json").read_text(encoding="utf-8")
    assert "Tôi thấy website bị tấn công" in raw_req
    assert "\\u" not in raw_req

    raw_hyps = (artifact_dir / "hypotheses.json").read_text(encoding="utf-8")
    assert "Kẻ tấn công đã chiếm quyền điều khiển máy chủ web" in raw_hyps
    assert "\\u" not in raw_hyps

    raw_obs = (artifact_dir / "observations.jsonl").read_text(encoding="utf-8")
    assert "Phát hiện tiến trình độc hại trên máy chủ" in raw_obs
    assert "\\u" not in raw_obs

    raw_md = (artifact_dir / "final_report.md").read_text(encoding="utf-8")
    assert "Tôi thấy website bị tấn công" in raw_md
    assert "bá»‹" not in raw_md
