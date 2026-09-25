"""Act export: parser gate, append-only backlog, stakeholder note, detection tier."""
from __future__ import annotations

import json
from types import SimpleNamespace

from hunting.act.act import commit_act, validate_spl
from hunting.act_input import account_to_act_input
from hunting.contracts.hunt import Hypothesis, HypothesisStatus, StoppingDecision


def test_write_command_is_invalid_and_backlog_appends(tmp_path):
    first = commit_act(
        source="hunt-1",
        spls=["search index=main logon_type=10 | head 20"],
        backlog=[{"kind": "hypothesis", "text": "service account interactive logon"}],
        stakeholder=["One hypothesis remains inconclusive."],
        detection_tier="report",
        export_dir=tmp_path,
        gaps=["authentication index was missing"],
    )
    assert first["validations"] == ["DRAFT"]
    assert first["detection_tier"] == "report"
    assert "inconclusive" in (tmp_path / "stakeholder.md").read_text(encoding="utf-8")
    second = commit_act(
        source="hunt-1",
        spls=["search index=main | delete"],
        backlog=[{"kind": "follow_up", "text": "re-check coverage"}],
        stakeholder=["Second note."],
        detection_tier="rule",
        export_dir=tmp_path,
    )
    assert second["validations"] == ["INVALID"]
    stored = json.loads((tmp_path / "backlog.json").read_text(encoding="utf-8"))
    assert [item["kind"] for item in stored] == ["hypothesis", "gap", "follow_up"]
    assert len(stored) == 3


def test_live_parser_can_validate_a_read_only_search():
    result = validate_spl("search index=main | head 1", lambda _spl: {"valid": True, "messages": []})
    assert result.status == "VALIDATED"


def test_account_adapter_keeps_gaps_and_citations():
    account = SimpleNamespace(
        request_id="hunt-logon",
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE,
        hypotheses=[Hypothesis(id="h1", statement="Service accounts log on interactively", status=HypothesisStatus.LIVE)],
        observation_citations=["obs-1"],
        gap_breakdown={"index": ["wineventlog was not searched"]},
        queries=[{"id": "q1", "native_query": "search index=wineventlog EventCode=4624"}],
    )
    payload = account_to_act_input(account, {"source": "derived"})
    assert payload["detection_tier"] == "report"
    assert payload["gaps"] == ["wineventlog was not searched"]
    assert payload["prepare"]["source"] == "derived"
    assert payload["spls"] == ['search index=wineventlog EventCode=4624']
