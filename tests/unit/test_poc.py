"""Unit tests for the PoC-driven Auto-Hunt Agent."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunting.controller.cost import LLMUsageTracker
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.poc import PocAgent, get_poc, list_pocs, render_poc_report


def test_library_exposes_expected_pocs():
    pocs = list_pocs()
    ids = {p.poc_id for p in pocs}
    assert "poc-phishing-powershell-enc" in ids
    assert "poc-c2-beacon" in ids
    assert "poc-office-macro" in ids
    assert "poc-credential-phish" in ids


def test_get_poc_raises_on_unknown_id():
    with pytest.raises(KeyError):
        get_poc("not-a-real-poc")


def test_poc_steps_have_required_fields():
    for poc in list_pocs():
        assert poc.name
        assert poc.summary
        assert poc.steps, f"{poc.poc_id} has no steps"
        # Hunt plan: built-in PoCs must carry ABLE context (reporting metadata)
        assert poc.topic, f"{poc.poc_id} missing topic"
        assert poc.behavior, f"{poc.poc_id} missing ABLE behavior"
        assert poc.location, f"{poc.poc_id} missing ABLE location"
        assert poc.evidence, f"{poc.poc_id} missing ABLE evidence"
        assert poc.scope, f"{poc.poc_id} missing scope"
        assert poc.max_duration, f"{poc.poc_id} missing max_duration"
        assert poc.plan, f"{poc.poc_id} missing plan"
        assert poc.research_refs, f"{poc.poc_id} missing research_refs"
        for step in poc.steps:
            assert step.step_id
            assert step.target_field
            assert step.value is not None
            assert step.op


def test_poc_renders_to_dict():
    poc = get_poc("poc-phishing-powershell-enc")
    render = poc.render()
    assert render["poc_id"] == "poc-phishing-powershell-enc"
    assert render["kind"] == "ttp"
    assert len(render["steps"]) == 3
    assert render["able"]["behavior"]
    assert render["able"]["location"]
    assert render["able"]["evidence"]
    assert render["scope"]
    assert render["plan"]


def test_poc_file_accepts_peak_prepare_fields(tmp_path: Path):
    """Analyst JSON PoCs may carry hunt-plan fields (topic/ABLE/scope/plan)."""
    from hunting.poc import poc_from_file

    spec = tmp_path / "peak-poc.json"
    spec.write_text(
        """{
            "poc_id": "poc-peak-test",
            "name": "Hunt-plan test",
            "kind": "ttp",
            "summary": "demo",
            "topic": "phishing payload execution",
            "able": {"actor": "", "behavior": "T1566 -> T1059.001",
                      "location": "workstations", "evidence": "process telemetry"},
            "research_refs": ["Splunk SURGe PEAK"],
            "scope": "fleet in window",
            "max_duration": "3d",
            "plan": "search_text over process telemetry",
            "steps": [
                {"step_id": "s1", "description": "x", "target_field": "image",
                 "op": "EQUALS", "value": "powershell.exe", "source_kind": "process"}
            ],
            "references": ["MITRE T1059.001"]
        }""",
        encoding="utf-8",
    )
    poc = poc_from_file(spec)
    assert poc.topic == "phishing payload execution"
    assert poc.behavior == "T1566 -> T1059.001"
    assert poc.location == "workstations"
    assert poc.evidence == "process telemetry"
    assert poc.scope == "fleet in window"
    assert poc.max_duration == "3d"
    assert poc.plan == "search_text over process telemetry"
    assert poc.research_refs == ["Splunk SURGe PEAK"]
    # actor may be empty (unknown actor is valid per ABLE)
    assert poc.actor == ""
    rendered = poc.render()
    assert rendered["able"]["behavior"] == "T1566 -> T1059.001"


def test_poc_file_prepare_fields_default_empty(tmp_path: Path):
    """Old JSON PoCs without hunt-plan fields still load (backward compatible)."""
    from hunting.poc import poc_from_file

    spec = tmp_path / "legacy.json"
    spec.write_text(
        """{"poc_id": "poc-legacy", "name": "x", "kind": "behavior",
            "summary": "x", "steps": [{"step_id": "s1", "description": "x",
            "target_field": "user", "op": "EQUALS", "value": "admin",
            "source_kind": "process"}]}""",
        encoding="utf-8",
    )
    poc = poc_from_file(spec)
    assert poc.topic == ""
    assert poc.behavior == ""
    assert poc.plan == ""


def _seed_cdb(adapter: CdbAdapter) -> None:
    """Insert one matching row and one negative row for the PowerShell PoC."""
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z",
            "host": "DESKTOP-VICTIM1",
            "user": "CORP\\alice",
            "image": "powershell.exe",
            "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc JABhID0A...",
            "raw_ref": "edr-001",
            "native_type": "process",
        },
        {
            "timestamp": "2026-09-01T11:00:00Z",
            "host": "OTHER-HOST",
            "user": "CORP\\bob",
            "image": "notepad.exe",
            "cmdline": "notepad.exe",
            "raw_ref": "edr-002",
            "native_type": "process",
        },
    ])


def test_operator_helpers_exact_equals():
    from hunting.poc.agent import _apply_op
    assert _apply_op("powershell.exe", "EQUALS", "powershell.exe")
    assert _apply_op("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "EQUALS", "powershell.exe")
    assert not _apply_op("splunk-powershell.exe", "EQUALS", "powershell.exe")
    assert not _apply_op(None, "EQUALS", "powershell.exe")
    assert _apply_op("abc -Enc xyz", "CONTAINS", "-enc")
    assert not _apply_op("abc", "CONTAINS", "-enc")


def test_exists_empty_value_matches_nothing(tmp_path: Path):
    """EXISTS with an empty value must not match arbitrary rows (eval FP fix)."""
    from hunting.poc.library import POC_LIBRARY
    from hunting.poc.models import FieldOp, PoC, PocKind, TestStep

    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    poc = PoC(
        poc_id="poc-exists-empty-test", name="x", kind=PocKind.BEHAVIOR,
        summary="x",
        steps=[TestStep(step_id="s1", description="x", target_field="image",
                        op=FieldOp.EXISTS, value="", source_kind="process")],
    )
    POC_LIBRARY[poc.poc_id] = poc
    try:
        agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
        result = agent.run(poc.poc_id, time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
        assert result.verdict == "EMPTY"
        assert result.total_observations == 0
    finally:
        del POC_LIBRARY[poc.poc_id]


def test_exact_equals_rejects_splunk_prefix(tmp_path: Path):
    """splunk-powershell.exe must not match EQUALS powershell.exe."""
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-09-01T10:14:30Z", "host": "H", "user": "u",
        "image": "splunk-powershell.exe",
        "cmdline": '"C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-powershell.exe"',
        "raw_ref": "e1", "native_type": "process",
    }])
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "EMPTY"


def test_poc_agent_runs_against_cdb(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)

    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")

    assert result.verdict == "MATCHED"
    assert result.total_observations >= 1
    assert "s1-powershell-enc" in result.matched_step_ids
    assert "s2-powershell-hidden" in result.matched_step_ids
    assert "s3-powershell-encoded" in result.matched_step_ids
    assert result.llm_calls == 0
    assert result.ledger_path is not None

    ledger = json.loads(Path(result.ledger_path).read_text(encoding="utf-8"))
    assert "graph" in ledger
    assert "result" in ledger
    assert ledger["result"]["verdict"] == "MATCHED"


def test_poc_agent_empty_no_escalation(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z",
            "host": "DESKTOP-VICTIM1",
            "user": "CORP\\alice",
            "image": "notepad.exe",
            "cmdline": "notepad.exe",
            "raw_ref": "edr-002",
            "native_type": "process",
        }
    ])
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "EMPTY"
    assert result.llm_calls == 0


def test_poc_agent_escalates_when_empty(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    tracker = LLMUsageTracker(model_name="stub")

    def fake_llm(question: str, max_tokens: int) -> str:
        return "No encoded PowerShell observed in the window."

    agent = PocAgent(adapter=adapter, llm_caller=fake_llm, llm_tracker=tracker, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "ESCALATED"
    assert result.llm_calls == 1
    assert result.escalation_called is True
    assert tracker.call_count == 1


def test_poc_chain_runs_multiple_pocs(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    results = agent.run_chain(
        ["poc-phishing-powershell-enc", "poc-c2-beacon"],
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )
    assert len(results) == 2
    assert results[0].poc_id == "poc-phishing-powershell-enc"
    assert results[1].poc_id == "poc-c2-beacon"


def test_poc_report_renders_markdown(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    poc_render = get_poc(result.poc_id).render()
    report = render_poc_report(result, poc_render)
    assert "# PoC Hunt Report" in report
    assert "MATCHED" in report
    assert "powershell.exe" in report


def _stub_judge_tp(prompt: str, max_tokens: int) -> str:
    return json.dumps({
        "verdict": "TRUE_POSITIVE",
        "confidence": 0.85,
        "rationale": "Parent image is OUTLOOK.EXE, user is interactive, time matches email arrival.",
        "notes": ["parent=outlook", "user=interactive"],
    })


def _stub_judge_fp(prompt: str, max_tokens: int) -> str:
    return json.dumps({
        "verdict": "FALSE_POSITIVE",
        "confidence": 0.9,
        "rationale": "Parent is Microsoft Configuration Manager, scheduled baseline deployment.",
        "notes": ["parent=sccm"],
    })


def test_judge_disabled_by_default(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.judgment is None
    assert result.judgment_llm_calls == 0


def test_judge_true_positive(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_tp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.judgment is not None
    assert result.judgment.verdict == "TRUE_POSITIVE"
    assert result.judgment.confidence == 0.85
    assert "outlook" in result.judgment.rationale.lower()


def test_judge_false_positive_admin_script(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z",
            "host": "SCCM-SERVER",
            "user": "CORP\\svc_admin",
            "image": "powershell.exe",
            "cmdline": "powershell.exe -NoP -W Hidden -Enc Zm9v",
            "parent_image": "C:\\Program Files\\Microsoft Configuration Manager\\bin\\CmRcViewer.exe",
            "raw_ref": "sccm-001",
            "native_type": "process",
        }
    ])
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_fp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "MATCHED"
    assert result.judgment.verdict == "FALSE_POSITIVE"
    assert result.judgment.confidence == 0.9


def test_judge_no_signal_when_empty(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_tp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "EMPTY"
    assert result.judgment.verdict == "NO_SIGNAL"
    assert result.judgment_llm_calls == 0


def test_judge_parser_handles_malformed_response():
    from hunting.poc import parse_judgment
    j = parse_judgment("not even json")
    assert j.verdict == "INCONCLUSIVE"
    assert j.confidence == 0.0


def test_judge_parser_strips_markdown_fence():
    from hunting.poc import parse_judgment
    raw = "```json\n{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.7,\"rationale\":\"x\"}\n```"
    j = parse_judgment(raw)
    assert j.verdict == "FALSE_POSITIVE"
    assert j.confidence == 0.7


def test_judge_parser_rejects_unknown_verdict():
    from hunting.poc import parse_judgment
    j = parse_judgment(json.dumps({"verdict": "MAYBE", "confidence": 0.5}))
    assert j.verdict == "INCONCLUSIVE"


def test_judge_report_section(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_tp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    poc_render = get_poc(result.poc_id).render()
    report = render_poc_report(result, poc_render)
    assert "LLM Judge" in report
    assert "TRUE_POSITIVE" in report


def test_poc_file_loads_and_registers(tmp_path: Path):
    """An analyst-authored PoC in JSON form is registered in the library."""
    from hunting.poc import list_pocs, poc_from_file

    spec = tmp_path / "my-poc.json"
    spec.write_text(
        """{
            "poc_id": "poc-my-test",
            "name": "Test JSON PoC",
            "kind": "behavior",
            "summary": "demo",
            "steps": [
                {"step_id": "s1", "description": "x", "target_field": "user", "op": "EQUALS", "value": "admin", "source_kind": "process"}
            ],
            "references": ["MITRE T1110"]
        }""",
        encoding="utf-8",
    )

    before = {p.poc_id for p in list_pocs()}
    poc = poc_from_file(spec)
    after = {p.poc_id for p in list_pocs()}
    assert poc.poc_id == "poc-my-test"
    assert "poc-my-test" not in before
    assert "poc-my-test" in after
    assert poc.kind.value == "behavior"
    assert poc.steps[0].value == "admin"
    assert poc.references == ["MITRE T1110"]


def test_poc_file_rejects_invalid_kind(tmp_path: Path):
    from hunting.poc import poc_from_file

    spec = tmp_path / "bad.json"
    spec.write_text(
        """{"poc_id": "poc-bad", "name": "x", "kind": "wrong", "summary": "x", "steps": [{"step_id": "s1", "description": "x", "target_field": "user", "op": "EQUALS", "value": "x", "source_kind": "process"}]}""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        poc_from_file(spec)


def test_poc_file_rejects_invalid_op(tmp_path: Path):
    from hunting.poc import poc_from_file

    spec = tmp_path / "bad-op.json"
    spec.write_text(
        """{"poc_id": "poc-badop", "name": "x", "kind": "ttp", "summary": "x", "steps": [{"step_id": "s1", "description": "x", "target_field": "user", "op": "WILDCARD", "value": "x", "source_kind": "process"}]}""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        poc_from_file(spec)


def test_able_host_filter_drives_the_query(tmp_path: Path):
    """A concrete location host is a predicate, not a report label."""
    from hunting.poc.library import POC_LIBRARY
    from hunting.poc.models import FieldOp, PoC, PocKind, TestStep

    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:00:00Z", "host": "DESKTOP-VICTIM1", "user": "CORP\\alice",
            "image": "cmd.exe", "cmdline": "cmd.exe /c whoami", "raw_ref": "a", "native_type": "process",
        },
        {
            "timestamp": "2026-09-01T10:05:00Z", "host": "OTHER-HOST", "user": "CORP\\bob",
            "image": "cmd.exe", "cmdline": "cmd.exe /c whoami", "raw_ref": "b", "native_type": "process",
        },
    ])
    poc = PoC(
        poc_id="poc-able-host", name="host drive", kind=PocKind.BEHAVIOR, summary="x",
        topic="lateral tool", behavior="cmd.exe execution", location="DESKTOP-VICTIM1",
        evidence="process telemetry", research_refs=["PEAK"], scope="one host",
        max_duration="3d", plan="search cmd.exe on the named host",
        steps=[TestStep(step_id="s1", description="cmd", target_field="image",
                        op=FieldOp.EQUALS, value="cmd.exe", source_kind="process")],
    )
    POC_LIBRARY[poc.poc_id] = poc
    try:
        result = PocAgent(adapter=adapter, ledger_dir=tmp_path).run(
            poc.poc_id, time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        )
        assert result.verdict == "MATCHED"
        assert result.total_observations == 1
        assert result.step_results[0].rows[0]["host"] == "DESKTOP-VICTIM1"
        assert result.ir_escalated is True
        assert result.ir_escalation_path
    finally:
        del POC_LIBRARY[poc.poc_id]


def test_refine_pivots_a_partial_match(tmp_path: Path):
    from hunting.poc.library import POC_LIBRARY
    from hunting.poc.models import FieldOp, PoC, PocKind, TestStep

    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:00:00Z", "host": "WKSTN-1", "user": "alice",
            "image": "powershell.exe", "cmdline": "powershell.exe -Enc QQ",
            "raw_ref": "p", "native_type": "process",
        },
        {
            "timestamp": "2026-09-01T10:01:00Z", "host": "WKSTN-1", "user": "alice",
            "image": "cmd.exe", "cmdline": "cmd.exe /c whoami",
            "raw_ref": "c", "native_type": "process",
        },
        {
            "timestamp": "2026-09-01T10:02:00Z", "host": "WKSTN-9", "user": "mallory",
            "image": "cmd.exe", "cmdline": "cmd.exe /c whoami",
            "raw_ref": "o", "native_type": "process",
        },
    ])
    poc = PoC(
        poc_id="poc-refine-pivot", name="pivot", kind=PocKind.BEHAVIOR, summary="x",
        topic="encoded powershell", behavior="encoded powershell then cmd",
        location="workstations", evidence="process telemetry",
        research_refs=["PEAK"], scope="fleet", max_duration="3d", plan="two steps",
        steps=[
            TestStep(step_id="s1", description="ps", target_field="image",
                     op=FieldOp.EQUALS, value="powershell.exe", source_kind="process"),
            TestStep(step_id="s2", description="cmd", target_field="image",
                     op=FieldOp.EQUALS, value="cmd.exe", source_kind="process"),
        ],
    )
    POC_LIBRARY[poc.poc_id] = poc
    try:
        result = PocAgent(adapter=adapter, ledger_dir=tmp_path).run(
            poc.poc_id, time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        )
        cmd = next(step for step in result.step_results if step.step_id == "s2")
        assert cmd.pass_index == 2
        assert cmd.row_count == 1
        assert cmd.rows[0]["host"] == "WKSTN-1"
        assert any(entry.get("phase") == "refine" for entry in result.refine_log)
    finally:
        del POC_LIBRARY[poc.poc_id]


def test_prepare_gate_rejects_a_plan_without_able(tmp_path: Path):
    from hunting.peak import PrepareError
    from hunting.poc.library import POC_LIBRARY
    from hunting.poc.models import FieldOp, PoC, PocKind, TestStep

    adapter = CdbAdapter(":memory:")
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    bare = PoC(
        poc_id="poc-bare-prepare", name="x", kind=PocKind.BEHAVIOR, summary="x",
        steps=[TestStep(step_id="s1", description="x", target_field="user",
                        op=FieldOp.EQUALS, value="admin", source_kind="process")],
    )
    POC_LIBRARY[bare.poc_id] = bare
    try:
        with pytest.raises(PrepareError):
            agent.run(bare.poc_id, time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z", enforce_prepare=True)
    finally:
        del POC_LIBRARY[bare.poc_id]


def test_max_duration_clamps_the_trailing_window():
    from hunting.peak import enforce_max_duration

    window, note = enforce_max_duration(
        "2026-09-01T00:00:00Z/2026-09-11T00:00:00Z",
        "3d",
    )
    assert window == "2026-09-08T00:00:00Z/2026-09-11T00:00:00Z"
    assert "clamped" in note


def test_hunt_plan_yaml_round_trip(tmp_path: Path):
    from hunting.peak import dump_hunt_plan, load_hunt_plan

    path = tmp_path / "plan.yaml"
    dump_hunt_plan({
        "topic": "exfil",
        "research_refs": ["PEAK"],
        "actor": "",
        "behavior": "DNS tunneling",
        "location": "finance hosts",
        "evidence": "dns telemetry",
        "scope": "finance vlan",
        "max_duration": "3d",
        "plan": "stack dns queries",
    }, path)
    loaded = load_hunt_plan(path)
    assert loaded["behavior"] == "DNS tunneling"
    assert loaded["research_refs"] == ["PEAK"]
    assert loaded["max_duration"] == "3d"


def test_compiler_puts_able_constraints_on_the_anchor():
    from hunting.poc.compiler import compile_poc

    graph = compile_poc(
        get_poc("poc-phishing-powershell-enc"),
        request_id="req-able",
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )
    anchor = graph.variables[0]
    keys = {item.key for item in anchor.constraints}
    assert "able_behavior" in keys
    assert "able_evidence" in keys
    assert any("powershell.exe" in item for item in graph.assumptions)


def test_analytic_poc_runs_against_botsv1_sample(tmp_path: Path):
    """An analyst PoC loaded from JSON finds the BOTS v1 brute-force rows."""
    from hunting.m5_adapter import CdbAdapter
    from hunting.poc import poc_from_file
    from scripts.seed_botsv1_sample import BOTS_SAMPLE

    adapter = CdbAdapter(":memory:")
    adapter.insert_events(BOTS_SAMPLE)

    spec = tmp_path / "bruteforce.json"
    spec.write_text(
        """{
            "poc_id": "poc-bruteforce-test",
            "name": "BF test",
            "kind": "behavior",
            "summary": "BOTS v1 brute force",
            "steps": [{"step_id": "s1-failed", "description": "Failed logon",
                       "target_field": "cmdline", "op": "CONTAINS",
                       "value": "Logon Failed", "source_kind": "authentication"}],
            "references": ["MITRE T1110"]
        }""",
        encoding="utf-8",
    )

    poc = poc_from_file(spec)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run(
        poc.poc_id,
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
    )
    assert result.verdict == "MATCHED"
    assert result.total_observations >= 5
