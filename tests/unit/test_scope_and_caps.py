"""Regression tests for: hidden ABLE scope, retrieval caps, MATCHES/EXISTS retrieval, SPL window, event-type coverage."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunting.act import window_to_splunk
from hunting.adapters.cdb_adapter import CdbAdapter
from hunting.cli import main
from hunting.poc.agent import _regex_literal
from hunting.recommend import CLOSE, COLLECT, INVESTIGATE, EvidenceSummary, StepEvidence, decide
from tests.unit.test_pipeline import _poc

WINDOW = "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z"


def _poc_file(tmp_path: Path, *, location: str, steps: list[dict], evidence: str = "telemetry") -> Path:
    poc = {
        "poc_id": "poc-scope-unit", "name": "n", "kind": "ttp", "summary": "s", "topic": "t",
        "able": {"actor": "", "behavior": "b", "location": location, "evidence": evidence},
        "research_refs": ["r"], "scope": "s", "max_duration": "3d", "plan": "p", "time_window": WINDOW,
        "steps": steps,
    }
    path = tmp_path / "poc.json"
    path.write_text(json.dumps(poc), encoding="utf-8")
    return path


def _run(tmp_path: Path, poc_file: Path, db: Path) -> dict:
    out = tmp_path / "out"
    assert main(["--poc", str(poc_file), "--db", str(db), "--offline", "--out", str(out)]) == 0
    return json.loads((out / "poc-scope-unit" / "recommendation.json").read_text(encoding="utf-8"))


def _web(i: int, host: str = "H1") -> dict:
    return {
        "timestamp": f"2026-09-01T10:{i // 60:02d}:{i % 60:02d}Z", "host": host, "domain": "d.com",
        "cmdline": f"site=d.com uri=/acunetix-{i}", "native_type": "web_request", "raw_ref": f"w{i}",
    }


# --- regex retrieval ------------------------------------------------------------

@pytest.mark.parametrize(
    ("pattern", "literal"),
    [
        ("acunet.x", "acunet"),
        ("acunetix.*test", "acunetix"),
        (r"\d+abcd", "abcd"),
        ("ab?cde", "cde"),
        ("evil|bad", None),  # alternation: no single mandatory literal
        ("x*", None),
        (r"[a-f]+", None),
    ],
)
def test_regex_literal_only_narrows_retrieval(pattern, literal):
    assert _regex_literal(pattern) == literal


def test_matches_with_real_regex_metacharacters_is_found(tmp_path: Path):
    db = tmp_path / "t.sqlite"
    CdbAdapter(str(db)).insert_events([_web(i) for i in range(5)])
    step = {"step_id": "s1", "description": "d", "target_field": "cmdline", "op": "MATCHES",
            "value": r"acunet.x-\d+", "source_kind": "web"}
    data = _run(tmp_path, _poc_file(tmp_path, location="web", steps=[step]), db)
    assert data["evidence"]["observations"] == 5  # a regex used to be sent to LIKE verbatim and match nothing


# --- row cap is reported, not hidden -----------------------------------------------

def test_row_cap_is_reported_with_the_true_total(tmp_path: Path):
    db = tmp_path / "t.sqlite"
    CdbAdapter(str(db)).insert_events([_web(i) for i in range(150)])
    step = {"step_id": "s1", "description": "d", "target_field": "cmdline", "op": "CONTAINS",
            "value": "acunetix", "source_kind": "web"}
    data = _run(tmp_path, _poc_file(tmp_path, location="web", steps=[step]), db)
    s = data["evidence"]["steps"][0]
    assert (s["row_count"], s["matched_total"], s["scan_truncated"]) == (100, 150, False)
    assert data["evidence"]["capped_steps"] == ["s1"]
    assert any("chỉ hiển thị 100 bản ghi trong 150" in c for c in data["caveats"])
    md = (tmp_path / "out" / "poc-scope-unit" / "recommendation.md").read_text(encoding="utf-8")
    assert "100 / 150" in md


def test_exists_is_pushed_down_so_the_scan_cap_cannot_hide_it(tmp_path: Path):
    db = tmp_path / "t.sqlite"
    rows = [
        {"timestamp": f"2026-09-01T10:{i // 60:02d}:{i % 60:02d}Z", "host": "H1", "native_type": "process_creation",
         "image": "", "raw_ref": f"p{i}"}
        for i in range(2500)
    ]
    rows.append({"timestamp": "2026-09-01T12:00:00Z", "host": "H1", "native_type": "process_creation",
                 "image": "a.exe", "raw_ref": "last"})
    CdbAdapter(str(db)).insert_events(rows)
    step = {"step_id": "s1", "description": "d", "target_field": "image", "op": "EXISTS",
            "value": "present", "source_kind": "process"}
    data = _run(tmp_path, _poc_file(tmp_path, location="proc", steps=[step]), db)
    assert data["evidence"]["observations"] == 1


# --- hidden host scope is disclosed and probed -----------------------------------------

def _auth_db(tmp_path: Path, failed_elsewhere: bool) -> Path:
    db = tmp_path / "t.sqlite"
    rows = [{"timestamp": "2026-09-01T10:00:00Z", "host": "OTHER1", "user": "u", "native_type": "authentication",
             "event_id": "4624", "cmdline": "Logon Success", "raw_ref": "a1"}]
    if failed_elsewhere:
        rows.append({"timestamp": "2026-09-01T10:01:00Z", "host": "OTHER1", "user": "u", "native_type": "authentication",
                     "event_id": "4625", "cmdline": "Logon Failed", "raw_ref": "a2"})
    CdbAdapter(str(db)).insert_events(rows)
    return db


_AUTH_STEP = {"step_id": "s1", "description": "d", "target_field": "cmdline", "op": "CONTAINS",
              "value": "Logon Failed", "source_kind": "authentication"}


def test_host_scope_with_no_data_is_disclosed_and_probed_without_the_filter(tmp_path: Path):
    db = _auth_db(tmp_path, failed_elsewhere=False)
    data = _run(tmp_path, _poc_file(tmp_path, location="we9999srv authentication log", steps=[_AUTH_STEP]), db)
    ev = data["evidence"]
    assert ev["scope"]["host"] == "we9999srv"
    assert ev["scope_empty_sources"] == ["authentication"]
    assert ev["source_hosts"]["authentication"][0][0] == "OTHER1"
    assert ev["unscoped_probe"]["observations"] == 0
    assert data["disposition"] == CLOSE
    assert any("KHÔNG lọc host: 0 bản ghi" in r for r in data["reasons"])
    assert any("authentication/4624" in c for c in data["caveats"])  # event types present, no 4625
    assert any("giới hạn bởi các điều kiện suy ra từ ABLE" in c for c in data["caveats"])
    assert (tmp_path / "out" / "poc-scope-unit" / "unscoped_probe").is_dir()


def test_activity_found_only_outside_the_host_scope_is_not_closed(tmp_path: Path):
    db = _auth_db(tmp_path, failed_elsewhere=True)
    data = _run(tmp_path, _poc_file(tmp_path, location="we9999srv authentication log", steps=[_AUTH_STEP]), db)
    assert data["evidence"]["observations"] == 0
    assert data["evidence"]["unscoped_probe"]["observations"] == 1
    assert (data["disposition"], data["confidence"]) == (INVESTIGATE, "LOW")
    assert data["decision_required"] is True


def test_scope_empty_without_a_probe_is_collect_data():
    steps = [StepEvidence("s0", "d", "f OP v", "process", 0, 100, source_rows_in_scope=0)]
    ev = EvidenceSummary(
        window=WINDOW, steps=steps, matched_steps=0, total_steps=1, observations=0, first_seen=None,
        last_seen=None, pivots={}, top_values={}, samples=[], scope={"host": "H9"},
        source_hosts={"process": [("H1", 100)]},
    )
    rec = decide(_poc(), ev, None)
    assert (rec.disposition, rec.confidence) == (COLLECT, "HIGH")
    assert any("`H9`" in r and "H1 (100)" in r for r in rec.reasons)


# --- coverage helpers and SPL window --------------------------------------------------

def test_cdb_source_breakdown_and_hosts(tmp_path: Path):
    db = _auth_db(tmp_path, failed_elsewhere=True)
    adapter = CdbAdapter(str(db))
    assert adapter.source_presence(WINDOW, "authentication") == 2
    assert adapter.source_presence(WINDOW, "authentication", host="NOPE") == 0
    assert dict(adapter.source_breakdown(WINDOW, "authentication")) == {"authentication/4624": 1, "authentication/4625": 1}
    assert adapter.source_top_hosts(WINDOW, "authentication") == [("OTHER1", 2)]


def test_spl_window_uses_the_poc_window_not_a_fixed_14_days():
    assert window_to_splunk("2016-08-21T00:00:00Z/2016-08-22T00:00:00Z") == ("1471737600", "1471824000")
    assert window_to_splunk(None) == ("-14d", "now")
    assert window_to_splunk("garbage") == ("-14d", "now")
