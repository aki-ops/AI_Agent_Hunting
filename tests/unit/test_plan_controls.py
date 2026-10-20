"""Controls the user asked for: model independence, a step-by-step human runbook, and strict SPL / time-window checks."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from hunting.plan import BindError, Limits, ResultBundle, bind_plan, build_plan, resolve_window, verify
from hunting.plan.runbook import render_runbook_md
from hunting.plan.safety import index_name_problem, lint_bound
from hunting.plan.schema import HuntPlan, QueryResult
from tests.unit.test_intel_plan import GOOD, ScriptedLlm, _bundle, _results, attest, hit

NOW = datetime(2099, 3, 10, 12, 0, tzinfo=timezone.utc)
INDEXES = {"web": "web_prod", "dns": "dns_prod", "proxy": "proxy_prod", "app": "app_prod", "endpoint": "edr_prod"}


@pytest.fixture()
def plan(tmp_path: Path) -> HuntPlan:
    return build_plan(_bundle(tmp_path), ScriptedLlm(GOOD), attempts=1, model_name="m")


# ----------------------------------------------------------------------------- 1. independence from the model


def test_every_model_gets_the_same_core_and_the_same_decision(tmp_path: Path):
    """A strong model, a weak one, one that rambles, one that is down and no model at all: the part of the plan that
    decides stays byte-identical, and so does the verdict for the same executed results."""
    bundle = _bundle(tmp_path)
    models = {
        "none": None,
        "strong": ScriptedLlm(GOOD),
        "weak": ScriptedLlm({"stages": []}),
        "rambling": ScriptedLlm("Sure! Here is my analysis of the vulnerability..."),
        "down": ScriptedLlm(RuntimeError("503")),
    }
    plans = {name: build_plan(bundle, llm, attempts=2) for name, llm in models.items()}
    digests = {p.provenance.core_digest for p in plans.values()}
    assert len(digests) == 1
    cores = {name: [s.model_dump_json() for s in p.stages if s.origin == "core"] for name, p in plans.items()}
    assert len({tuple(v) for v in cores.values()}) == 1
    assert plans["strong"].provenance.plan_digest != plans["none"].provenance.plan_digest  # suggestions are part of what is approved
    # the same executed results (core queries only) give the same decision whichever model wrote the suggestions
    decisions = set()
    for name, p in plans.items():
        sample = [{"src": "203.0.113.7", "dest": "web-01"}]
        v, _ = verify(p, _results(p, **{"S3-Q1": hit("S3-Q1", 1, sample)}))
        decisions.add((v.decision, tuple(s.status for s in v.stages if s.stage_id.startswith("S"))))
    assert decisions == {("ESCALATE_AFFECTED", ("CLEAR", "CLEAR", "HIT"))}


def test_an_llm_suggestion_cannot_change_a_decision(plan: HuntPlan):
    """Even if the reviewer accepted and ran an LLM suggestion and it returned hits, it neither escalates nor pivots."""
    sample = [{"src": "203.0.113.7", "dest": "web-01"}]
    rows = [hit("L2-Q1", 50, sample) if q.query_id == "L2-Q1" else r for q in plan.all_queries()
            for r in [_results(plan).results[[x.query_id for x in plan.all_queries()].index(q.query_id)]]]
    v, nxt = verify(plan, attest(plan, rows, accepted_llm_stages=["L2"]))
    assert v.decision == "ACCEPT_NO_EVIDENCE" and nxt is None
    stage = next(s for s in v.stages if s.stage_id == "L2")
    assert stage.status == "HIT" and "KHÔNG dùng để leo thang" in " ".join(stage.notes)
    # a suggestion that was run without being recorded as accepted is ignored and reported
    v2, _ = verify(plan, attest(plan, rows))
    assert next(s for s in v2.stages if s.stage_id == "L2").status == "SKIPPED"
    assert any("L2" in i and "accepted_llm_stages" in i for i in v2.protocol_issues)


def test_llm_stages_that_were_not_run_do_not_make_the_round_incomplete(plan: HuntPlan):
    v, _ = verify(plan, _results(plan))
    assert v.decision == "ACCEPT_NO_EVIDENCE"


# ----------------------------------------------------------------------------- 2. human in the loop, step by step


def test_the_runbook_gates_every_stage_and_leaves_every_decision_to_a_person(plan: HuntPlan):
    steps = plan.runbook
    assert [s.step_id for s in steps] == [f"R{i}" for i in range(len(steps))]
    assert steps[0].kind == "precheck" and steps[0].human_decision and "approved_by" in " ".join(steps[0].record)
    assert steps[1].kind == "bind" and "index=*" in " ".join(steps[1].do)
    assert steps[-2].kind == "handoff" and steps[-1].kind == "decision" and steps[-1].human_decision
    kinds = [s.kind for s in steps]
    assert kinds.index("bind") < kinds.index("coverage") < kinds.index("query")  # coverage before detection, bind before anything runs
    # every planned query has exactly one step, and each stage ends in a gate that asks a person
    planned = [q.query_id for q in plan.all_queries()]
    in_steps = [qid for s in steps for qid in s.query_ids]
    assert sorted(planned) == sorted(in_steps)
    for stage in plan.stages:
        last_query_step = max(i for i, s in enumerate(steps) if set(s.query_ids) & {q.query_id for q in stage.queries})
        assert steps[last_query_step + 1].kind == "gate" and steps[last_query_step + 1].human_decision
    # steps for LLM suggestions are optional, core steps are not
    for s in steps:
        if s.kind == "query":
            q = next(x for x in plan.all_queries() if x.query_id == s.query_ids[0])
            assert s.optional == (q.origin == "llm")
            assert any("tuần tự" in d or "từng truy vấn" in d for d in s.do) and any("row_count" in r for r in s.record)
    impact_gate = next(s for s in steps if s.kind == "gate" and "S3" in s.title)
    assert any("DỪNG mở rộng" in c for c in impact_gate.stop_if)
    md = render_runbook_md(plan)
    assert md.count("Quyết định của người") >= len(plan.stages) + 3 and "plan_digest" in md and "- [ ] Đã quyết định" in md


def test_what_the_code_could_not_decide_is_handed_to_a_person_not_guessed(tmp_path: Path):
    plan = build_plan(_bundle(tmp_path), None)
    assert any("tiến trình cha" in t for t in plan.manual_todo)
    assert not any(q.data_source == "endpoint" for s in plan.stages for q in s.queries)  # no unfiltered process search was invented
    assert any("tiến trình cha" in d for d in plan.runbook[0].do)


def test_results_without_a_named_approver_or_with_another_digest_are_rejected(plan: HuntPlan):
    good = _results(plan)
    assert verify(plan, good)[0].decision == "ACCEPT_NO_EVIDENCE"
    for change in ({"approved_by": ""}, {"approved_at": " "}, {"plan_digest": ""}, {"plan_digest": "0" * 32}):
        v, nxt = verify(plan, good.model_copy(update=change))
        assert v.decision == "REJECT_RESULTS" and nxt is None and v.protocol_issues, change
    edited = plan.model_copy(deep=True)
    edited.stages[0].queries[0].spl = edited.stages[0].queries[0].spl.replace("widget-scan", "other-scan")
    from hunting.plan.digest import plan_digest
    assert plan_digest(edited) != plan.provenance.plan_digest  # editing the plan after approval changes its digest


# ----------------------------------------------------------------------------- 3. SPL and time window


def test_binding_is_all_or_nothing_and_core_only_unless_a_suggestion_was_accepted(plan: HuntPlan):
    bound, window = bind_plan(plan, INDEXES, earliest="2099-03-01T00:00:00Z", latest="2099-03-02T00:00:00Z", now=NOW)
    assert window.startswith("2099-03-01T00:00:00Z -> 2099-03-02T00:00:00Z")
    ids = [b.query_id for b in bound]
    assert not any(i.startswith("L") for i in ids) and {"S1-Q1", "S3-Q2", "C-web", "C-dns"} <= set(ids) and "C-app" not in ids
    for b in bound:
        assert lint_bound(b.spl, max_rows=plan.limits.max_rows_per_query) == [], b.spl
        assert "index=*" not in b.spl and "{{" not in b.spl
    with_llm, _ = bind_plan(plan, INDEXES, earliest="2099-03-01T00:00:00Z", latest="2099-03-02T00:00:00Z", accept_llm=("L1",), now=NOW)
    assert {"L1-Q1", "C-app"} <= {b.query_id for b in with_llm} and "L2-Q1" not in {b.query_id for b in with_llm}
    with pytest.raises(BindError, match="no LLM suggestion with id L9"):
        bind_plan(plan, INDEXES, accept_llm=("L9",), now=NOW)
    with pytest.raises(BindError, match="no index mapping") as err:
        bind_plan(plan, {"web": "web_prod"}, earliest="2099-03-01T00:00:00Z", latest="2099-03-02T00:00:00Z", now=NOW)
    assert str(err.value).count("\n") >= 2  # every problem is reported at once, nothing is half-bound


def test_time_window_is_always_explicit_bounded_and_not_in_the_future(plan: HuntPlan):
    e, late, text = resolve_window(plan, now=NOW)  # default: now - lookback .. now, turned into absolute epochs
    assert int(late) - int(e) == 14 * 86400 and int(late) == int(NOW.timestamp()) and "(UTC)" in text
    with pytest.raises(BindError, match="both"):
        resolve_window(plan, earliest="2099-03-01T00:00:00Z", now=NOW)
    with pytest.raises(BindError, match="reversed"):
        resolve_window(plan, "2099-03-02T00:00:00Z", "2099-03-01T00:00:00Z", now=NOW)
    with pytest.raises(BindError, match="wider than 90"):
        resolve_window(plan, "2098-11-01T00:00:00Z", "2099-03-09T00:00:00Z", now=NOW)
    with pytest.raises(BindError, match="future"):
        resolve_window(plan, "2099-03-09T00:00:00Z", "2099-03-20T00:00:00Z", now=NOW)
    with pytest.raises(BindError, match="cannot read"):
        resolve_window(plan, "yesterday", "today", now=NOW)
    for bad in ("0d", "91d", "13w", "x", "-5d", "", "1y"):
        with pytest.raises((ValidationError, ValueError)):
            Limits(lookback=bad)
    with pytest.raises(ValidationError):
        Limits(window={"earliest": "2099-01-01T00:00:00Z", "latest": "2099-06-01T00:00:00Z"})
    assert Limits(lookback="90d").lookback == "90d" and Limits(lookback="12h").lookback == "12h"


@pytest.mark.parametrize("spl,fragment", [
    ("search index=* earliest=1 latest=2 uri_path=\"/login\" | head 10", "real index name"),
    ("search index=web_prod uri_path=\"/login\" | head 10", "no earliest"),
    ("search index=web_prod earliest=1 uri_path=\"/login\" | head 10", "no latest"),
    ("search index=web_prod earliest=-100y latest=now uri_path=\"/login\" | head 10", "not a relative time"),
    ("search index=web_prod earliest=1700000000 latest=1700003600 uri_path=\"/login\" | stats count", "head N"),
    ("search index=web_prod earliest=1700000000 latest=1700003600 uri_path=\"/login\" | head 5000", "outside 1.."),
    ("search index=web_prod index=other earliest=1700000000 latest=1700003600 uri_path=\"/login\" | head 10", "exactly one index"),
    ("search index=_internal earliest=1700000000 latest=1700003600 uri_path=\"/login\" | head 10", "_internal"),
    ("search index={{INDEX_WEB}} earliest=1700000000 latest=1700003600 uri_path=\"/login\" | head 10", "placeholder"),
    ("search index=web_prod earliest=1700000000 latest=1700003600 uri_path=\"/login\" | delete | head 10", "allow-list"),
])
def test_lint_of_a_bound_search_catches_what_would_flood_or_widen_a_search(spl: str, fragment: str):
    problems = lint_bound(spl, max_rows=200)
    assert any(fragment in p for p in problems), problems


def test_a_good_bound_search_and_the_coverage_probe_pass_the_lint():
    assert lint_bound('search index=web_prod earliest=1700000000 latest=1700003600 uri_path="/login" | stats count by src | head 200', max_rows=200) == []
    probe = "| tstats count min(_time) as first_seen max(_time) as last_seen where index=web_prod earliest=1700000000 latest=1700003600 by sourcetype | head 20"
    assert lint_bound(probe, max_rows=200) == []


@pytest.mark.parametrize("name,ok", [("web_prod", True), ("web*", True), ("os", True), ("*", False), ("w*", False), ("_internal", False),
                                     ("_audit", False), ("a b", False), ("x|delete", False), ("", False), ("web_prod,other", False)])
def test_index_names(name: str, ok: bool):
    assert (index_name_problem(name) is None) == ok


def test_results_with_an_impossible_window_are_flagged(plan: HuntPlan):
    results = _results(plan)
    results.results[0] = QueryResult(query_id=results.results[0].query_id, status="ok", row_count=0,
                                     earliest="2099-01-01T00:00:00Z", latest="2099-12-31T00:00:00Z")
    v, _ = verify(plan, results)
    assert any("rộng hơn 90 ngày" in i for i in v.protocol_issues)


def test_the_result_bundle_schema_carries_the_attestation_fields():
    fields = ResultBundle.model_fields
    assert {"plan_digest", "approved_by", "approved_at", "accepted_llm_stages"} <= set(fields)
