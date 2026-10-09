"""Verification of executed results, and the next round.

The executing team returns a ``ResultBundle``. This module decides, deterministically, what happens next:

``ESCALATE_AFFECTED``   an 'impact' stage returned events: stop widening and hand over to incident response;
``REFINE``              events in context/indicator stages (or truncated output): pivot on the observed values, next round;
``COLLECT_DATA``        a needed source has no data: an empty result there proves nothing;
``RERUN_INCOMPLETE``    queries failed, timed out or were not run;
``ACCEPT_NO_EVIDENCE``  everything ran, every source has data, nothing was found: accept (this is never "clean");
``STOP_REVIEW``         iteration cap reached or no new leads: a human has to read the evidence;
``REJECT_RESULTS``      the bundle does not belong to this plan.

No LLM is involved here. Values taken from result rows are attacker-influenced (they come from logs), so they are only
embedded in follow-up searches when they pass a strict character filter.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from hunting.plan.catalog import CATALOG
from hunting.plan.safety import check_spl, coverage_probe, spl_literal
from hunting.plan.schema import HuntPlan, Query, QueryResult, ResultBundle, Stage

Decision = Literal[
    "ESCALATE_AFFECTED", "ACCEPT_NO_EVIDENCE", "REFINE", "COLLECT_DATA", "RERUN_INCOMPLETE", "STOP_REVIEW", "REJECT_RESULTS"
]
MAX_SAMPLE = 25
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTLIKE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,99}$")
_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash", "zsh", "curl", "wget", "whoami", "nc", "ncat", "certutil.exe", "mshta.exe")


class StageVerdict(BaseModel):
    stage_id: str
    name: str
    status: Literal["HIT", "CLEAR", "NO_DATA", "INCOMPLETE"]
    hits: int = 0
    truncated: bool = False
    actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class Verification(BaseModel):
    plan_id: str
    iteration: int
    decision: Decision
    summary: str
    reasons: list[str] = Field(default_factory=list)
    stages: list[StageVerdict] = Field(default_factory=list)
    coverage: dict[str, str] = Field(default_factory=dict)  # source -> present | empty | unknown
    protocol_issues: list[str] = Field(default_factory=list)
    leads: list[dict[str, Any]] = Field(default_factory=list)
    next_plan_id: str | None = None
    human_required: bool = True


def _query_state(q: Query, r: QueryResult | None, cap: int) -> tuple[str, int, bool]:
    """-> (state, hits, truncated). state: HIT | ZERO | ERROR | NOT_RUN"""
    if r is None or r.status == "skipped":
        return "NOT_RUN", 0, False
    if r.status in ("error", "timeout"):
        return "ERROR", 0, False
    truncated = r.truncated or r.row_count > cap
    return ("HIT" if r.row_count > 0 else "ZERO"), r.row_count, truncated


def _parse_time(value: Any) -> datetime | None:
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,11}(\.\d+)?", value)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str) and value.strip():
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None
    return None


def extract_leads(bundle: ResultBundle, plan: HuntPlan, hit_ids: set[str]) -> tuple[list[dict[str, Any]], tuple[datetime, datetime] | None]:
    """Pivot candidates (attacker source, victim host, user) and the time span seen in the sample rows."""
    counters: dict[str, Counter] = {"src": Counter(), "dest": Counter(), "user": Counter()}
    times: list[datetime] = []
    field_for = {"src": ("src", "src_ip", "clientip"), "dest": ("dest", "host", "dest_host"), "user": ("user",)}
    for result in bundle.results:
        if result.query_id not in hit_ids:
            continue
        for row in result.sample[:MAX_SAMPLE]:
            for kind, names in field_for.items():
                for name in names:
                    value = row.get(name)
                    if isinstance(value, str) and value.strip():
                        text = value.strip()
                        if kind == "user" and spl_literal(text) is None:
                            continue
                        if kind != "user" and not (_IP.match(text) or _HOSTLIKE.match(text)):
                            continue
                        counters[kind][text] += int(row.get("count", 1)) if isinstance(row.get("count", 1), (int, float)) else 1
                        break
            for name in ("_time", "first", "last", "first_seen", "last_seen", "firstTime", "lastTime"):
                moment = _parse_time(row.get(name))
                if moment:
                    times.append(moment)
    seen = {(lead["kind"], lead["value"]) for lead in plan.leads}
    leads = [
        {"kind": kind, "value": value, "count": count}
        for kind, counter in counters.items() for value, count in counter.most_common(3)
        if (kind, value) not in seen
    ]
    span = (min(times), max(times)) if times else None
    return leads, span


def _pivot_stages(leads: list[dict[str, Any]], plan: HuntPlan) -> list[Stage]:
    from hunting.plan.build import default_stops

    limits = plan.limits
    srcs = [lead["value"] for lead in leads if lead["kind"] == "src"][:3]
    dests = [lead["value"] for lead in leads if lead["kind"] == "dest"][:3]
    users = [lead["value"] for lead in leads if lead["kind"] == "user"][:2]
    oast = [o.value for s in plan.stages for o in s.observables if o.kind == "oast_domain" and o.basis == "from_poc"][:4]
    shells = " OR ".join(f'process_name="{p}"' for p in _SHELLS)

    def q(stage: str, n: int, purpose: str, source: str, spl: str, fields: list[str], benign: str = "") -> Query | None:
        norm, errors, _ = check_spl(spl)
        if norm is None:
            return None
        return Query(query_id=f"{stage}-Q{n}", purpose=purpose, data_source=source, spl=norm, expected_fields=fields,  # type: ignore[arg-type]
                     benign_notes=benign, role="pivot", grounded=None)

    stages: list[Stage] = []
    a: list[Query | None] = []
    for ip in srcs:
        lit = spl_literal(ip)
        if lit is None:
            continue
        a.append(q("P1", len(a) + 1, f"Mọi yêu cầu web từ nguồn {ip}", "web",
                   f"search index={{{{INDEX_WEB}}}} src={lit} | stats count min(_time) as first max(_time) as last by dest, uri_path, status | sort - count",
                   ["dest", "uri_path", "status", "count"], "Máy quét hợp lệ của chính tổ chức."))
        a.append(q("P1", len(a) + 1, f"Kết nối mạng liên quan tới {ip}", "network",
                   f"search index={{{{INDEX_NETWORK}}}} (src={lit} OR dest={lit}) | stats count by src, dest, dest_port, action | sort - count",
                   ["src", "dest", "dest_port", "action"]))
    a = [x for x in a if x]
    if a:
        stages.append(Stage(stage_id="P1", name="Pivot theo nguồn tấn công quan sát được", phase="initial_access", technique_ids=["T1190"],
                            significance="indicator", description="Xem toàn bộ hoạt động của các nguồn đã khớp ở vòng trước.",
                            data_sources=sorted({x.data_source for x in a}), queries=a,  # type: ignore[type-var]
                            stop_conditions=default_stops("indicator", limits.max_rows_per_query)))
    b: list[Query | None] = []
    for host in dests:
        lit = spl_literal(host)
        if lit is None:
            continue
        b.append(q("P2", len(b) + 1, f"Tiến trình đáng ngờ trên {host} (shell, công cụ tải về)", "endpoint",
                   f"search index={{{{INDEX_ENDPOINT}}}} dest={lit} ({shells}) | stats count min(_time) as first max(_time) as last by parent_process_name, process_name, process | sort - count",
                   ["parent_process_name", "process_name", "process", "count"], "Quản trị viên mở shell hợp lệ; so với tiến trình cha là dịch vụ bị khai thác."))
        for domain in oast:
            dl = spl_literal(f"*{domain}*")
            if dl:
                b.append(q("P2", len(b) + 1, f"Truy vấn DNS từ {host} tới tên miền out-of-band của PoC ({domain})", "dns",
                           f"search index={{{{INDEX_DNS}}}} src={lit} query={dl} | stats count by query, answer",
                           ["query", "answer", "count"], "Dịch vụ quét lỗ hổng nội bộ dùng cùng tên miền."))
    b = [x for x in b if x]
    if b:
        stages.append(Stage(stage_id="P2", name="Pivot theo host bị nhắm tới: hậu khai thác", phase="execution", technique_ids=["T1059"],
                            significance="impact", description="Tìm tiến trình lạ hoặc kết nối out-of-band từ các host đã bị nhắm tới.",
                            data_sources=sorted({x.data_source for x in b}), queries=b, depends_on=["P1"] if a else [],  # type: ignore[type-var]
                            stop_conditions=default_stops("impact", limits.max_rows_per_query)))
    c: list[Query | None] = []
    for host in dests:
        lit = spl_literal(host)
        if lit is None:
            continue
        c.append(q("P3", len(c) + 1, f"Kết nối đi ra ngoài của {host} (ngoài dải riêng)", "network",
                   f"search index={{{{INDEX_NETWORK}}}} src={lit} | where NOT (cidrmatch(\"10.0.0.0/8\", dest) OR cidrmatch(\"172.16.0.0/12\", dest) OR cidrmatch(\"192.168.0.0/16\", dest)) | stats count by dest, dest_port | sort - count",
                   ["dest", "dest_port", "count"], "Cập nhật phần mềm, NTP, dịch vụ đám mây hợp lệ: cần người lọc."))
    for user in users:
        lit = spl_literal(user)
        if lit:
            c.append(q("P3", len(c) + 1, f"Hoạt động xác thực của tài khoản {user}", "auth",
                       f"search index={{{{INDEX_AUTH}}}} user={lit} | stats count by src, dest, action | sort - count", ["src", "dest", "action", "count"]))
    c = [x for x in c if x]
    if c:
        stages.append(Stage(stage_id="P3", name="Ngữ cảnh: kết nối ra ngoài và tài khoản liên quan", phase="command_and_control", technique_ids=[],
                            significance="context", description="Bối cảnh để người săn đánh giá; hầu hết host đều có kết nối ra ngoài, nên kết quả chỉ để đọc.",
                            data_sources=sorted({x.data_source for x in c}), queries=c, depends_on=["P2"] if b else [],  # type: ignore[type-var]
                            stop_conditions=default_stops("context", limits.max_rows_per_query)))
    return stages


def verify(plan: HuntPlan, bundle: ResultBundle) -> tuple[Verification, HuntPlan | None]:
    issues: list[str] = []
    if bundle.plan_id != plan.plan_id:
        v = Verification(plan_id=plan.plan_id, iteration=plan.iteration, decision="REJECT_RESULTS",
                         summary="Kết quả thuộc kế hoạch khác; không dùng.", protocol_issues=[f"plan_id {bundle.plan_id!r} ≠ {plan.plan_id!r}"])
        return v, None
    if bundle.iteration != plan.iteration:
        issues.append(f"iteration {bundle.iteration} ≠ {plan.iteration} của kế hoạch")
    planned = {q.query_id: q for q in plan.all_queries()}
    by_id: dict[str, QueryResult] = {}
    for r in bundle.results:
        if r.query_id not in planned:
            issues.append(f"{r.query_id}: không có trong kế hoạch (truy vấn ngoài kế hoạch bị bỏ qua)")
            continue
        if r.query_id in by_id:
            issues.append(f"{r.query_id}: trùng lặp, lấy bản đầu tiên")
            continue
        if len(r.sample) > MAX_SAMPLE:
            issues.append(f"{r.query_id}: mẫu {len(r.sample)} dòng > {MAX_SAMPLE}, cắt bớt")
            r = r.model_copy(update={"sample": r.sample[:MAX_SAMPLE]})
        by_id[r.query_id] = r
    cap = plan.limits.max_rows_per_query

    coverage: dict[str, str] = {}
    for probe in plan.coverage_probes:
        r = by_id.get(probe.query_id)
        state, hits, _ = _query_state(probe, r, 10**9)
        coverage[probe.data_source] = "present" if state == "HIT" else ("empty" if state == "ZERO" else "unknown")

    verdicts: list[StageVerdict] = []
    hit_ids: set[str] = set()
    escalate = False
    impact_incomplete = False
    for stage in plan.stages:
        states = [(q, *_query_state(q, by_id.get(q.query_id), cap)) for q in stage.queries]
        hits = sum(h for _, st, h, _ in states if st == "HIT")
        truncated = any(t for _, st, _, t in states if st == "HIT")
        errors = [q.query_id for q, st, _, _ in states if st in ("ERROR", "NOT_RUN")]
        empty_sources = [s for s in stage.data_sources if coverage.get(s) == "empty"]
        notes: list[str] = []
        if hits:
            status = "HIT"
            hit_ids |= {q.query_id for q, st, _, _ in states if st == "HIT"}
        elif errors:
            status = "INCOMPLETE"
        elif empty_sources or any(coverage.get(s, "unknown") == "unknown" for s in stage.data_sources):
            status = "NO_DATA"
        else:
            status = "CLEAR"
        if errors:
            notes.append("chưa chạy được: " + ", ".join(errors))
        if empty_sources:
            notes.append("nguồn không có dữ liệu: " + ", ".join(empty_sources))
        unknown = [s for s in stage.data_sources if coverage.get(s) == "unknown"]
        if unknown and status != "HIT":
            notes.append("chưa xác nhận được độ phủ của: " + ", ".join(unknown))
        actions: list[str] = []
        for c in stage.stop_conditions:
            if (
                (c.when == "hits_ge" and hits >= (c.threshold or 1) and hits > 0)
                or (c.when == "zero_hits" and status == "CLEAR")
                or (c.when == "no_data" and (status == "NO_DATA" and empty_sources))
                or (c.when == "truncated" and truncated)
                or (c.when == "error" and errors)
            ):
                actions.append(c.action)
        if stage.significance == "impact" and "escalate" in actions:
            escalate = True
        if stage.significance == "impact" and errors and not hits:
            impact_incomplete = True
        verdicts.append(StageVerdict(stage_id=stage.stage_id, name=stage.name, status=status, hits=hits,  # type: ignore[arg-type]
                                     truncated=truncated, actions=list(dict.fromkeys(actions)), notes=notes))

    missing_cov = [s for s, st in coverage.items() if st != "present"]
    any_hit = any(v.status == "HIT" for v in verdicts)
    leads, span = extract_leads(bundle, plan, hit_ids)
    reasons: list[str] = []

    def done(decision: Decision, summary: str, next_plan: HuntPlan | None = None) -> tuple[Verification, HuntPlan | None]:
        return Verification(
            plan_id=plan.plan_id, iteration=plan.iteration, decision=decision, summary=summary, reasons=reasons, stages=verdicts,
            coverage=coverage, protocol_issues=issues, leads=leads, next_plan_id=next_plan.plan_id if next_plan else None,
        ), next_plan

    if escalate:
        reasons += [f"{v.stage_id} ({v.name}): {v.hits} kết quả" for v in verdicts if v.status == "HIT" and "escalate" in v.actions]
        reasons.append("Giai đoạn 'impact' có sự kiện: dừng mở rộng, chuyển IR kèm bằng chứng. Đây là gợi ý; người quyết định cuối cùng là người săn.")
        return done("ESCALATE_AFFECTED", "Có dấu hiệu khai thác thành công hoặc hậu khai thác: chuyển IR.")
    if impact_incomplete:
        reasons.append("Truy vấn của giai đoạn 'impact' lỗi hoặc chưa chạy nên chưa thể kết luận.")
        return done("RERUN_INCOMPLETE", "Chạy lại các truy vấn lỗi/thiếu, nhất là giai đoạn impact.")
    if any_hit or any(v.truncated for v in verdicts):
        if plan.iteration >= plan.limits.max_iterations:
            reasons.append(f"Đã đạt {plan.limits.max_iterations} vòng nhưng vẫn còn dấu vết: cần người đọc bằng chứng.")
            return done("STOP_REVIEW", "Hết số vòng cho phép; chuyển người săn xem xét.")
        if not leads:
            reasons.append("Có kết quả nhưng không có giá trị mới nào đủ an toàn để pivot (hoặc đã pivot rồi).")
            return done("STOP_REVIEW", "Không còn dấu vết mới để pivot; chuyển người săn xem xét.")
        stages = _pivot_stages(leads, plan)
        if not stages:
            reasons.append("Không dựng được truy vấn pivot hợp lệ từ các giá trị quan sát được.")
            return done("STOP_REVIEW", "Không dựng được vòng kế tiếp; chuyển người săn xem xét.")
        limits = plan.limits.model_copy(deep=True)
        if span:
            limits.window = {
                "earliest": (span[0] - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "latest": (span[1] + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        sources = sorted({q.data_source for s in stages for q in s.queries})
        probes = [Query(query_id=f"C-{s}", purpose=f"Kiểm tra nguồn '{s}' có dữ liệu trong cửa sổ", data_source=s,  # type: ignore[arg-type]
                        spl=coverage_probe(s, str(CATALOG[s]["placeholder"])), role="coverage") for s in sources]
        nxt = plan.model_copy(deep=True)
        nxt.iteration = plan.iteration + 1
        nxt.parent_plan_id = plan.plan_id
        nxt.plan_id = f"{re.sub(r'-r\d+$', '', plan.plan_id)}-r{nxt.iteration}"
        nxt.title = f"{plan.title} — vòng {nxt.iteration}: pivot"
        nxt.stages, nxt.coverage_probes, nxt.limits, nxt.leads = stages, probes, limits, plan.leads + leads
        nxt.dropped = []
        nxt.peak = None
        reasons += [f"{v.stage_id} có {v.hits} kết quả" + (" (bị cắt ở trần dòng)" if v.truncated else "") for v in verdicts if v.status == "HIT"]
        reasons.append(f"Pivot trên {len(leads)} giá trị quan sát được: " + ", ".join(f"{lead['kind']}={lead['value']}" for lead in leads[:6]))
        if span:
            reasons.append(f"Thu hẹp cửa sổ về {limits.window['earliest']} → {limits.window['latest']} (±1 giờ quanh hoạt động thấy được).")  # type: ignore[index]
        if missing_cov:
            reasons.append("Lưu ý độ phủ: " + ", ".join(f"{s}={coverage[s]}" for s in missing_cov))
        return done("REFINE", f"Chạy vòng {nxt.iteration} với các truy vấn pivot.", nxt)
    if any(v.status == "INCOMPLETE" for v in verdicts):
        reasons += [f"{v.stage_id}: " + "; ".join(v.notes) for v in verdicts if v.status == "INCOMPLETE"]
        return done("RERUN_INCOMPLETE", "Một số truy vấn lỗi hoặc chưa chạy: chạy lại rồi gửi kết quả.")
    if any(v.status == "NO_DATA" for v in verdicts):
        reasons += [f"{v.stage_id}: " + "; ".join(v.notes) for v in verdicts if v.status == "NO_DATA"]
        reasons.append("Kết quả rỗng ở nguồn không có dữ liệu không chứng minh điều gì.")
        return done("COLLECT_DATA", "Bổ sung hoặc xác nhận telemetry của các nguồn thiếu rồi chạy lại.")
    reasons.append("Mọi truy vấn đã chạy, mọi nguồn đều có dữ liệu, không có sự kiện nào khớp.")
    reasons.append(
        f"Phạm vi: {plan.limits.lookback if not plan.limits.window else 'cửa sổ ' + plan.limits.window['earliest'] + ' → ' + plan.limits.window['latest']}; "
        "chỉ các dấu vết và biến thể nêu trong kế hoạch; đây KHÔNG phải kết luận 'sạch'."
    )
    return done("ACCEPT_NO_EVIDENCE", "Chấp nhận kết quả: không thấy bằng chứng khai thác trong phạm vi đã quét.")


def render_verification_md(v: Verification, plan: HuntPlan) -> str:
    label = {
        "ESCALATE_AFFECTED": "Chuyển IR", "ACCEPT_NO_EVIDENCE": "Chấp nhận: không thấy bằng chứng (không phải 'sạch')",
        "REFINE": "Chạy vòng tiếp theo (pivot)", "COLLECT_DATA": "Bổ sung dữ liệu rồi chạy lại",
        "RERUN_INCOMPLETE": "Chạy lại phần lỗi/thiếu", "STOP_REVIEW": "Dừng: người săn xem xét", "REJECT_RESULTS": "Từ chối kết quả",
    }
    lines = [
        f"# Xác minh kết quả — {plan.title}", "",
        f"- Plan `{v.plan_id}` · vòng {v.iteration}",
        f"- **Quyết định:** `{v.decision}` — {label[v.decision]}",
        f"- {v.summary}", "", "## Lý do", "", *[f"- {r}" for r in v.reasons], "",
    ]
    if v.stages:
        lines += ["## Từng giai đoạn", "", "| Giai đoạn | Trạng thái | Kết quả | Hành động theo điểm dừng |", "|---|---|---|---|"]
        for s in v.stages:
            lines.append(f"| {s.stage_id} {s.name} | {s.status}{' (cắt)' if s.truncated else ''} | {s.hits} | {', '.join(s.actions) or '—'} |")
            for n in s.notes:
                lines.append(f"| | | | ↳ {n} |")
        lines.append("")
    if v.coverage:
        lines += ["## Độ phủ nguồn", "", *[f"- {s}: {st}" for s, st in v.coverage.items()], ""]
    if v.leads:
        lines += ["## Dấu vết mới", "", *[f"- {lead['kind']}: `{lead['value']}` (×{lead['count']})" for lead in v.leads], ""]
    if v.protocol_issues:
        lines += ["## Vấn đề về định dạng kết quả", "", *[f"- {i}" for i in v.protocol_issues], ""]
    if v.next_plan_id:
        lines += ["## Vòng kế tiếp", "", f"Kế hoạch mới: `{v.next_plan_id}` (file `plan.json` trong thư mục vòng kế tiếp).", ""]
    lines.append("> Quyết định này chỉ hỗ trợ; người săn mối đe dọa là người quyết định cuối cùng.")
    return "\n".join(lines) + "\n"
