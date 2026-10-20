"""Plan rendering (Vietnamese Markdown for people) and binding (placeholders -> a deployment's real values)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from hunting.plan.catalog import CATALOG
from hunting.plan.safety import index_name_problem, lint_bound
from hunting.plan.schema import MAX_LOOKBACK_DAYS, HuntPlan, lookback_delta, parse_iso

_SIG = {"context": "ngữ cảnh (nhiễu mong đợi)", "indicator": "dấu hiệu nỗ lực khai thác", "impact": "dấu hiệu thành công / hậu khai thác"}
_ACTION = {
    "continue": "tiếp tục", "stop_stage": "dừng giai đoạn", "stop_plan": "dừng toàn kế hoạch", "escalate": "chuyển IR",
    "collect_data": "bổ sung telemetry", "narrow": "thu hẹp rồi chạy lại",
}
_WHEN = {
    "zero_hits": "không có kết quả", "hits_ge": "có ≥ {t} kết quả", "no_data": "nguồn không có dữ liệu",
    "truncated": "kết quả bị cắt ở trần dòng", "error": "lỗi/quá thời gian", "budget_exceeded": "hết ngân sách",
}


def _iso_to_epoch(value: str) -> str:
    return str(int(datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()))


def time_bounds(plan: HuntPlan) -> tuple[str, str]:
    """Splunk ``earliest`` / ``latest`` for the plan: an explicit window (refine rounds) or the relative lookback."""
    if plan.limits.window:
        return _iso_to_epoch(plan.limits.window["earliest"]), _iso_to_epoch(plan.limits.window["latest"])
    return f"-{plan.limits.lookback}", "now"


class BindError(ValueError):
    """The search cannot be bound safely (bad index, bad time window, a lint problem). Nothing is returned."""


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_window(
    plan: HuntPlan, earliest: str | None = None, latest: str | None = None, *, now: datetime | None = None,
) -> tuple[str, str, str]:
    """Absolute (epoch) search window and its human-readable form.

    An explicit window comes from the arguments, else from the plan (refine rounds), else from ``now - lookback .. now``.
    Always absolute at bind time so the bound search says exactly which dates it reads. Refuses a window that is reversed,
    wider than MAX_LOOKBACK_DAYS or ends in the future.
    """
    now = now or datetime.now(timezone.utc)
    if (earliest is None) != (latest is None):
        raise BindError("give both earliest and latest, or neither")
    try:
        if earliest is not None and latest is not None:
            start, end = parse_iso(earliest), parse_iso(latest)
        elif plan.limits.window:
            start, end = parse_iso(plan.limits.window["earliest"]), parse_iso(plan.limits.window["latest"])
        else:
            end, start = now, now - lookback_delta(plan.limits.lookback)
    except ValueError as exc:
        raise BindError(f"cannot read the time window: {exc}") from exc
    if not start < end:
        raise BindError(f"window is empty or reversed: {_iso(start)} -> {_iso(end)}")
    if end - start > timedelta(days=MAX_LOOKBACK_DAYS):
        raise BindError(f"window {_iso(start)} -> {_iso(end)} is wider than {MAX_LOOKBACK_DAYS} days")
    if end > now + timedelta(minutes=5):
        raise BindError(f"window ends in the future ({_iso(end)}; now is {_iso(now)})")
    return str(int(start.timestamp())), str(int(end.timestamp())), f"{_iso(start)} -> {_iso(end)} (UTC)"


def bind(
    spl: str, plan: HuntPlan, indexes: dict[str, str], window: tuple[str, str] | None = None, *, now: datetime | None = None,
) -> str:
    """Replace the placeholders of one search with a deployment's values, then lint the result.

    ``indexes`` maps a data source (``web``, ``endpoint``...) to ONE real index name (or a prefix pattern such as
    ``web_*``). Raises ``KeyError`` if a source used by the search has no mapping, so a missing mapping can never silently
    widen a search, and ``BindError`` for an unsafe index, a bad time window or anything ``lint_bound`` finds (no
    ``index=*``, an explicit earliest and latest, a row cap, no unbound placeholder).
    """
    earliest, latest = window or resolve_window(plan, now=now)[:2]
    out = spl.replace("{{EARLIEST}}", earliest).replace("{{LATEST}}", latest).replace("{{MAX_ROWS}}", str(plan.limits.max_rows_per_query))
    for source, spec in CATALOG.items():
        placeholder = str(spec["placeholder"])
        if placeholder in out:
            if source not in indexes:
                raise KeyError(f"no index mapping for data source '{source}'")
            issue = index_name_problem(indexes[source])
            if issue:
                raise BindError(issue)
            out = out.replace(placeholder, indexes[source])
    problems = lint_bound(out, max_rows=plan.limits.max_rows_per_query)
    if problems:
        raise BindError("; ".join(problems))
    return out


@dataclass
class BoundQuery:
    query_id: str
    stage_id: str
    role: str
    data_source: str
    origin: str
    purpose: str
    spl: str


def bind_plan(
    plan: HuntPlan, indexes: dict[str, str], *, earliest: str | None = None, latest: str | None = None,
    accept_llm: tuple[str, ...] = (), now: datetime | None = None,
) -> tuple[list[BoundQuery], str]:
    """Bind everything a person is about to run: core coverage probes and searches, plus the LLM-suggested stages the
    reviewer explicitly accepted (``accept_llm``). All problems are collected and raised together; nothing is partially bound."""
    t0, t1, text = resolve_window(plan, earliest, latest, now=now)
    unknown = [s for s in accept_llm if s not in {st.stage_id for st in plan.stages if st.origin == "llm"}]
    if unknown:
        raise BindError(f"no LLM suggestion with id {', '.join(unknown)}")
    accepted_sources = {src for st in plan.stages if st.stage_id in accept_llm for src in st.data_sources}
    picked: list[tuple[str, str, object]] = []
    for q in plan.coverage_probes:
        if q.origin == "core" or q.data_source in accepted_sources:
            picked.append(("-", q.role, q))
    for st in plan.stages:
        if st.origin == "core" or st.stage_id in accept_llm:
            picked.extend((st.stage_id, q.role, q) for q in st.queries)
    if len(picked) > plan.limits.max_queries + len(plan.coverage_probes):
        raise BindError(f"{len(picked)} searches exceed the plan limit of {plan.limits.max_queries}")
    bound: list[BoundQuery] = []
    problems: list[str] = []
    for stage_id, role, q in picked:
        try:
            spl = bind(q.spl, plan, indexes, (t0, t1))  # type: ignore[attr-defined]
        except (KeyError, BindError) as exc:
            problems.append(f"{q.query_id}: {exc.args[0] if exc.args else exc}")  # type: ignore[attr-defined]
            continue
        bound.append(BoundQuery(q.query_id, stage_id, role, q.data_source, q.origin, q.purpose, spl))  # type: ignore[attr-defined]
    if problems:
        raise BindError("\n".join(problems))
    return bound, text


def render_bound(plan: HuntPlan, bound: list[BoundQuery], window_text: str, indexes: dict[str, str]) -> str:
    lines = [
        f"// {plan.plan_id} (vòng {plan.iteration}) — truy vấn ĐÃ GẮN, chỉ đọc. Không sửa tay: muốn đổi thì quay lại bước R0.",
        f"// plan_digest: {plan.provenance.plan_digest}",
        f"// Cửa sổ thời gian: {window_text}",
        "// Chỉ mục: " + ", ".join(f"{s}={i}" for s, i in sorted(indexes.items())),
        f"// Mỗi truy vấn tối đa {plan.limits.max_rows_per_query} dòng, timeout {plan.limits.query_timeout_s}s. Chạy tuần tự, độ phủ (C-*) trước.",
        "",
    ]
    for b in bound:
        tag = "" if b.origin == "core" else "  [GỢI Ý LLM ĐÃ ĐƯỢC CHẤP NHẬN — chỉ tham khảo]"
        lines += [f"// [{b.query_id}] ({b.role}, {b.data_source}, giai đoạn {b.stage_id}) {b.purpose}{tag}", b.spl, ""]
    return "\n".join(lines)


def _code(text: str) -> list[str]:
    return ["```spl", text, "```"]


def render_plan_md(plan: HuntPlan) -> str:
    p = plan
    lines = [
        f"# Kế hoạch săn: {p.title}",
        "",
        f"- **Plan ID:** `{p.plan_id}` · vòng {p.iteration}" + (f" · tiếp nối `{p.parent_plan_id}`" if p.parent_plan_id else ""),
        f"- **Tạo lúc:** {p.provenance.created_at} · model `{p.provenance.llm_model or '?'}` · PEAK Assistant: {'có' if p.provenance.peak_used else 'không'}",
        f"- **plan_digest:** `{p.provenance.plan_digest}` · **core_digest:** `{p.provenance.core_digest}` "
        "(core_digest không đổi dù dùng model nào; plan_digest phải được chép vào kết quả khi gửi lại)",
        "- **Quy trình thực hiện từng bước:** xem `RUNBOOK.md`. Công cụ chỉ đề xuất; mọi cổng duyệt do người quyết định.",
        "- **Phạm vi của bản kế hoạch này:** chỉ giai đoạn **Prepare**. Không truy cập hệ thống nội bộ, không chạy PoC; "
        "các truy vấn dưới đây do đội Execute chạy trên dữ liệu của họ.",
        "",
        "## Giả thuyết",
        "",
        p.hypothesis,
        "",
        "## Tình báo đầu vào",
        "",
    ]
    i = p.intel
    if i.cve_ids:
        lines.append(f"- **CVE:** {', '.join(i.cve_ids)}" + (f" · mức {i.severity} ({i.cvss})" if i.severity else "") + (" · **CISA KEV: đã bị khai thác ngoài thực tế**" if i.kev else ""))
    if i.summary:
        lines.append(f"- **Mô tả:** {i.summary}")
    for r in i.poc_repos:
        lines.append(f"- **PoC:** [{r.name}]({r.url}) · {r.stars:,} sao" + (" · đã lưu trữ (archived)" if r.archived else ""))
    for w in i.warnings:
        lines.append(f"- ⚠ {w}")
    a = p.applicability
    if a.products or a.affected_versions or a.preconditions or a.not_applicable_if:
        lines += ["", "## Hệ thống nào có thể bị ảnh hưởng", ""]
        for label, items in (("Sản phẩm", a.products), ("Phiên bản", a.affected_versions), ("Điều kiện để khai thác được", a.preconditions), ("Không áp dụng nếu", a.not_applicable_if)):
            if items:
                lines.append(f"- **{label}:** " + "; ".join(items))
    lines += ["", "## Các giai đoạn tấn công", ""]
    for s in p.stages:
        lines += [
            f"### {s.stage_id} — {s.name}" + ("" if s.origin == "core" else "  ⟵ GỢI Ý CỦA LLM (chỉ chạy nếu người duyệt chấp nhận)"),
            "",
            f"*Giai đoạn:* `{s.phase}`" + (f" · ATT&CK: {', '.join(s.technique_ids)}" if s.technique_ids else "") + f" · *ý nghĩa:* {_SIG.get(s.significance, s.significance)}"
            + (f" · chạy sau {', '.join(s.depends_on)}" if s.depends_on else ""),
            "",
            s.description,
            "",
        ]
        if s.observables:
            lines += ["| Dấu vết | Giá trị | Nguồn gốc |", "|---|---|---|"]
            for o in s.observables:
                basis = "có trong PoC" if o.basis == "from_poc" else "suy luận (không thấy nguyên văn trong PoC)"
                lines.append(f"| {o.kind} | `{o.value.replace('|', '\\|')}` | {basis} |")
            lines.append("")
        if not s.queries:
            lines += ["> ⚠ Giai đoạn này không còn truy vấn hợp lệ nào (bộ kiểm tra đã loại, xem mục cuối): chưa kiểm tra được gì ở đây.", ""]
        for q in s.queries:
            lines += [f"**{q.query_id}** — {q.purpose} (nguồn `{q.data_source}`" + ("" if q.grounded is None else (", có chuỗi lấy từ PoC" if q.grounded else ", KHÔNG có chuỗi nào lấy nguyên văn từ PoC")) + ")", ""]
            lines += _code(q.spl)
            if q.expected_fields:
                lines.append(f"Trường kỳ vọng: {', '.join(q.expected_fields)}")
            if q.benign_notes:
                lines.append(f"Hoạt động hợp lệ có thể khớp: {q.benign_notes}")
            lines.append("")
        if s.stop_conditions:
            lines.append("**Điểm dừng:**")
            for c in s.stop_conditions:
                when = _WHEN[c.when].format(t=c.threshold)
                lines.append(f"- khi {when} → {_ACTION[c.action]}" + (f" — {c.note}" if c.note else ""))
            lines.append("")
    if p.coverage_probes:
        lines += ["## Kiểm tra độ phủ nguồn (chạy trước)", "", "Kết quả rỗng chỉ có ý nghĩa khi nguồn có dữ liệu trong cửa sổ.", ""]
        for q in p.coverage_probes:
            lines += [f"**{q.query_id}** — {q.purpose}", ""] + _code(q.spl) + [""]
    L = p.limits
    lines += [
        "## Giới hạn và điểm dừng toàn kế hoạch",
        "",
        "- Cửa sổ: " + (f"{L.window['earliest']} → {L.window['latest']}" if L.window else f"{L.lookback} gần nhất"),
        f"- Tối đa {L.max_queries} truy vấn · {L.max_rows_per_query} dòng/truy vấn · {L.query_timeout_s}s/truy vấn · {L.total_runtime_s}s tổng · {L.max_iterations} vòng · chỉ đọc",
        *[f"- {r}" for r in p.stop_rules],
        "",
        "## Cách xác minh kết quả",
        "",
        f"- **Chuyển IR** khi: {p.verification.escalate_if}.",
        f"- **Chấp nhận (không có bằng chứng)** khi: {p.verification.accept_clear_if}.",
        f"- **Chạy lại có pivot** khi: {p.verification.refine_if}.",
        f"- **Bổ sung dữ liệu** khi: {p.verification.collect_data_if}.",
        "- Gửi kết quả theo `result.schema.json`; chạy `verify` để nhận quyết định và (nếu cần) kế hoạch vòng kế tiếp.",
        "",
    ]
    if p.manual_todo:
        lines += ["## Việc con người phải tự làm (công cụ không tự suy ra được)", ""] + [f"- {m}" for m in p.manual_todo] + [""]
    if p.leads:
        lines += ["## Dấu vết dẫn tới vòng này", ""] + [f"- {lead['kind']}: `{lead['value']}` (×{lead['count']})" for lead in p.leads] + [""]
    if p.dropped:
        lines += ["## Đã loại bỏ / ghi chú của bộ kiểm tra", ""] + [f"- {d}" for d in p.dropped] + [""]
    if p.peak:
        lines += ["## PEAK Assistant", "", "Bảng ABLE và kế hoạch do PEAK viết nằm trong `peak_able.md` và `peak_hunt_plan.md` (tham khảo, không phải bằng chứng).", ""]
    lines.append("> Kế hoạch là gợi ý hỗ trợ quyết định; người săn mối đe dọa quyết định cuối cùng.")
    return "\n".join(lines) + "\n"
