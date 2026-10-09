"""Plan rendering (Vietnamese Markdown for people) and binding (placeholders -> a deployment's real values)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from hunting.plan.catalog import CATALOG
from hunting.plan.schema import HuntPlan

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


def bind(spl: str, plan: HuntPlan, indexes: dict[str, str]) -> str:
    """Replace the placeholders of one search with a deployment's values.

    ``indexes`` maps a data source (``web``, ``endpoint``...) to a real index name or a parenthesised list
    (``"(idx1 OR idx2)"`` is not valid after ``index=``; use one index or ``idx*`` patterns). Raises ``KeyError`` if a
    source used by the search has no mapping, so a missing mapping can never silently widen a search.
    """
    earliest, latest = time_bounds(plan)
    out = spl.replace("{{EARLIEST}}", earliest).replace("{{LATEST}}", latest).replace("{{MAX_ROWS}}", str(plan.limits.max_rows_per_query))
    for source, spec in CATALOG.items():
        placeholder = str(spec["placeholder"])
        if placeholder in out:
            if source not in indexes or not re.fullmatch(r"[A-Za-z0-9_\-*.:]+", indexes[source]):
                raise KeyError(f"no safe index mapping for data source '{source}'")
            out = out.replace(placeholder, indexes[source])
    return out


def _code(text: str) -> list[str]:
    return ["```spl", text, "```"]


def render_plan_md(plan: HuntPlan) -> str:
    p = plan
    lines = [
        f"# Kế hoạch săn: {p.title}",
        "",
        f"- **Plan ID:** `{p.plan_id}` · vòng {p.iteration}" + (f" · tiếp nối `{p.parent_plan_id}`" if p.parent_plan_id else ""),
        f"- **Tạo lúc:** {p.provenance.created_at} · model `{p.provenance.llm_model or '?'}` · PEAK Assistant: {'có' if p.provenance.peak_used else 'không'}",
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
            f"### {s.stage_id} — {s.name}",
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
    if p.leads:
        lines += ["## Dấu vết dẫn tới vòng này", ""] + [f"- {lead['kind']}: `{lead['value']}` (×{lead['count']})" for lead in p.leads] + [""]
    if p.dropped:
        lines += ["## Đã loại bỏ / ghi chú của bộ kiểm tra", ""] + [f"- {d}" for d in p.dropped] + [""]
    if p.peak:
        lines += ["## PEAK Assistant", "", "Bảng ABLE và kế hoạch do PEAK viết nằm trong `peak_able.md` và `peak_hunt_plan.md` (tham khảo, không phải bằng chứng).", ""]
    lines.append("> Kế hoạch là gợi ý hỗ trợ quyết định; người săn mối đe dọa quyết định cuối cùng.")
    return "\n".join(lines) + "\n"
