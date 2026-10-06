"""Markdown rendering of the hunter-facing recommendation."""
from __future__ import annotations

from typing import Any

from hunting.recommend import DISPOSITION_LABEL, Recommendation

_CONF_NOTE = {"HIGH": "cao", "MEDIUM": "trung bình", "LOW": "thấp"}


def _bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items] or ["- (không có)"]


def render_recommendation(rec: Recommendation, meta: dict[str, Any], act_block: dict[str, Any]) -> str:
    ev = rec.evidence
    lines: list[str] = [
        f"# Khuyến nghị hunt — `{rec.poc_id}`",
        "",
        f"**PoC:** {rec.poc_name}  ",
        f"**Cửa sổ dữ liệu:** `{ev.window}`  ",
        f"**Nguồn dữ liệu:** {meta.get('data_source', '-')}  ",
        f"**PEAK Assistant:** {'đã dùng (ABLE + hunt plan)' if meta.get('used_peak') else 'KHÔNG dùng — ' + '; '.join(meta.get('peak_notes', []))}",
        "",
        "## Khuyến nghị",
        "",
        f"### {DISPOSITION_LABEL[rec.disposition]}",
        f"`{rec.disposition}` — độ tin cậy **{_CONF_NOTE.get(rec.confidence, rec.confidence)}** ({rec.confidence}).",
        "",
        "> Đây là gợi ý hỗ trợ quyết định. **Người săn mối đe dọa là người quyết định cuối cùng**; "
        "hệ thống không tự hành động.",
        "",
        "**Lý do**",
        "",
        *_bullets(rec.reasons),
        "",
        "**Cần lưu ý (giới hạn của kết luận)**",
        "",
        *_bullets(rec.caveats),
        "",
        "## Các lựa chọn cho người quyết định (xếp theo ưu tiên)",
        "",
        "| # | Hành động | Việc cần làm |",
        "|---|---|---|",
    ]
    for opt in rec.options:
        lines.append(f"| {opt.rank} | `{opt.action}` ({DISPOSITION_LABEL[opt.action]}) | {opt.rationale} |")

    lines += [
        "", "## Bằng chứng", "",
        "| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Trong phạm vi lọc | Khớp (hiển thị / tổng) |",
        "|---|---|---|---|---|---|",
    ]
    for s in ev.steps:
        cov = "không kiểm tra được" if s.source_rows_in_window is None else f"{s.source_rows_in_window:,}"
        in_scope = "không kiểm tra được" if s.source_rows_in_scope is None else f"{s.source_rows_in_scope:,}"
        if s.matched_total > s.row_count or s.scan_truncated:
            hit = f"{s.row_count} / {'≥' if s.scan_truncated else ''}{s.matched_total}"
        else:
            hit = str(s.row_count)
        lines.append(f"| `{s.step_id}` | `{s.predicate}` | {s.source_kind} | {cov} | {in_scope} | {hit} |")
    if ev.scope.get("host") or ev.scope.get("actor") or ev.scope.get("observables"):
        lines += ["", "**Phạm vi truy vấn thực tế** (ngoài predicate, suy ra từ ABLE của PoC):"]
        if ev.scope.get("host"):
            lines.append(f"- host = `{ev.scope['host']}`")
        if ev.scope.get("actor"):
            lines.append(f"- tài khoản chứa `{ev.scope['actor']}`")
        if ev.scope.get("observables"):
            lines.append("- chuỗi bổ sung (AND): " + ", ".join(f"`{o}`" for o in ev.scope["observables"]))
    lines += ["", f"Tổng {ev.observations} bản ghi hiển thị làm bằng chứng; {ev.matched_steps}/{ev.total_steps} bước có kết quả."]
    if ev.first_seen:
        lines.append(f"Hit đầu tiên {ev.first_seen}, hit cuối {ev.last_seen}.")
    for name, values in ev.pivots.items():
        lines.append(f"- Top `{name}`: " + ", ".join(f"{v} ({c})" for v, c in values))
    for name, values in ev.top_values.items():
        lines.append(f"- Giá trị phổ biến của `{name}`: " + ", ".join(f"`{v[:90]}` ({c})" for v, c in values[:3]))
    if ev.samples:
        lines += ["", "**Mẫu bản ghi**", ""]
        lines += [f"- `{sample}`" for sample in ev.samples[:3]]

    if rec.judge is not None:
        lines += [
            "", "## Judge (LLM, chỉ tham khảo)", "",
            f"**{rec.judge.verdict}** — độ tin cậy {rec.judge.confidence:.2f}",
            "", rec.judge.rationale, *[f"- {n}" for n in rec.judge.notes],
        ]

    lines += ["", "## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)", ""]
    if rec.next_steps:
        lines += [f"{i}. **{s['action']}** — {s['why']}" for i, s in enumerate(rec.next_steps, 1)]
    else:
        lines.append("(không có)")
    if rec.advisor_note:
        lines += ["", f"_{rec.advisor_note}_"]
    lines += ["", "**Câu hỏi để người săn tự trả lời trước khi quyết định**", "", *_bullets(rec.questions_for_hunter)]
    lines += ["", "**Rủi ro nếu quyết định sai**", "", *_bullets(rec.risks)]

    lines += [
        "", "## Kế hoạch từ PEAK Assistant", "",
        f"Chi tiết: `{meta.get('able_file')}` (bảng ABLE) và `{meta.get('plan_file')}` (hunt plan).",
        "", *[f"- {note}" for note in meta.get("peak_notes", [])],
        "", "## Act: bản nháp phát hiện (SPL)", "",
        f"Trạng thái: **{(act_block.get('validation') or {}).get('status', 'DRAFT')}** (chưa chạy trên Splunk thật).",
        "", "```spl", str(act_block.get("detection_spl", "")), "```",
        "", "## Chi phí và tái lập", "",
        f"- LLM (judge + advisor): {meta.get('llm_calls', 0)} lần gọi, {meta.get('llm_tokens', 0)} token. "
        "Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.",
        f"- Thời gian chạy bước Execute (gồm lệnh gọi judge): {meta.get('hunt_seconds', 0):.2f}s",
        f"- Ledger: `{meta.get('ledger_path')}`",
        "",
    ]
    return "\n".join(lines)


def render_summary(items: list[dict[str, Any]]) -> str:
    lines = [
        "# Tổng hợp khuyến nghị các PoC",
        "",
        "| PoC | Verdict thực thi | Bản ghi | Khuyến nghị | Tin cậy | PEAK | Báo cáo |",
        "|---|---|---|---|---|---|---|",
    ]
    for it in items:
        lines.append(
            f"| `{it['poc_id']}` | {it['verdict']} | {it['observations']} | `{it['disposition']}` | {it['confidence']} | "
            f"{'có' if it['used_peak'] else 'không'} | [{it['poc_id']}/recommendation.md]({it['poc_id']}/recommendation.md) |"
        )
    lines += ["", "Mọi khuyến nghị chỉ hỗ trợ quyết định; người săn là người chốt hành động.", ""]
    return "\n".join(lines)
