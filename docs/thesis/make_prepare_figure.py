"""Sơ đồ pipeline của hướng Prepare-only v0.4 (Pillow). Chạy: python docs/thesis/make_prepare_figure.py
Ghi ra docs/images/pipeline-prepare-only.png (README) và docs/thesis/assets/fig-6-prepare-only.png (luận văn)."""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_figures as mf  # noqa: E402
from make_figures import BLUE, GREEN, GREY, ORANGE, PURPLE, RED, Canvas  # noqa: E402

OUTS = [HERE.parent / "images" / "pipeline-prepare-only.png", HERE / "assets" / "fig-6-prepare-only.png"]
W, H, GAP = 390, 210, 40
XS = [30, 460, 890, 1320]


def title(c: Canvas, y: int, text: str, color: str = "#33415C", x: int = 30) -> None:
    c.d.text((x, y), text, font=mf.font(26, bold=True), fill=color)


def legend(c: Canvas, y: int) -> None:
    items = [(BLUE, "LLM / PEAK (tuỳ chọn)"), (GREEN, "Mã tất định"), (RED, "Kiểm tra an toàn"), (ORANGE, "Con người / bàn giao"), (GREY, "Ngoài dự án / nguồn"), (PURPLE, "Tài liệu trao đổi")]
    for i, (col, txt) in enumerate(items):
        x = 40 + i * 290
        c.d.rounded_rectangle([x, y, x + 40, y + 28], radius=6, fill=col, outline=mf.EDGE, width=2)
        c.d.text((x + 52, y + 2), txt, font=mf.font(20), fill="#111111")


def main() -> None:
    c = Canvas(1790, 1700)

    # ---- nguồn công khai
    title(c, 14, "ĐẦU VÀO — nguồn công khai: cho biết lỗ hổng và PoC là gì (chỉ đọc, HTTPS, allow-list 3 host)")
    c.box(30, 52, 390, 84, "NVD API\nCVSS · CWE · phiên bản · cờ CISA KEV", fill=GREY, size=19)
    c.box(460, 52, 390, 84, "GitHub API + raw\nrepo nhiều sao · README · mã PoC\n(chỉ đọc văn bản)", fill=GREY, size=19)
    c.arrow(225, 136, 225, 168)
    c.arrow(655, 136, 330, 168)

    # ---- hàng 1
    y1 = 170
    r1 = [
        ("1. gather() + Fetcher", "NVD · GitHub · cache 24h\nCVE yêu cầu luôn là CVE chính\n(NVD lỗi vẫn giữ + cảnh báo)\n→ IntelBundle", GREEN),
        ("2. extract_indicators() + digest()", "regex: http_param, uri_pattern, oast_domain,\nuser_agent, file_name, command...\ndigest: exploit/README trước, fence <<< >>>", GREEN),
        ("3. build_core()  — CORE", "mã dựng S1 · S2 · S3 từ chuỗi CÓ trong PoC\nbỏ regex và biến trong mã\nKHÔNG gọi LLM → core_digest", GREEN),
        ("4. Gợi ý LLM  (tuỳ chọn)", "PEAK (tuỳ chọn) + đề xuất ≤ 2×2 truy vấn\nnhãn origin=llm\nlỗi hoặc hết khoá → bỏ qua, lõi giữ nguyên", BLUE),
    ]
    for x, (t, d, col) in zip(XS, r1):
        c.box(x, y1, W, H, f"{t}\n{d}", fill=col, size=20)
    for i in range(3):
        c.arrow(XS[i] + W, y1 + H // 2, XS[i + 1], y1 + H // 2)

    # ---- hàng 2 (rắn: phải sang trái)
    title(c, 405, "PREPARE — dự án này: lõi do mã + gợi ý có nhãn (cục bộ)")
    y2 = 450
    r2 = [
        (XS[3], "5. assemble() + check_spl()", "allow-list lệnh · 1 index · lọc cụ thể\ncấm eventstats, group theo _raw\ntiến trình cha · ngoại ngữ → plan.dropped", RED),
        (XS[2], "6. build_plan() + stamp()", "ghép lõi + gợi ý · điểm dừng, độ phủ, giới hạn\nbuild_runbook() từng bước, cổng người\ncore_digest · plan_digest", GREEN),
        (XS[1], "7. write_plan()", "plan.json · plan.md · RUNBOOK.md\nqueries.spl (mẫu) · result.template.json\n+ plan/result.schema.json", PURPLE),
        (XS[0], "R0. NGƯỜI duyệt kế hoạch", "đọc plan.md + việc phải tự làm\nchấp nhận / bỏ từng gợi ý LLM\nghi approved_by, plan_digest", ORANGE),
    ]
    for x, t, d, col in r2:
        c.box(x, y2, W, H, f"{t}\n{d}", fill=col, size=20)
    c.arrow(XS[3] + W // 2, y1 + H, XS[3] + W // 2, y2, "JSON gợi ý")
    c.arrow(XS[2] + W // 2, y1 + H, XS[2] + W // 2, y2, "lõi (không qua LLM)")
    for i in range(3, 0, -1):
        c.arrow(XS[i], y2 + H // 2, XS[i - 1] + W, y2 + H // 2)

    # ---- hàng 3: bind + Execute
    title(c, 705, "ĐỘI EXECUTE — ngoài dự án: chạy truy vấn trên dữ liệu thật (dữ liệu nội bộ ở lại bên đó)", "#7A4B00", x=300)
    y3 = 750
    c.arrow(XS[0] + W // 2, y2 + H, XS[0] + W // 2, y3)
    c.d.text((XS[0] + W // 2 + 12, y2 + H + 12), "đã duyệt", font=mf.font(18), fill="#222222")
    r3 = [
        (XS[0], "R1. bind_plan()  — lệnh bind", "1 chỉ mục thật / nguồn · thời gian tuyệt đối ≤ 90 ngày\nlint: không index=*, bắt buộc head N\nlỗi → từ chối cả lô; ra queries.bound.spl", RED),
        (XS[1], "Chạy trên Splunk của họ", "theo RUNBOOK, từng bước một\nđộ phủ trước · cổng người mỗi giai đoạn\n≤ max_rows · ≤ timeout", GREY),
        (XS[2], "ResultBundle (results.json)", "query_id · status · row_count · sample ≤ 25\nplan_digest · approved_by · approved_at\naccepted_llm_stages", PURPLE),
    ]
    for x, t, d, col in r3:
        c.box(x, y3, W, H, f"{t}\n{d}", fill=col, size=20)
    c.arrow(XS[0] + W, y3 + H // 2, XS[1], y3 + H // 2)
    c.arrow(XS[1] + W, y3 + H // 2, XS[2], y3 + H // 2)
    c.box(XS[3], y3, W, H, "Ranh giới dữ liệu\nChỉ ResultBundle quay về.\nKhông có tên host/index/IP nội bộ\nđi vào LLM hay vào kế hoạch.", fill=GREY, size=20)

    # ---- hàng 4: verify
    title(c, 995, "XÁC MINH — verify(): nhận kết quả hay chạy vòng sau (mã thuần, không LLM)")
    y4 = 1040
    c.arrow(XS[2] + W // 2, y3 + H, XS[2] + W // 2, y4, "results.json")
    r4 = [
        (XS[2], "A. Chữ ký & giao thức", "thiếu người duyệt / sai plan_digest\n/ sai plan_id → REJECT_RESULTS\nquery lạ · trùng · mẫu > 25 dòng", RED),
        (XS[1], "B. Trạng thái", "truy vấn HIT/ZERO/ERROR/NOT_RUN · độ phủ\ngợi ý LLM: SKIPPED hoặc chỉ tham khảo\nkhông leo thang, không pivot", GREEN),
        (XS[0], "C. Thứ tự quyết định", "1 escalate · 2 impact lỗi · 3 có dấu vết→pivot\n4 lỗi · 5 thiếu dữ liệu · 6 chấp nhận\nchỉ dựa vào phần LÕI", GREEN),
    ]
    for x, t, d, col in r4:
        c.box(x, y4, W, H - 20, f"{t}\n{d}", fill=col, size=20)
    c.arrow(XS[2], y4 + 95, XS[1] + W, y4 + 95)
    c.arrow(XS[1], y4 + 95, XS[0] + W, y4 + 95)

    # ---- hàng 5: quyết định
    title(c, 1236, "ĐẦU RA — gợi ý quyết định (người săn mới là người chốt, ghi tên và lý do)", x=240)
    y5 = 1330
    dw, dg = 320, 25
    decisions = [
        ("ESCALATE_AFFECTED", "giai đoạn impact (lõi) có sự kiện\n→ chuyển IR, dừng mở rộng", ORANGE),
        ("ACCEPT_NO_EVIDENCE", "chạy đủ, nguồn đủ, không thấy gì\n→ KHÔNG phải 'sạch'", GREEN),
        ("COLLECT_DATA /\nRERUN_INCOMPLETE", "nguồn rỗng hoặc truy vấn lỗi\n→ bổ sung / chạy lại", GREY),
        ("REFINE", "kế hoạch MỚI (plan_digest mới):\npivot src/dest/user, cửa sổ ±1h", BLUE),
        ("STOP_REVIEW /\nREJECT_RESULTS", "hết 3 vòng, hết dấu vết mới,\nthiếu chữ ký → người đọc", GREY),
    ]
    xs5 = [30 + i * (dw + dg) for i in range(5)]
    bus = 1290
    c.d.line([XS[0] + W // 2, y4 + H - 20, XS[0] + W // 2, bus], fill=mf.EDGE, width=3)
    c.d.line([xs5[0] + dw // 2, bus, xs5[4] + dw // 2, bus], fill=mf.EDGE, width=3)
    for x, (t_, d, col) in zip(xs5, decisions):
        c.box(x, y5, dw, 190, f"{t_}\n{d}", fill=col, size=19)
        c.arrow(x + dw // 2, bus, x + dw // 2, y5)
    # vòng lặp REFINE -> duyệt lại -> Execute
    rx = xs5[3] + dw // 2
    lx = 1765
    c.d.line([rx, y5 + 190, rx, y5 + 235], fill=mf.EDGE, width=3)
    c.d.line([rx, y5 + 235, lx, y5 + 235], fill=mf.EDGE, width=3)
    c.d.line([lx, y5 + 235, lx, y3 + H // 2 + 60], fill=mf.EDGE, width=3)
    c.arrow(lx, y3 + H // 2 + 60, XS[3] + W, y3 + H // 2 + 60)
    c.d.text((560, y5 + 245), "vòng N+1: iterN/plan.json là kế hoạch mới → người duyệt lại (R0) → bind → Execute", font=mf.font(20), fill="#222222")

    legend(c, 1650)
    for out in OUTS:
        out.parent.mkdir(parents=True, exist_ok=True)
        c.img.save(out)
    print("wrote", c.img.size)


main()
