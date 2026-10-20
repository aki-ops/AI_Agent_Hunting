"""Sơ đồ ba bảo đảm của Prepare-only v0.4. Chạy: python docs/thesis/make_guarantees_figure.py
Ghi ra docs/images/three-guarantees.png (README) và docs/thesis/assets/fig-7-three-guarantees.png (luận văn)."""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_figures as mf  # noqa: E402
from make_figures import BLUE, GREEN, GREY, ORANGE, PURPLE, RED, Canvas  # noqa: E402

OUTS = [HERE.parent / "images" / "three-guarantees.png", HERE / "assets" / "fig-7-three-guarantees.png"]
CW, GAP, X0 = 540, 50, 40
COLS = [X0 + i * (CW + GAP) for i in range(3)]


def head(c: Canvas, x: int, text: str, fill: str) -> None:
    c.box(x, 20, CW, 90, text, fill=fill, size=24)


def main() -> None:
    c = Canvas(1790, 1330)
    head(c, COLS[0], "1. Kết quả không phụ thuộc model", GREEN)
    head(c, COLS[1], "2. Người quyết định từng bước", ORANGE)
    head(c, COLS[2], "3. SPL và thời gian được kiểm tra hai lần", RED)

    # ---- cột 1
    x, w = COLS[0], CW
    c.box(x, 160, w, 130, "Tình báo PoC/CVE công khai\nNVD · KEV · GitHub", fill=GREY, size=21)
    c.arrow(x + w // 2, 290, x + w // 2, 340)
    c.box(x, 340, w, 200, "CORE — mã tất định (origin=core)\nS1 ngữ cảnh · S2 nỗ lực · S3 hậu khai thác\nđiểm dừng, giới hạn, độ phủ sinh từ mẫu\ncore_digest: cùng tình báo → cùng giá trị\nvới MỌI model, kể cả không model", fill=GREEN, size=21)
    c.arrow(x + w // 2, 540, x + w // 2, 590)
    c.box(x, 590, w, 190, "GỢI Ý — LLM (origin=llm, tuỳ chọn)\n≤ 2 giai đoạn × 2 truy vấn, qua cùng check_spl\nkhông bao giờ có điểm dừng escalate\nlỗi / hết khoá → bỏ qua, lõi không đổi", fill=BLUE, size=21)
    c.arrow(x + w // 2, 780, x + w // 2, 830)
    c.box(x, 830, w, 190, "verify chỉ dựa vào CORE\ngợi ý LLM: người chấp nhận từng cái\n(accepted_llm_stages); kết quả của gợi ý\nchỉ để tham khảo, không leo thang, không pivot", fill=ORANGE, size=21)
    c.box(x, 1070, w, 200, "Đã đo\n5 cấu hình cho cùng core_digest: không LLM,\nkhoá hết hạn, model bị từ chối, deepseek-flash,\ndeepseek-v4-pro. plan_digest khác (gợi ý khác).\nChất lượng gợi ý: CHƯA đo", fill=GREY, size=20)

    # ---- cột 2
    x = COLS[1]
    steps = [
        ("R0  Duyệt kế hoạch (người)", "đọc plan.md, chấp nhận / bỏ gợi ý LLM\nghi approved_by, plan_digest", ORANGE),
        ("R1  Gắn chỉ mục và thời gian", "bind: một chỉ mục thật, mốc tuyệt đối\ntừ chối cả lô nếu không an toàn", RED),
        ("Độ phủ  C-*", "nguồn có dữ liệu không?\nrỗng không có nghĩa là sạch", GREEN),
        ("Mỗi truy vấn = một bước", "chạy tuần tự · ghi status, row_count\nghi 'dừng nếu' · không sửa tay SPL", GREEN),
        ("Cổng người sau mỗi giai đoạn", "câu hỏi chỉ người trả lời được\nimpact có kết quả → dừng, báo IR", ORANGE),
        ("Nộp kết quả", "kèm plan_digest + approved_by + approved_at\nthiếu / sai → REJECT_RESULTS", PURPLE),
        ("verify gợi ý, NGƯỜI quyết định", "REFINE = kế hoạch mới, duyệt lại từ R0\nACCEPT ≠ sạch", ORANGE),
    ]
    y, bh, gap = 160, 128, 24
    for i, (t, d, col) in enumerate(steps):
        c.box(x, y, CW, bh, f"{t}\n{d}", fill=col, size=21)
        if i < len(steps) - 1:
            c.arrow(x + CW // 2, y + bh, x + CW // 2, y + bh + gap)
        y += bh + gap
    c.d.text((x, y + 2), "27 bước trong kế hoạch Log4Shell, 14 có câu hỏi cho người", font=mf.font(19), fill="#222222")

    # ---- cột 3
    x = COLS[2]
    c.box(x, 160, CW, 330, "Lớp 1 — check_spl (lúc lập kế hoạch)\nchỉ lệnh trong allow-list · không truy vấn con/macro\nkhông eventstats, streamstats, mvexpand, makemv\nkhông group/dedup theo _raw · không limit=0, sort 0\nbộ lọc phải có chuỗi cụ thể ≥ 3 ký tự\nendpoint phải lọc tiến trình cha\nmốc thời gian và head do mã thêm, không do LLM", fill=RED, size=21)
    c.arrow(x + CW // 2, 490, x + CW // 2, 540, "bind")
    c.box(x, 540, CW, 330, "Lớp 2 — bind + lint_bound (sau khi gắn giá trị thật)\nđúng MỘT chỉ mục thật; cấm index=*, _internal\nmốc thời gian tuyệt đối (epoch), cửa sổ ≤ 90 ngày\nkhông đảo ngược, không ở tương lai\nbắt buộc head N (1 ≤ N ≤ max_rows)\nkiểm tra lại allow-list lệnh trên truy vấn đã gắn\nbắt cả khi plan.json bị sửa tay", fill=RED, size=21)
    c.arrow(x + CW // 2, 870, x + CW // 2, 920)
    c.box(x, 920, CW, 150, "Kết quả: queries.bound.spl\ncó lỗi → từ chối CẢ LÔ, in mọi lỗi cùng lúc,\nkhông ghi file nào", fill=PURPLE, size=21)
    c.box(x, 1120, CW, 150, "Chưa có / giới hạn\nChưa chạy trên Splunk thật (tên trường CIM, tstats).\nKhông thay hạn mức tìm kiếm theo vai trò phía Splunk.", fill=GREY, size=20)

    for out in OUTS:
        out.parent.mkdir(parents=True, exist_ok=True)
        c.img.save(out)
    print("wrote", c.img.size)


main()
