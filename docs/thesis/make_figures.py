"""Vẽ các hình minh hoạ cho luận văn bằng Pillow (không cần matplotlib/mermaid).

Chạy: .venv\\Scripts\\python.exe docs/thesis/make_figures.py
Đầu ra: docs/thesis/assets/fig-*.png
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "assets"
OUT.mkdir(exist_ok=True)
FONT = "C:/Windows/Fonts/arial.ttf"
FONT_B = "C:/Windows/Fonts/arialbd.ttf"

BLUE, GREEN, ORANGE, GREY, RED, PURPLE = "#D9E8FB", "#DDF2DD", "#FDE9C9", "#EEEEEE", "#F8D7D7", "#E6DDF5"
EDGE = "#33415C"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_B if bold else FONT, size)


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt, width: int) -> list[str]:
    lines: list[str] = []
    for para in text.split("\n"):
        cur = ""
        for word in para.split(" "):
            trial = (cur + " " + word).strip()
            if draw.textlength(trial, font=fnt) <= width or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = word
        lines.append(cur)
    return lines


class Canvas:
    def __init__(self, w: int, h: int) -> None:
        self.img = Image.new("RGB", (w, h), "white")
        self.d = ImageDraw.Draw(self.img)

    def box(self, x, y, w, h, text, fill=BLUE, size=22, bold_first=True, align="center"):
        self.d.rounded_rectangle([x, y, x + w, y + h], radius=14, fill=fill, outline=EDGE, width=3)
        lines_all = []
        for i, para in enumerate(text.split("\n")):
            f = font(size, bold=(bold_first and i == 0))
            for ln in wrap(self.d, para, f, w - 24):
                lines_all.append((ln, f))
        lh = size + 6
        ty = y + (h - lh * len(lines_all)) / 2
        for ln, f in lines_all:
            tw = self.d.textlength(ln, font=f)
            tx = x + (w - tw) / 2 if align == "center" else x + 14
            self.d.text((tx, ty), ln, font=f, fill="#111111")
            ty += lh

    def arrow(self, x1, y1, x2, y2, label="", dashed=False, size=18):
        if dashed:
            n = 14
            for i in range(n):
                if i % 2 == 0:
                    a = i / n
                    b = (i + 1) / n
                    self.d.line([x1 + (x2 - x1) * a, y1 + (y2 - y1) * a, x1 + (x2 - x1) * b, y1 + (y2 - y1) * b], fill=EDGE, width=3)
        else:
            self.d.line([x1, y1, x2, y2], fill=EDGE, width=3)
        import math

        ang = math.atan2(y2 - y1, x2 - x1)
        for da in (2.7, -2.7):
            self.d.line([x2, y2, x2 + 16 * math.cos(ang + da), y2 + 16 * math.sin(ang + da)], fill=EDGE, width=3)
        if label:
            f = font(size)
            tw = self.d.textlength(label, font=f)
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            self.d.rectangle([mx - tw / 2 - 4, my - size / 2 - 4, mx + tw / 2 + 4, my + size / 2 + 4], fill="white")
            self.d.text((mx - tw / 2, my - size / 2 - 2), label, font=f, fill="#222222")

    def title(self, text, y=14, size=26):
        """Caption is added by the document builder; the figure itself carries no title."""
        return None

    def save(self, name):
        self.img.save(OUT / name)
        print("wrote", name, self.img.size)


def fig_peak_mapping():
    c = Canvas(1500, 760)
    c.title("Hình 1. Ba pha PEAK và thành phần hiện thực tương ứng")
    cols = [("PREPARE", "Chuẩn bị", BLUE, 40), ("EXECUTE", "Thực thi", GREEN, 540), ("ACT", "Hành động", ORANGE, 1040)]
    for name, vi, col, x in cols:
        c.box(x, 80, 420, 80, f"{name}\n{vi}", fill=col, size=28)
    c.arrow(460, 120, 540, 120)
    c.arrow(960, 120, 1040, 120)
    c.box(40, 190, 420, 130, "Khung PEAK\nchủ đề → nghiên cứu → giả thuyết → ABLE → phạm vi → kế hoạch", fill="white", size=20)
    c.box(540, 190, 420, 130, "Khung PEAK\nthu thập → phân tích → tinh chỉnh → leo thang IR", fill="white", size=20)
    c.box(1040, 190, 420, 130, "Khung PEAK\nbảo tồn → tài liệu → detection → backlog → truyền đạt", fill="white", size=20)
    c.d.line([40, 350, 1460, 350], fill="#999999", width=2)
    c.box(40, 380, 420, 170, "PEAK Assistant (Cisco Talos)\nable_table: bảng ABLE\nplan_hunt: planner + critic\n(tuỳ chọn) researcher", fill=BLUE, size=20)
    c.box(540, 380, 420, 170, "Bộ thực thi tất định\nPocAgent + adapter CDB/Splunk\nvị từ literal field/op/value\nmột lượt refine", fill=GREEN, size=20)
    c.box(1040, 380, 420, 170, "Khuyến nghị cho người quyết định\nluật tất định + judge + advisor\nbản nháp SPL, backlog", fill=ORANGE, size=20)
    c.box(40, 600, 1420, 110, "Knowledge: PoC, tài liệu tham khảo MITRE/PEAK, ledger các lần chạy, caveat về độ phủ dữ liệu\nChảy ngược vào Prepare của lần săn sau", fill=GREY, size=20)
    c.arrow(250, 600, 250, 552, dashed=True)
    c.arrow(750, 600, 750, 552, dashed=True)
    c.arrow(1250, 600, 1250, 552, dashed=True)
    c.save("fig-1-peak-mapping.png")


def fig_architecture():
    c = Canvas(1500, 900)
    c.title("Hình 2. Kiến trúc tổng thể của hệ thống")
    c.box(40, 80, 300, 90, "PoC (JSON)\ntopic, ABLE, bước, time_window", fill=GREY, size=20)
    c.box(40, 220, 300, 90, "CLI: main.py\n--poc-dir, --window, --offline, --model", fill=GREY, size=20)
    c.box(430, 80, 360, 110, "prepare.py\ncầu nối PEAK Assistant\n(retry, fallback offline)", fill=BLUE, size=20)
    c.box(430, 240, 360, 110, "llm.py\n.env → model_config.json\nPeakLlm, retry_async", fill=BLUE, size=20)
    c.box(890, 80, 570, 110, "PEAK Assistant (thư viện bên ngoài)\nable_table · plan_hunt (planner+critic) · researcher", fill=PURPLE, size=20)
    c.box(890, 240, 570, 110, "Endpoint LLM tương thích OpenAI\n(OpenRouter, Azure, cục bộ...) — TUỲ CHỌN", fill=PURPLE, size=20)
    c.box(40, 420, 360, 130, "poc/agent.py\nPocAgent: chạy vị từ\nanalyze → refine → IR", fill=GREEN, size=20)
    c.box(470, 420, 360, 130, "adapters/\nCdbAdapter (SQLite)\nSplunkLiveAdapter", fill=GREEN, size=20)
    c.box(900, 420, 560, 130, "Telemetry\nBOTS v1: 4,4 triệu dòng\nprocess · auth · smb · web · dns", fill=GREY, size=20)
    c.box(40, 650, 360, 130, "recommend.py\nluật tất định + advisor\nđộ phủ nguồn", fill=ORANGE, size=20)
    c.box(470, 650, 360, 130, "poc/judge.py\nJudge LLM (tham khảo)", fill=ORANGE, size=20)
    c.box(900, 650, 560, 130, "report.py · act/\nrecommendation.md/json\nSPL nháp · backlog · stakeholder", fill=ORANGE, size=20)
    c.arrow(190, 170, 190, 220)
    c.arrow(340, 125, 430, 125)
    c.arrow(790, 135, 890, 135)
    c.arrow(610, 190, 610, 240, dashed=True)
    c.arrow(790, 295, 890, 295)
    c.arrow(190, 310, 190, 420, "vị từ")
    c.arrow(400, 485, 470, 485)
    c.arrow(830, 485, 900, 485)
    c.arrow(220, 550, 220, 650, "hàng khớp")
    c.arrow(400, 715, 470, 715)
    c.arrow(830, 715, 900, 715)
    c.arrow(650, 550, 650, 650, "độ phủ")
    c.save("fig-2-architecture.png")


def fig_flow():
    c = Canvas(1500, 560)
    c.title("Hình 3. Luồng xử lý một PoC")
    steps = [
        ("1. Nạp PoC\nkiểm tra cổng\nPrepare", GREY), ("2. PEAK\nABLE + plan", BLUE), ("3. Thực thi\nvị từ literal", GREEN),
        ("4. Refine\n(tối đa 1 lượt)", GREEN), ("5. Độ phủ\nnguồn", GREEN), ("6. Luật\nkhuyến nghị", ORANGE),
        ("7. Judge +\nadvisor", ORANGE), ("8. Báo cáo\nMD/JSON", ORANGE),
    ]
    w, gap, x0 = 160, 28, 30
    for i, (t, col) in enumerate(steps):
        x = x0 + i * (w + gap)
        c.box(x, 120, w, 150, t, fill=col, size=21, bold_first=False)
        if i:
            c.arrow(x - gap, 195, x, 195)
    c.box(30, 330, 480, 160, "Không có LLM / không cấu hình .env\n→ bỏ bước 2 và 7, dùng ABLE/plan của PoC,\nkhuyến nghị vẫn do luật tất định tính", fill=GREY, size=20, bold_first=False)
    c.box(560, 330, 910, 160, "Lỗi LLM thoáng qua (ví dụ 404 model_not_found): gọi lại 3s/10s/25s từng bước;\nvẫn lỗi → ghi lý do vào peak.notes và dùng kế hoạch của PoC.\nLLM không bao giờ tạo hoặc sửa bản ghi bằng chứng.", fill=RED, size=20, bold_first=False)
    c.save("fig-3-flow.png")


def fig_decision():
    c = Canvas(1500, 900)
    c.title("Hình 4. Cây quyết định của luật khuyến nghị")
    c.box(560, 70, 380, 90, "Có bản ghi khớp?", fill=GREY, size=24)
    c.box(110, 230, 420, 90, "Mọi bước khớp?", fill=GREY, size=22)
    c.box(960, 230, 460, 90, "Nguồn cần thiết có 0 bản ghi\ntrong cửa sổ?", fill=GREY, size=20, bold_first=False)
    c.arrow(650, 160, 330, 230, "có")
    c.arrow(850, 160, 1190, 230, "không")
    c.box(20, 400, 330, 120, "Khớp một phần\nINVESTIGATE_FURTHER\nLOW/MEDIUM", fill=ORANGE, size=20)
    c.arrow(250, 320, 190, 400, "không")
    c.box(390, 400, 330, 90, "Judge ≥ 0,7?", fill=GREY, size=22)
    c.arrow(390, 320, 540, 400, "có")
    c.box(330, 580, 250, 120, "TRUE_POSITIVE\nESCALATE_TO_IR\nHIGH / MEDIUM", fill=RED, size=19)
    c.box(600, 580, 250, 120, "FALSE_POSITIVE\nTUNE_POC_OR_CLOSE\nMEDIUM", fill=GREEN, size=19)
    c.box(870, 580, 250, 120, "Không rõ / không judge\nINVESTIGATE_FURTHER\nMEDIUM", fill=ORANGE, size=19)
    c.arrow(480, 490, 455, 580)
    c.arrow(580, 490, 725, 580)
    c.arrow(650, 470, 995, 580)
    c.box(940, 400, 260, 120, "COLLECT_DATA_\nTHEN_RERUN\nHIGH", fill=BLUE, size=20)
    c.arrow(1100, 320, 1070, 400, "có")
    c.box(1240, 400, 240, 120, "CLOSE_WITH_CAVEAT\nMEDIUM\n(LOW nếu không kiểm\ntra được độ phủ)", fill=GREY, size=18)
    c.arrow(1300, 320, 1360, 400, "không")
    c.box(40, 770, 1420, 90, "HIGH của ESCALATE chỉ khi judge ≥ 0,8 VÀ PoC có bước kiểm tra kết quả (status/action); mọi khuyến nghị đều decision_required = true", fill="#FFFBE0", size=20, bold_first=False)
    c.save("fig-4-decision.png")


def fig_error():
    c = Canvas(1500, 500)
    c.title("Hình 5. Xử lý lỗi của lớp LLM")
    c.box(30, 110, 250, 120, "Gọi LLM\n(ABLE / plan /\njudge / advisor)", fill=BLUE, size=21, bold_first=False)
    c.box(350, 110, 250, 120, "Thành công?", fill=GREY, size=22)
    c.box(680, 110, 280, 120, "Gọi lại có backoff\n3s → 10s → 25s", fill=ORANGE, size=21, bold_first=False)
    c.box(1040, 110, 430, 120, "Vẫn lỗi: ghi nguyên nhân vào\npeak.notes / advisor_note", fill=RED, size=21, bold_first=False)
    c.arrow(280, 170, 350, 170)
    c.arrow(600, 170, 680, 170, "lỗi")
    c.arrow(960, 170, 1040, 170, "hết lượt")
    c.arrow(820, 110, 520, 110, "")
    c.box(350, 320, 250, 100, "Dùng kết quả LLM", fill=GREEN, size=21, bold_first=False)
    c.arrow(475, 230, 475, 320, "ok")
    c.box(1040, 320, 430, 100, "Dùng ABLE/plan của PoC;\nhunt vẫn chạy bình thường", fill=GREY, size=21, bold_first=False)
    c.arrow(1255, 230, 1255, 320)
    c.save("fig-5-errors.png")


if __name__ == "__main__":
    fig_peak_mapping()
    fig_architecture()
    fig_flow()
    fig_decision()
    fig_error()
