"""Gộp 12 tệp chương trong docs/paper thành một tài liệu luận văn DOCX.

- Render mọi khối ```mermaid``` ra PNG (qua mermaid-cli / mmdc) và nhúng làm Hình.
- Đánh số chương/mục theo heading, đánh số Hình X.Y và Bảng X.Y theo chương.
- Thêm trang bìa, mục lục (trường TOC của Word), và số trang ở chân trang.

Chạy: .venv\\Scripts\\python.exe scripts/build_paper_docx.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "docs" / "paper"
ASSETS = PAPER / "assets"
ASSETS.mkdir(exist_ok=True)
NODE = r"C:\Program Files\nodejs\node.exe"
NPX_CLI = r"C:\Program Files\nodejs\node_modules\npm\bin\npx-cli.js"

CHAPTER_FILES = [
    "01-MO-DAU.md",
    "02-CO-SO-LY-THUYET.md",
    "03-KHUNG-PEAK.md",
    "04-KIEN-TRUC-HE-THONG.md",
    "05-CONG-PEAK-PREPARE.md",
    "06-PHUONG-PHAP-THUC-NGHIEM.md",
    "07-KET-QUA.md",
    "08-BAN-LUAN-VA-HAN-CHE.md",
    "09-KET-LUAN.md",
    "10-TAI-LIEU-THAM-KHAO.md",
    "11-PHU-LUC.md",
]


# --------------------------------------------------------------------------
# Mermaid rendering
# --------------------------------------------------------------------------
def render_mermaid(code: str, out_png: Path) -> bool:
    src = out_png.with_suffix(".mmd")
    src.write_text(code, encoding="utf-8")
    try:
        subprocess.run(
            [NODE, NPX_CLI, "-y", "@mermaid-js/mermaid-cli@latest",
             "-i", str(src), "-o", str(out_png), "-b", "white", "-s", "2"],
            check=True, capture_output=True, timeout=300,
        )
        return out_png.exists()
    except Exception as e:  # noqa: BLE001
        print(f"[!] mermaid render failed for {out_png.name}: {e}")
        return False
    finally:
        if src.exists():
            src.unlink()


# --------------------------------------------------------------------------
# DOCX low-level helpers
# --------------------------------------------------------------------------
def add_field(paragraph, instr: str):
    """Chèn một trường Word (PAGE, TOC, ...)."""
    run = paragraph.add_run()
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr_el = OxmlElement("w:instrText")
    instr_el.set(qn("xml:space"), "preserve")
    instr_el.text = instr
    fld_sep = OxmlElement("w:fldChar")
    fld_sep.set(qn("w:fldCharType"), "separate")
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    run._r.append(fld_begin)
    run._r.append(instr_el)
    run._r.append(fld_sep)
    run._r.append(fld_end)


def set_cell_background(cell, hex_color: str):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), hex_color)
    tc_pr.append(shd)


# --------------------------------------------------------------------------
# Inline markdown -> runs (bold, code)
# --------------------------------------------------------------------------
INLINE_RE = re.compile(r"(\*\*.+?\*\*|`.+?`)")


def add_inline(paragraph, text: str):
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)  # link -> "text (url)"
    for part in INLINE_RE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            r = paragraph.add_run(part[2:-2])
            r.bold = True
        elif part.startswith("`") and part.endswith("`"):
            r = paragraph.add_run(part[1:-1])
            r.font.name = "Consolas"
            r.font.size = Pt(9.5)
        else:
            paragraph.add_run(part)


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
def main() -> int:
    doc = Document()

    # Base styles
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)

    # Page number footer for the body section (added after cover/TOC sections)
    def add_page_footer(section):
        footer = section.footer
        footer.is_linked_to_previous = False
        p = footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run("Trang ")
        add_field(p, "PAGE")
        p.add_run(" / ")
        add_field(p, "NUMPAGES")

    # ---- COVER PAGE ----
    for _ in range(3):
        doc.add_paragraph()
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run("AI AGENT HUNTING")
    r.bold = True
    r.font.size = Pt(26)
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run("Tác tử điều tra mối đe dọa bị ràng buộc bởi bằng chứng,\nvận hành theo khung PEAK của Splunk")
    r.font.size = Pt(15)
    doc.add_paragraph()
    kind = doc.add_paragraph()
    kind.alignment = WD_ALIGN_PARAGRAPH.CENTER
    kind.add_run("Báo cáo nghiên cứu kỹ thuật").italic = True
    for _ in range(8):
        doc.add_paragraph()
    meta = [
        ("Hệ thống", "gói Python hunting v0.1.0"),
        ("Khung quy trình", "PEAK — Prepare, Execute, Act + Knowledge"),
        ("Dữ liệu đánh giá", "BOTS v1 (eval 4.42M dòng + sample 16 sự kiện)"),
        ("Kết quả kiểm thử", "514 passed, 13 skipped, 0 failed"),
        ("Ngày lập báo cáo", "2026-09-22"),
    ]
    for k, v in meta:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rr = p.add_run(f"{k}: ")
        rr.bold = True
        p.add_run(v)

    # ---- TOC SECTION ----
    doc.add_section(WD_SECTION.NEW_PAGE)
    h = doc.add_paragraph()
    h.add_run("MỤC LỤC").bold = True
    h.runs[0].font.size = Pt(16)
    toc_p = doc.add_paragraph()
    add_field(toc_p, r'TOC \o "1-3" \h \z \u')
    note = doc.add_paragraph()
    note.add_run("(Nhấn Ctrl+A rồi F9 trong Word để cập nhật mục lục và số trang.)").italic = True

    # ---- BODY SECTION with page numbers ----
    body_section = doc.add_section(WD_SECTION.NEW_PAGE)
    add_page_footer(body_section)

    fig_counter: dict[int, int] = {}
    tbl_counter: dict[int, int] = {}
    current_chapter = 0

    for cf in CHAPTER_FILES:
        lines = (PAPER / cf).read_text(encoding="utf-8").splitlines()
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]

            # --- fenced blocks ---
            if line.strip().startswith("```"):
                fence = line.strip()
                block: list[str] = []
                i += 1
                while i < n and not lines[i].strip().startswith("```"):
                    block.append(lines[i])
                    i += 1
                i += 1  # skip closing fence
                code = "\n".join(block)
                if fence.startswith("```mermaid"):
                    fig_counter[current_chapter] = fig_counter.get(current_chapter, 0) + 1
                    fno = f"{current_chapter}.{fig_counter[current_chapter]}"
                    png = ASSETS / f"fig-{current_chapter}-{fig_counter[current_chapter]}.png"
                    ok = render_mermaid(code, png)
                    if ok:
                        pic_p = doc.add_paragraph()
                        pic_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        run = pic_p.add_run()
                        try:
                            run.add_picture(str(png), width=Inches(6.0))
                        except Exception:
                            run.add_picture(str(png))
                    cap = doc.add_paragraph()
                    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    cr = cap.add_run(f"Hình {fno}. Sơ đồ minh họa")
                    cr.italic = True
                    cr.font.size = Pt(9.5)
                else:
                    for cl in block:
                        cp = doc.add_paragraph()
                        cr = cp.add_run(cl if cl else " ")
                        cr.font.name = "Consolas"
                        cr.font.size = Pt(9)
                continue

            # --- tables ---
            if line.lstrip().startswith("|") and i + 1 < n and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
                header = [c.strip() for c in line.strip().strip("|").split("|")]
                i += 2
                rows = []
                while i < n and lines[i].lstrip().startswith("|"):
                    rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                    i += 1
                tbl_counter[current_chapter] = tbl_counter.get(current_chapter, 0) + 1
                tno = f"{current_chapter}.{tbl_counter[current_chapter]}"
                cap = doc.add_paragraph()
                cr = cap.add_run(f"Bảng {tno}.")
                cr.italic = True
                cr.font.size = Pt(9.5)
                table = doc.add_table(rows=1, cols=len(header))
                table.style = "Light Grid Accent 1"
                for j, htext in enumerate(header):
                    c = table.rows[0].cells[j]
                    c.paragraphs[0].text = ""
                    add_inline(c.paragraphs[0], htext)
                    for rn in c.paragraphs[0].runs:
                        rn.bold = True
                    set_cell_background(c, "D9E2F3")
                for row in rows:
                    cells = table.add_row().cells
                    for j in range(len(header)):
                        val = row[j] if j < len(row) else ""
                        cells[j].paragraphs[0].text = ""
                        add_inline(cells[j].paragraphs[0], val)
                        for rn in cells[j].paragraphs[0].runs:
                            rn.font.size = Pt(9.5)
                doc.add_paragraph()
                continue

            # --- headings ---
            m = re.match(r"^(#{1,4})\s+(.*)$", line)
            if m:
                level = len(m.group(1))
                text = m.group(2).strip()
                # Chương X — ... : bắt số chương
                cm = re.match(r"^Chương\s+(\d+)\b", text)
                if level == 1 and cm:
                    current_chapter = int(cm.group(1))
                    fig_counter.setdefault(current_chapter, 0)
                    tbl_counter.setdefault(current_chapter, 0)
                doc.add_heading(text, level=min(level, 4))
                i += 1
                continue

            # --- blockquote ---
            if line.lstrip().startswith(">"):
                q = doc.add_paragraph(style="Intense Quote")
                add_inline(q, line.lstrip().lstrip(">").strip())
                i += 1
                continue

            # --- bullets ---
            bm = re.match(r"^(\s*)[-*]\s+(.*)$", line)
            if bm:
                p = doc.add_paragraph(style="List Bullet")
                add_inline(p, bm.group(2))
                i += 1
                continue

            # --- numbered list ---
            nm = re.match(r"^\s*\d+\.\s+(.*)$", line)
            if nm:
                p = doc.add_paragraph(style="List Number")
                add_inline(p, nm.group(1))
                i += 1
                continue

            # --- horizontal rule / blank ---
            if line.strip() in ("---", "***", "___"):
                i += 1
                continue
            if not line.strip():
                i += 1
                continue

            # --- normal paragraph ---
            p = doc.add_paragraph()
            add_inline(p, line.strip())
            i += 1

        # page break between chapters
        doc.add_page_break()

    out = PAPER / "BAO-CAO-NGHIEN-CUU.docx"
    doc.save(str(out))
    print(f"[+] DOCX written: {out} ({out.stat().st_size} bytes)")

    # cleanup probe
    for f in (ASSETS / "_probe.png", ASSETS / "_probe.mmd"):
        if f.exists():
            f.unlink()

    return 0


if __name__ == "__main__":
    sys.exit(main())
