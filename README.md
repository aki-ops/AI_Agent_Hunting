# AI Agent Hunting (v7) — PEAK Assistant + hunt tất định + khuyến nghị cho người quyết định

Công cụ hỗ trợ săn mối đe dọa theo khung PEAK. Phần **Prepare** do
[PEAK Assistant](https://github.com/Cisco-Talos/PEAK-Assistant) (Cisco Talos) đảm nhiệm, phần **Execute**
chạy các predicate literal trên telemetry, phần **Act** đưa ra *khuyến nghị có xếp hạng* để người săn
mối đe dọa quyết định. Hệ thống không tự hành động.

```text
PoC (JSON) ──► PEAK Assistant: ABLE table + hunt plan (planner/critic)      [LLM, tham khảo]
          ──► Execute: predicate field/op/value trên CDB hoặc Splunk        [tất định, không LLM]
          ──► Judge + Advisor (LLM) + luật tất định                          [tham khảo]
          ──► recommendation.md / .json  → NGƯỜI QUYẾT ĐỊNH
```

Bất biến: LLM không tạo hay sửa bằng chứng; bản ghi chỉ đến từ adapter. Kết quả rỗng khi nguồn telemetry
không có dữ liệu được báo là `COLLECT_DATA_THEN_RERUN`, không phải "sạch".

## Cài đặt (Python ≥ 3.12)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate trên Linux/macOS
pip install -e ".[dev]"          # kéo theo PEAK Assistant (pin theo commit)
cp .env.example .env             # điền LLM_ENDPOINT, LLM_API_KEY, LLM_MODEL (endpoint tương thích OpenAI)
```

## Chạy

```bash
# Tất cả PoC trong pocs/ (PEAK Assistant + LLM; mỗi PoC ~4-8 phút vì planner/critic lặp)
python main.py --poc-dir pocs --db data/botsv1_eval.sqlite

# Một PoC, cửa sổ tự chọn
python main.py --poc pocs/poc-joomla-rce.json --window 2016-08-10T21:36:00Z/2016-08-10T22:00:00Z

# Chỉ phần tất định (không PEAK, không LLM)
python main.py --poc-dir pocs --offline
```

Kết quả nằm ở `artifacts/runs/<thời gian>/`: `summary.md`, và mỗi PoC có `recommendation.md`,
`recommendation.json`, `peak_able.md`, `peak_hunt_plan.md`, ledger, bản nháp SPL (`act/`).
Mẫu kết quả đã kiểm chứng: [`results/`](results/).

## Kiểm thử

```bash
python -m pytest tests -q
ruff check .
```

## Cấu trúc

| Đường dẫn | Vai trò |
|---|---|
| `src/hunting/llm.py` | `.env` → cấu hình `model_config.json` của PEAK; caller đồng bộ dùng chung client PEAK |
| `src/hunting/prepare.py` | cầu nối PEAK: `able_table`, `plan_hunt` (tuỳ chọn `researcher`); có fallback offline |
| `src/hunting/poc/` | mô hình PoC, loader JSON, agent thực thi, judge |
| `src/hunting/adapters/` | CDB (SQLite) và Splunk live; `source_presence`, `describe_data` |
| `src/hunting/recommend.py` | luật khuyến nghị + advisor |
| `src/hunting/pipeline.py`, `cli.py`, `report.py` | điều phối, CLI, báo cáo |
| `pocs/` | PoC mẫu (BOTS v1) |
| `docs/ARCHITECTURE.md`, `docs/BAO-CAO-PEAK-ASSISTANT.md` | kiến trúc, luật khuyến nghị, giới hạn; báo cáo thay đổi và kết quả |
| `docs/archive/` | engine v6 (ClaimGraph) và paper cũ; khôi phục code bằng tag `v6-engine-final` |
