# Kết quả tốt nhất — Joomla web compromise (BOTS v1 attack thật)

> Thư mục này chứa kết quả đã verify trên dữ liệu thật, mang lên repo thay cho
> các artifacts cũ đã gỡ. Tái chạy bằng lệnh ở cuối file.

## 1. Hypothesis engine path (template replay, 0 LLM compile calls)

`HUNT-REPORT.md` — hypothesis *"Attacker exploits Joomla search component on
imreallynotbatman.com"* → **SUPPORTED / STOP_RESOLVED**:

- 1 evidence card (12,019 web requests tới victim, query complete=True qua 2 pages)
- Causal Path 100%, 1 query, `cdb_web_requests` với binding `subject=domain`
- `audit_summary.json`, `queries.json`, `evidence_cards.json` kèm theo

Giới hạn trung thực: card chứng minh *traffic tới victim*, URIs trong card chưa
chứa chuỗi Joomla/search/exploit — SUPPORTED ở mức web-access, chưa phải RCE proven.
Chuẩn cao hơn nằm ở PoC bên dưới.

## 2. PoC + LLM judge (TRUE_POSITIVE 0.87)

`POC-JUDGE-REPORT.md` — `poc-joomla-rce` (site EQUALS + uri CONTAINS `/joomla/`):

- MATCHED 199 obs, 2/2 steps; judge **TRUE_POSITIVE (0.87)**:
  "Acunetix probe, fuzz paths, Joomla enumeration consistent with scan stage"
- 1 LLM call, 4995 tokens. 4 PoC còn lại trên benign: EMPTY + NO_SIGNAL, 0 FP.

## 3. Tái chạy

```bash
# Hypothesis (cần template + eval DB)
.venv/Scripts/python.exe main.py --provider cdb --db data/botsv1_eval.sqlite \
  --hypothesis "Attacker exploits Joomla search component on imreallynotbatman.com to gain access" \
  --time-window "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z" \
  --llm api --query-limit 10000 \
  --graph-template templates/joomla-web-compromise.graph.json

# PoC + judge (cần eval DB + .env có LLM key)
.venv/Scripts/python.exe main.py --provider cdb --db data/botsv1_eval.sqlite \
  --poc-file pocs/poc-joomla-rce.json \
  --time-window "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z" \
  --poc-judge --llm api --poc-judge-max-tokens 16000
```

Eval DB (`data/botsv1_eval.sqlite`, 4.42M rows) không commit — dựng bằng
`scripts/ingest_botsv1_eval.py` + `scripts/ingest_http.py` (xem `docs/EVAL-GROUND-TRUTH.md`).
