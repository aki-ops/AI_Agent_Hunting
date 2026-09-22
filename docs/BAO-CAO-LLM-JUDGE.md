# Báo cáo: LLM có detect được attack dựa trên PoC không? (2026-09-22)

> Chạy trên eval DB thật (`data/botsv1_eval.sqlite`, 4.42M rows BOTS v1).
> Model: `meta/muse-spark-1.3-contributor` qua OpenRouter (config từ `.env`).
> Câu hỏi: với các PoC mình đưa, LLM judge có phát hiện đúng attack không?

## 1. Kết quả tổng (5 PoC + 1 hypothesis tự do)

| # | PoC / Input | Verdict (rules) | Judge (LLM) | Đọc kết quả |
|---|---|---|---|---|
| 1 | `poc-joomla-rce` (attack thật: 19.7k Joomla rows) | MATCHED (199 obs) | **TRUE_POSITIVE 0.87** | LLM detect đúng: "Acunetix probe, fuzz paths, Joomla enumeration consistent with scan stage" |
| 2 | `poc-pdf-exploit-enc` (0 encoded-PS thật trong DB) | EMPTY | NO_SIGNAL | Đúng: không có gì để chấm, judge không bịa |
| 3 | `poc-bruteforce-we1149srv` (0× 4625 thật) | EMPTY | NO_SIGNAL | Đúng: absence of evidence, không hô bừa |
| 4 | `poc-c2-beacon-networkfilter` (0× beacon thật) | EMPTY | NO_SIGNAL | Đúng: không bịa TP |
| 5 | `poc-phishing-powershell-enc` built-in (0 hit) | ESCALATED (1 LLM call) | NO_SIGNAL | Escalation trả narrative bounded; judge giữ NO_SIGNAL — đúng |
| 6 | Hypothesis tự do Joomla (engine path) | INCONCLUSIVE | — | 48k obs, 4 queries, 1 card nhưng relation chưa proven |

**Trả lời câu hỏi:** có — LLM judge detect đúng TP duy nhất có thật (Joomla 0.87)
và giữ im lặng đúng ở cả 4 trường hợp không có attack (NO_SIGNAL, không bịa TP).
Điểm yếu duy nhất lộ ra là judge non-deterministic (Joomla trước đây từng
INCONCLUSIVE 0.82, lần này TRUE_POSITIVE 0.87) — verdict chính phải là rules.

## 2. Chi tiết từng lần chạy (tokens / cost)

| Chạy | LLM calls | Tokens | Verdict |
|---|---|---|---|
| Joomla PoC + judge | 1 [match=0, judge=1] | 4995 | TP 0.87 |
| PDF-enc PoC | 0 | 0 | NO_SIGNAL |
| Brute-force PoC | 0 | 0 | NO_SIGNAL |
| C2 PoC | 0 | 0 | NO_SIGNAL |
| Phishing-PS built-in | 1 [match=1, judge=0] | 400 | NO_SIGNAL |
| Hypothesis tự do | 3 | 12247 ($0.0149) | INCONCLUSIVE, 48k obs |

Tổng: LLM chỉ tốn tiền khi có việc thật (judge TP 1 lần, escalation 1 lần,
hypothesis compile 3 calls). 3/5 PoC tốn 0 token vì EMPTY → skip LLM đúng thiết kế.

## 3. Giới hạn (nói trước với sếp)

- Judge chấm đúng 1/1 TP có thật — mẫu quá nhỏ để claim tỷ lệ.
- Judge non-deterministic: cùng evidence Joomla từng ra INCONCLUSIVE 0.82 và
  TRUE_POSITIVE 0.87 ở 2 lần chạy → chỉ advisory.
- Hypothesis engine path ra INCONCLUSIVE (48k obs nhưng relation unproven) —
  PoC viết tay vẫn là đường ra kết quả đáng tin hơn hypothesis tự do.
- Recall mới đo 1 phase (Joomla web); 4625/encoded-PS/networkfilter không có
  trong dữ liệu hiện có.

## 4. Tái chạy

```bash
.venv/Scripts/python.exe main.py --provider cdb --db data/botsv1_eval.sqlite \
  --poc-file pocs/poc-joomla-rce.json \
  --time-window "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z" \
  --poc-judge --llm api --poc-judge-max-tokens 16000
```
