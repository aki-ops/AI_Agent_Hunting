# Báo cáo: Hệ thống săn tìm mối đe dọa tự động — giả thuyết, kiểm chứng và đánh giá trên dữ liệu thật

> Một file duy nhất từ đầu tới đuôi: giả thuyết đầu vào → phương pháp → demo →
> đánh giá số liệu → giới hạn → kết luận. Gộp từ 3 tài liệu chi tiết
> (`PEAK-RESEARCH-AND-MAPPING.md`, `PEAK-END-TO-END-DEMO.md`, `EVAL-GROUND-TRUTH.md`).

## 1. Giả thuyết đầu vào: hệ thống này săn cái gì?

Hệ thống không tự nghĩ ra giả thuyết. Mọi lần chạy đều bắt đầu từ một trong hai loại đầu vào do analyst đưa:

1. **PoC viết sẵn** — kịch bản tấn công cụ thể, testable, gắn MITRE. Ví dụ:
   - "Joomla có thể bị RCE qua search component" (T1190)
   - "Có thể có brute-force vào server" (T1110)
   - "Có thể có encoded PowerShell từ phishing" (T1566 → T1059.001)
   - "Có thể có C2 beacon ra domain ngoài" (T1071.001)
2. **Nghi ngờ tự do** — analyst gõ câu hỏi ("Phishing email dẫn tới PowerShell trên máy X?"),
   tool biên dịch thành kế hoạch hunt có cấu trúc.

Mỗi PoC phải có hunt plan trước khi chạy: topic, research, ABLE, scope, max duration, plan.
Actor được để trống. Token cụ thể trong ABLE (host có chữ số, account `DOMAIN\user`, tên file, flag, IP, chuỗi trích dẫn) thành predicate của query. Phần văn xuôi không thêm điều kiện. Matching vẫn literal, không do LLM bịa hàng.

## 2. Phương pháp: deterministic trước, LLM chỉ advisory

```
Prepare (wizard hoặc YAML): topic → research → ABLE → scope → plan
  → từ chối chạy nếu thiếu trường bắt buộc
  → max_duration cắt cửa sổ về cạnh cuối
PoC
  → compile deterministic thành SemanticGoalGraph; ABLE thành constraint (không LLM)
  → pass 1: match literal qua adapter
  → analyze → tối đa một pass refine (siết host, hoặc chạy lại predicate gốc)
  → MATCHED / EMPTY
  → finding khớp, hoặc narrative LLM khi rỗng: ghi gói IR
  → nếu MATCHED và analyst yêu cầu: LLM judge TP/FP/INCONCLUSIVE (advisory)
  → Act: SPL + kiểm tra parser Splunk khi có session, backlog JSONL, stakeholder Markdown
  → ledger JSON + report
```

Baseline survey vẫn là EDA không LLM. Nhánh `--math` không train model: nó gọi API LLM
đã khai trong `.env`. Lead chỉ sống nếu giá trị nằm trong hàng đã kéo. Khi API không
có, prefilter stdlib chạy và được ghi rõ là không phải model đã train.

**Lập trường:** PEAK là quy trình Splunk SURGe. Kho này chạy bốn cửa đó trên đường PoC
và không nhận chứng nhận PEAK. Match vẫn deterministic. LLM không tạo observation.

## 3. Demo trên sample 16 events (BOTS v1 thu gọn)

Quy trình 3 bước trên cùng sample. Baseline không gọi LLM. `--math` gọi API nếu `.env` sẵn sàng:

| Bước | Lệnh | Kết quả |
|---|---|---|
| Baseline survey | `--baseline cdb:events` | 16 rows → 11 fields, 23 outliers (`smtp`, `schtasks.exe`, `svc_admin`...), 4 gaps (`domain`, `file_path`... trống) |
| LLM-assisted (`--math`) | `--math cdb:events` | API LLM xếp lead đã có trong hàng; không có API thì prefilter stdlib |
| PoC + Judge | `--poc-file pocs/poc-pdf-exploit-enc.json --poc-judge --llm api` | MATCHED 9 obs, 3 steps; judge INCONCLUSIVE 0.88 (bóc được SCCM `foobar` là noise, 2 cmdline alice thiếu parent/network nên không kết TP) |

Mỗi bước sinh report có Act (SPL draft + backlog + stakeholder) và ledger tái chạy được.

## 4. Đánh giá trên dữ liệu BOTS v1 thật (4.42M rows, 19 ngày)

Dataset: full Security CSV 14.2M rows (lọc giữ auth/process/SMB) + 66 sysmon
Event-1 + 35.9k stream:dns + 39k stream:http → eval DB `data/botsv1_eval.sqlite`.

**Specificity (4 PoC × 4.38M benign rows, ~26s): 0 FP.**

| PoC | Verdict | FP rate |
|---|---|---|
| `poc-phishing-powershell-enc` | EMPTY | 0 |
| `poc-c2-beacon` | EMPTY | 0 |
| `poc-office-macro` | EMPTY | 0 |
| `poc-credential-phish` | EMPTY | 0 |

Eval này khui ra 2 bugs đã fix: `EQUALS` qua LIKE match cả `splunk-powershell.exe`
(100 FP) → post-filter exact + basename; step `EXISTS` rỗng match bừa → chặn +
xóa step vô nghĩa khỏi `poc-c2-beacon`. Trước fix FP rate 0.000023, sau fix = 0.

**Recall trên attack thật (Joomla RCE, stream:http):** `imreallynotbatman.com`
22k hits, `/joomla/.../search/` 16.6k hits — đúng BOTS web-compromise phase.
PoC `poc-joomla-rce.json` → **MATCHED 199 obs, 2/2 steps; judge INCONCLUSIVE 0.82**
— judge phân biệt đúng recon (Acunetix probe, URI discovery) vs compromise
(thiếu payload/status/RCE evidence). Đây là TP đầu tiên trên attack thật.

## 5. Giới hạn (nói trước)

- Substring scan từng báo sai đã đính chính: `4656`≠`4625`, `iexplore`≠`IEX`.
  **0× failed-logon 4625 thật, 0× encoded-PS thật, 0× `networkfilter` beacon**
  trong dữ liệu hiện có — các phase đó nằm ở sourcetype chưa tải.
- Recall mới đo 1 phase (Joomla web). Judge non-deterministic (0.97/0.92/0.88 cùng
  evidence) — chỉ advisory, không làm verdict chính.
- SPL draft chưa validate trên Splunk thật; baseline demo 1 ngày (chuẩn 30–90d).

## 6. Kết luận

Tool phát hiện được attack thật mà không báo bừa trên benign: **specificity 100%
(0 FP/4.38M rows), recall có (Joomla RCE thật, judge phân biệt đúng recon vs
compromise)**. Việc tiếp theo: thêm sourcetype để đo các phase còn lại, Splunk live
adapter, dataset dài ngày. Chi tiết kỹ thuật ở 3 tài liệu nguồn kể trên.
