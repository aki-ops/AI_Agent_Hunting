# Đánh giá ground-truth trên dữ liệu BOTS v1 thật (2026-09-21)

> Specificity: 4 PoC built-in × 4.38M benign rows → 0 FP (Mục 2).
> Recall: PoC Joomla trên 19.7k attack rows thật → MATCHED; judge INCONCLUSIVE đúng đắn (Mục 4).

## 1. Dataset

| Nguồn | Nội dung | Rows |
|---|---|---|
| `botsv1.WinEventLog:Security.csv.gz` (888MB, 14.2M rows full) lọc giữ auth/process/SMB | 4624 logon, 4688 process, 5140/5145 SMB, 4648 explicit logon | 4,342,563 |
| Attack-only journals: sysmon Event 1 (process create) | 66 rows process thật (WmiPrvSE, wermgr, rundll32...) | 66 |
| Attack-only journals: stream:dns | query thật (PTR, NBNS, wpad, crl.microsoft.com...) | 35,904 |
| `botsv1.stream-http.csv.gz` (20MB) ingest nguyên file | web attack thật: Joomla RCE trên `imreallynotbatman.com` (19.7k rows), benign: windowsupdate/msn/google | 39,010 |
| **Tổng eval DB** (`data/botsv1_eval.sqlite`, gitignored) | | **4,417,543** |

Timeline: 2016-08-10 → 2016-08-28 (19 ngày, đúng window BOTS v1).

## 2. Kết quả sau fix (4 PoC × 4.38M rows, ~26s)

| PoC | Verdict | Obs | FP rate | Nhận xét |
|---|---|---|---|---|
| `poc-phishing-powershell-enc` | EMPTY | 0 | 0.000000 | 1M+ `splunk-powershell.exe` rows không lọt sau fix EQUALS |
| `poc-c2-beacon` | EMPTY | 0 | 0.000000 | step EXISTS rỗng đã chặn; DNS/HTTP steps 0 hit |
| `poc-office-macro` | EMPTY | 0 | 0.000000 | 3.6M process rows, không báo bừa |
| `poc-credential-phish` | EMPTY | 0 | 0.000000 | 0 hit |

**Specificity = 100% trên 4.38M benign rows** (với định nghĩa benign = toàn bộ eval DB,
trong đó 1 row `powershell.exe` thật là admin `Get-AppxPackage` — đúng là không match).

## 3. Bugs tìm được nhờ eval (đã fix, commit này)

1. **`EQUALS qua LIKE` (nghiêm trọng):** `image EQUALS powershell.exe` match cả
   `splunk-powershell.exe` → 100 FP / 4.38M rows. Fix: post-filter exact match
   (+ basename fallback `C:\...\powershell.exe`), áp dụng mọi op
   (EQUALS/CONTAINS/STARTS_WITH/ENDS_WITH/MATCHES/EXISTS) trong `agent._run_step`.
2. **Step `EXISTS` rỗng (trung bình):** `image EXISTS value=""` match row đầu tiên có
   image bất kỳ (gặp `TrueImageMonitor.exe`). Fix: EXISTS rỗng → 0 rows; đồng thời
   xóa step `s3-outbound-process` khỏi `poc-c2-beacon` (không có nghĩa phát hiện).
3. Test hồi quy: `test_exact_equals_rejects_splunk_prefix`,
   `test_exists_empty_value_matches_nothing`, `test_operator_helpers_exact_equals`;
   sửa 1 test cũ dùng sai field (`action EQUALS Logon Failed` → `cmdline CONTAINS`).

Trước fix: FP rate 0.000023 (100 rows) + 1 row lạc. Sau fix: 0.

## 4. Recall trên attack thật: Joomla RCE (stream:http)

Attack thật tìm được trong `stream:http` (39k rows): `imreallynotbatman.com`
22k hits, `/joomla/index.php/component/search/` 16.6k hits — đúng BOTS v1
web-compromise phase (quét + khai thác Joomla). PoC mới `pocs/poc-joomla-rce.json`
(site EQUALS + uri CONTAINS `/joomla/`):

```
PoC poc-joomla-rce — verdict MATCHED — 199 obs, 2 matched step(s),
1 LLM call(s) [match=0, judge=1] | JUDGE: INCONCLUSIVE (0.82)
```

- **Rules: bắt được attack (recall bước match = có).** 19.7k Joomla rows → 199 obs
  (limit 100/step). Benign cùng file (windowsupdate/msn) không match.
- **Judge INCONCLUSIVE 0.82 là đúng đắn, không phải thất bại:** rows cho thấy
  recon (Acunetix probe, URI discovery) nhưng thiếu exploit payload, HTTP status,
  command execution để kết RCE. Giá trị của judge ở đây là *phân biệt
  recon vs compromise* — việc rules không làm được.
- Đây là TP đầu tiên trên attack thật (không phải sample tự dựng).

## 5. Giới hạn trung thực (nói trước với sếp)

- Substring scan báo sai đã đính chính: `4625` 3.6k hits thực ra là `EventCode=4656`
  (RecordNumber chứa "4625"); `IEX` 15 hits thực ra là `iexplore.exe`.
  **0× failed-logon 4625 thật, 0× encoded-PS thật, 0× `networkfilter` beacon**
  trong dữ liệu hiện có — các phase đó nằm ở sourcetype chưa tải (Sysmon full).
- Recall mới đo được 1 phase (Joomla web). Các phase khác cần thêm sourcetype.
- Judge LLM non-deterministic (cùng evidence từng ra 0.97/0.92/0.88) — chỉ dùng
  làm advisory phân biệt recon vs compromise, không làm verdict chính.

## 6. Tái chạy

```bash
.venv/Scripts/python.exe scripts/ingest_botsv1_eval.py  # ~6 phút, cần data/raw/*.gz
.venv/Scripts/python.exe scripts/run_fp_eval.py         # ~30s
.venv/Scripts/python.exe scripts/ingest_http.py         # ingest stream:http + tạo PoC Joomla
.venv/Scripts/python.exe main.py --provider cdb --db data/botsv1_eval.sqlite \
  --poc-file pocs/poc-joomla-rce.json --time-window "2016-08-10T00:00:00Z/2016-08-11T00:00:00Z" \
  --poc-judge --llm api
```
