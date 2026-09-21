# Đánh giá ground-truth trên dữ liệu BOTS v1 thật (2026-09-21)

> Đo specificity (false-positive rate) của 4 PoC built-in trên enterprise noise thật.
> Recall chưa đo được — dataset không chứa attack labels verify được (xem Mục 4).

## 1. Dataset

| Nguồn | Nội dung | Rows |
|---|---|---|
| `botsv1.WinEventLog:Security.csv.gz` (888MB, 14.2M rows full) lọc giữ auth/process/SMB | 4624 logon, 4688 process, 5140/5145 SMB, 4648 explicit logon | 4,342,563 |
| Attack-only journals: sysmon Event 1 (process create) | 66 rows process thật (WmiPrvSE, wermgr, rundll32...) | 66 |
| Attack-only journals: stream:dns | query thật (PTR, NBNS, wpad, crl.microsoft.com...) | 35,904 |
| **Tổng eval DB** (`data/botsv1_eval.sqlite`, gitignored) | | **4,378,533** |

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

## 4. Giới hạn trung thực (nói trước với sếp)

- **Recall chưa đo được:** eval DB có 0× failed-logon 4625, 0× encoded-PS thật,
  0× `networkfilter` beacon — toàn bộ attack labels của BOTS nằm ở sourcetype khác
  (stream:http, Sysmon đầy đủ) không tải được trên mạng hiện tại.
- Vì vậy đây là **đo specificity, không phải accuracy hoàn chỉnh**.
  Muốn recall cần dataset có attack thật (BOTS v2, ATT&CK eval, hoặc replay attack
  trong lab rồi ingest).
- Judge LLM không tham gia eval này (deterministic match only) — đúng, vì judge
  non-deterministic không đo FP rate được.

## 5. Tái chạy

```bash
.venv/Scripts/python.exe scripts/ingest_botsv1_eval.py  # ~6 phút, cần data/raw/*.gz
.venv/Scripts/python.exe scripts/run_fp_eval.py         # ~30s
```
