# Chương 7 — Kết quả và phân tích tỉ lệ

> Mọi con số trong chương này truy được về một tệp nguồn trong kho hoặc một lần chạy đã ghi lại trong phiên báo cáo. Phần chưa đo được nói rõ là chưa đo. Bốn đại lượng D1–D4 tương ứng bốn lớp thực nghiệm ở Chương 6.

## 7.1. D1 — Tính đúng đắn phần mềm: 514 passed, 13 skipped, 0 failed

Chạy `pytest tests/unit -q` hai lần trong phiên báo cáo (mỗi lần ~65 giây):

```
514 passed, 13 skipped, 21 warnings in 65.xx s
```

- **0 test thất bại.**
- **13 test bỏ qua** là các test cần Splunk sống hoặc mạng ngoài (ví dụ live Splunk adapter, phase D live) — không phải thất bại.
- `compileall -q src main.py` và `ruff check` trên mã nguồn lõi (`src/hunting/peak.py`, `src/hunting/cli.py`): sạch, 0 lỗi.

Kết quả này được đo **sau** khi tích hợp cổng PEAK Prepare mới (Chương 5), xác nhận cổng không gây hồi quy.

**So với mốc lịch sử:** checklist ghi 356 passed / 3 failed / 1 skipped vào 2026-09-09. Con số 514 hiện tại thay cho mốc đó; ba thất bại cũ (test từ khóa và đồ thị email đời v5) không còn.

## 7.2. D2 — Độ đặc hiệu: 0 dương tính giả trên 4.38 triệu dòng

Nguồn: `data/eval_fp_results.json`. Cửa sổ `2016-08-10 → 2016-08-28`, tổng 4,378,533 dòng, tổng thời gian 26.6 giây.

| PoC | Verdict | Quan sát | FP rate | Thời gian (s) |
|---|---|---|---|---|
| `poc-phishing-powershell-enc` | EMPTY | 0 | 0.000000 | 10.77 |
| `poc-c2-beacon` | EMPTY | 0 | 0.000000 | 4.73 |
| `poc-office-macro` | EMPTY | 0 | 0.000000 | 4.71 |
| `poc-credential-phish` | EMPTY | 0 | 0.000000 | 5.76 |

**Độ đặc hiệu = 100% trên 4.38 triệu dòng lành tính (0 dương tính giả).**

### 7.2.1. Hai lỗi được khui ra và sửa

Đánh giá này khui ra hai lỗi (nay đã sửa), minh họa giá trị của việc đo trên quy mô lớn:

1. **`EQUALS` qua `LIKE` (nghiêm trọng):** `image EQUALS powershell.exe` match cả `splunk-powershell.exe` → 100 dương tính giả trên 4.38 triệu dòng. Sửa: post-filter khớp chính xác + fallback theo basename (`C:\...\powershell.exe` vẫn khớp, `splunk-powershell.exe` không khớp), áp cho mọi toán tử trong `agent._run_step`.
2. **Step `EXISTS` với value rỗng (trung bình):** `image EXISTS value=""` match dòng đầu tiên có trường bất kỳ. Sửa: EXISTS rỗng → 0 dòng; đồng thời xóa một step vô nghĩa khỏi `poc-c2-beacon`.

Trước khi sửa: FP rate 0.000023 (100 dòng). **Sau khi sửa: 0.** Ba test hồi quy được thêm để khóa hành vi này.

## 7.3. D3 — Độ nhạy trên tấn công thật: Joomla RCE MATCHED

Tấn công thật trong `stream:http` (39k dòng, Joomla ~19.7k): `imreallynotbatman.com` ~22k hit, `/joomla/index.php/component/search/` ~16.6k hit — đúng chặng web-compromise của BOTS v1 (quét + khai thác Joomla).

PoC `poc-joomla-rce.json` (domain EQUALS `imreallynotbatman.com` + uri CONTAINS `/joomla/`), chạy trong phiên báo cáo:

```
PoC poc-joomla-rce — verdict MATCHED — 199 obs, 2 matched step(s),
1 LLM call(s) [match=0, judge=1], 5163 tokens | JUDGE: TRUE_POSITIVE (0.85)
```

- **Rules bắt được attack thật (recall bước match = có):** 19.7k dòng Joomla → 199 quan sát (giới hạn 100/bước). Benign cùng tệp (windowsupdate/msn) không match.
- **Judge phân biệt đúng recon vs compromise:** nhận ra Acunetix scanner probe (`/acunetix-wvs-test-for-some-inexistent-file`), các path fuzz ngẫu nhiên (`/PdgdyH6M`, `/OD6xDhbF`), và Joomla enumeration → kết luận đây là giai đoạn quét chủ động, không phải duyệt web bình thường.
- **Đây là dương tính thật đầu tiên trên tấn công thật** (không phải sample tự dựng).

### 7.3.1. Tính non-deterministic của judge

Cùng một bằng chứng Joomla cho các nhãn/độ tự tin khác nhau qua các lần chạy:

| Nguồn lần chạy | Judge verdict | Độ tự tin |
|---|---|---|
| `EVAL-GROUND-TRUTH.md` (bản ghi cũ) | INCONCLUSIVE | 0.82 |
| Phiên báo cáo (lần 1) | TRUE_POSITIVE | 0.87 |
| Phiên báo cáo (lần 2) | TRUE_POSITIVE | 0.85 |

Đây chính là lý do **verdict chính luôn là rules tất định**, còn judge chỉ advisory (dùng để phân biệt recon vs compromise — việc rules không làm được).

## 7.4. Judge trên các case âm tính: NO_SIGNAL đúng

Ba PoC âm tính chạy trên cùng eval DB trong phiên báo cáo:

| PoC | Verdict (rules) | Quan sát | LLM calls | Judge |
|---|---|---|---|---|
| `poc-pdf-exploit-enc` | EMPTY | 0 | 0 | NO_SIGNAL |
| `poc-bruteforce-we1149srv` | EMPTY | 0 | 0 | NO_SIGNAL |
| `poc-c2-beacon-networkfilter` | EMPTY | 0 | 0 | NO_SIGNAL |

Judge giữ im lặng đúng ("absence of evidence, not evidence of absence"), **không bịa dương tính**, và **không tốn token** — khi không có hàng, judge từ chối gọi LLM. Đây là bằng chứng trực tiếp rằng hệ thống chặn lỗi L3 ở tầng hành vi thực tế, không chỉ ở đơn vị.

## 7.5. D4 — Hành vi cổng PEAK Prepare

| Kịch bản | Kết quả đo |
|---|---|
| Hunt bình thường (plan suy tự động) | In `PEAK Prepare ready ... (source=derived from hunt inputs)`, hunt chạy tiếp |
| `--hunt-plan` thiếu trường | Exit 2, báo `missing: able.behavior, able.location, ... research_refs` |
| `--skip-prepare` | Exit 0, in `PEAK Prepare gate skipped`, hunt chạy |

Xem Chương 5 để có chi tiết đầy đủ.

## 7.6. Demo end-to-end trên sample 16 sự kiện

Chuỗi ba bước trên `data/cdb_sample.sqlite`:

| Bước | Lệnh | Kết quả đo |
|---|---|---|
| Baseline (EDA, không LLM) | `--baseline cdb:events` | 16 dòng → 11 trường, 23 outlier, 4 gap (~0.0002s) |
| M-ATH (`--math`) | `--math cdb:events` | 25 lead; encoded PowerShell (score 6.50) xếp trên brute-force rời rạc (5.81) |
| PoC + Judge | `--poc-file poc-pdf-exploit-enc.json --poc-judge --llm api` | MATCHED 9 obs, 3 bước; judge INCONCLUSIVE 0.88 (bóc được SCCM `foobar` là noise; 2 cmdline alice thiếu parent/network nên không kết TP) |

Baseline phát hiện outlier hợp lý (`smtp`, `schtasks.exe`, `svc_admin`, `SCCM-SERVER`) và gap đúng (`domain`, `file_path`, `action`, `status` trống trong window). M-ATH xếp đúng thứ tự ưu tiên (encoded PowerShell lên trước). Judge INCONCLUSIVE 0.88 là đúng chuẩn khi thiếu bằng chứng parent/network.

## 7.7. Bảng tổng hợp tỉ lệ

| Đại lượng | Giá trị đo | Nguồn |
|---|---|---|
| D1 — Test phần mềm đạt | 514/527 (13 skip), 0 fail | phiên báo cáo |
| D2 — Độ đặc hiệu (FP trên benign) | 100% (0 FP / 4,378,533 dòng) | `eval_fp_results.json` |
| D3 — Recall bước match (Joomla thật) | có (199 obs, 2/2 bước) | `EVAL-GROUND-TRUTH.md` + phiên báo cáo |
| Judge trên 4 case (phiên báo cáo) | 1 TP đúng, 3 NO_SIGNAL đúng | phiên báo cáo |
| D4 — Cổng Prepare | 3/3 kịch bản đúng | phiên báo cáo |
| F1 tổng quát (claim/cạnh/câu trả lời) | **chưa đo** — thiếu nhãn đầy đủ | `04-IMPLEMENTATION-CHECKLIST.md` |

Diễn giải và hạn chế của các con số này nằm ở Chương 8.
