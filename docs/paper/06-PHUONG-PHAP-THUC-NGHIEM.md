# Chương 6 — Phương pháp thực nghiệm

> Chương này mô tả môi trường thực nghiệm, bộ dữ liệu Boss of the SOC v1 (BOTS v1), thiết kế bốn lớp kiểm thử, và tiêu chí đo. Kết quả cụ thể nằm ở Chương 7.

## 6.1. Mục tiêu thực nghiệm

Thực nghiệm nhằm trả lời câu hỏi nghiên cứu CH3 (Chương 1): trên dữ liệu tấn công thật, hệ thống có đạt độ đặc hiệu cao (ít dương tính giả) mà vẫn bắt được tấn công thật (có độ nhạy) hay không, và đo được đến đâu. Đồng thời, thực nghiệm kiểm chứng rằng các ràng buộc kiến trúc (Chương 4) và cổng Prepare mới (Chương 5) không làm hồi quy hành vi phần mềm.

Bốn đại lượng đo:

- **D1 — Tính đúng đắn phần mềm:** bộ kiểm thử tự động đạt/thất bại.
- **D2 — Độ đặc hiệu (specificity):** tỉ lệ dương tính giả khi chạy PoC trên telemetry lành tính quy mô lớn.
- **D3 — Độ nhạy (recall) trên tấn công thật:** hệ thống có bắt được một tấn công đã biết hay không.
- **D4 — Hành vi cổng Prepare:** ba kịch bản (suy tự động / plan thiếu / van thoát).

## 6.2. Môi trường thực nghiệm

| Thành phần | Cấu hình |
|---|---|
| Hệ điều hành | Windows (win32), PowerShell |
| Python | 3.12 (yêu cầu tối thiểu 3.10) |
| Thư viện runtime | Pydantic 2, PyYAML, requests |
| Công cụ phát triển | pytest, pytest-cov, ruff |
| Mô hình ngôn ngữ | `meta/muse-spark-1.3-contributor` qua OpenRouter (cấu hình trong `.env`) |
| Backend telemetry | SQLite (CDB) và Splunk REST (khi có) |

Cài đặt và kiểm nhanh (theo `README.md`):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m pytest tests/unit -q
python -m compileall -q src main.py
ruff check .
```

## 6.3. Vì sao chọn BOTS v1

**Boss of the SOC v1 (BOTS v1)** là bộ dữ liệu telemetry công khai của Splunk, mô phỏng một chuỗi tấn công thật trên trang `imreallynotbatman.com`: quét và khai thác Joomla (T1190), brute-force, lateral movement, và C2. Lý do chọn:

1. **Có ground-truth công khai** qua walkthrough của Splunk, nên xác minh được kết quả.
2. **Vừa có tấn công vừa có nhiễu lành tính**, cho phép đo cả độ nhạy (trên tấn công) lẫn độ đặc hiệu (trên nhiễu) trên cùng một bộ.
3. **Là chuẩn thực địa** được cộng đồng săn mối đe dọa dùng rộng rãi.

## 6.4. Hai backend thực thi

| Backend | Tệp / kết nối | Vai trò trong thực nghiệm |
|---|---|---|
| CDB (SQLite) | `data/cdb_sample.sqlite`, `data/botsv1_eval.sqlite` | Backend chính cho đánh giá tự động — phát lại được, chạy không cần Splunk |
| Splunk sống | `SplunkLiveAdapter` qua REST cổng 8089 | Môi trường SIEM thật, khi có |

**Ranh giới trung thực:** một kết quả trên CDB chứng minh hợp đồng và logic bằng chứng, **không** chứng minh hành vi của một SIEM sản xuất. Đây là lý do các test cần Splunk sống bị bỏ qua (skip) khi không có instance.

## 6.5. Hai bộ dữ liệu

### 6.5.1. Bộ sample — 16 sự kiện

`data/cdb_sample.sqlite`, gieo bằng `scripts/seed_botsv1_sample.py`, phủ các chặng chính của BOTS v1 để demo end-to-end nhanh:

| Thời điểm (2016-08-21) | Sự kiện | MITRE |
|---|---|---|
| 03:00–03:06 | 7 logon thất bại vào `we1149srv` (brute-force) | T1110 |
| 03:08 | alice logon thành công (pivot) | T1078 |
| 06:02 | email phishing SMTP | T1566.001 |
| 08:14 | beacon tới `ad.networkfilter.co` | T1071.001 |
| 08:14 | powershell -enc con của PDF exploit | T1059.001 + T1027 |
| 11:33 | lateral SMB tới JGREEN-PC | T1021.002 |
| 11:42 | scheduled task + Run-key persistence | T1053.005 / T1547.001 |
| 02:15 | script SCCM admin lành tính (ứng viên FP) | — |

### 6.5.2. Bộ eval — 4.42 triệu dòng

`data/botsv1_eval.sqlite` (gitignored, ~6 phút để nạp), tạo bằng `scripts/ingest_botsv1_eval.py` và `scripts/ingest_http.py`:

| Nguồn | Nội dung | Số dòng |
|---|---|---|
| `WinEventLog:Security.csv.gz` (lọc giữ auth/process/SMB) | 4624 logon, 4688 process, 5140/5145 SMB, 4648 explicit logon | 4,342,563 |
| Sysmon Event 1 (process create) | tiến trình thật (WmiPrvSE, wermgr, rundll32...) | 66 |
| `stream:dns` | query thật (PTR, NBNS, wpad, crl.microsoft.com...) | 35,904 |
| `stream:http` | web attack thật: Joomla RCE trên `imreallynotbatman.com` (~19.7k) + benign (windowsupdate/msn/google) | 39,010 |
| **Tổng eval DB** | | **4,417,543** |

Timeline: 2016-08-10 → 2016-08-28 (19 ngày, đúng window BOTS v1). Cửa sổ dùng cho đánh giá độ đặc hiệu là `2016-08-10 → 2016-08-28`, tổng 4,378,533 dòng nằm trong cửa sổ đó.

## 6.6. Thiết kế bốn lớp kiểm thử

Hệ thống có bốn lớp kiểm thử, tương ứng bốn mức tin cậy khác nhau.

### 6.6.1. Lớp 1 — Unit test hợp đồng (74 tệp → D1)

Khóa từng hợp đồng và từng pha. Nhóm tiêu biểu:

| Tệp | Khóa điều gì |
|---|---|
| `test_phase0_contracts.py`, `test_contracts.py` | Hợp đồng nền |
| `test_phase1_compiler.py`, `test_v6_semantic_claim_compiler.py` | Biên dịch và từ chối SPL (chặn L1) |
| `test_provider_census.py`, `test_capability_retriever.py` | Census và batch không Top-K (chặn L2) |
| `test_semantic_goal_planner.py`, `test_semantic_executor.py`, `test_semantic_readiness.py` | Plan, thực thi, sẵn sàng chứng minh |
| `test_v5_relation_verifier.py`, `test_deterministic_transition_verifier.py` | Cạnh và chuyển trạng thái |
| `test_counterfactual_matrix.py`, `test_route_negative_license_and_provenance.py` | Cùng từ khóa cho đồ thị khác nhau; âm tính không cấp phép bừa (chặn L3) |
| `test_security_regression.py`, `test_llm_timeout_fail_fast.py` | Injection và hết giờ |

Lệnh: `python -m pytest tests/unit -q`.

### 6.6.2. Lớp 2 — Integration (1 tệp)

`tests/integration/test_botsv1_web_compromise.py` chạy lát cắt dọc BOTS v1 end-to-end.

### 6.6.3. Lớp 3 — Đánh giá độ đặc hiệu (→ D2)

Chạy bốn PoC dựng sẵn trên toàn eval DB, đo dương tính giả:

```powershell
.venv\Scripts\python.exe scripts/run_fp_eval.py   # ~30s, ghi data/eval_fp_results.json
```

Định nghĩa đo: telemetry lành tính = toàn bộ eval DB (trong đó gần như không có các chặng mà PoC dựng sẵn nhắm tới); dương tính giả = một PoC dựng sẵn báo MATCHED trên dữ liệu này. FP rate = số dòng match / tổng dòng.

### 6.6.4. Lớp 4 — Đánh giá độ nhạy trên tấn công thật + PoC end-to-end (→ D3)

Chạy PoC Joomla RCE trên `stream:http` thật, kèm LLM judge:

```powershell
.venv\Scripts\python.exe main.py --provider cdb --db data/botsv1_eval.sqlite `
  --poc-file pocs/poc-joomla-rce.json `
  --time-window "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z" `
  --poc-judge --llm api --poc-judge-max-tokens 16000
```

Để kiểm rằng judge không bịa dương tính khi không có tấn công, chạy thêm ba PoC âm tính (`poc-pdf-exploit-enc`, `poc-bruteforce-we1149srv`, `poc-c2-beacon-networkfilter`) trên cùng eval DB.

## 6.7. Tiêu chí đo và tính lặp lại

- **D1** đạt khi 0 test thất bại (skip do thiếu Splunk/mạng không tính là thất bại).
- **D2** đo bằng FP rate; mục tiêu 0.
- **D3** đo bằng verdict rules (MATCHED/EMPTY) là chính, judge chỉ advisory. Judge LLM non-deterministic nên verdict chính luôn là rules.
- **D4** đo bằng ba kịch bản cổng Prepare (Chương 5).

Mọi lần chạy PoC sinh một ledger JSON và một report Markdown tái chạy được; các lệnh tái chạy đầy đủ nằm trong `docs/EVAL-GROUND-TRUTH.md` và `docs/BOTS-V1-WALKTHROUGH.md`.
