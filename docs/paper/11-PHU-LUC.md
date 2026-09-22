# Chương 11 — Phụ lục

## Phụ lục A. Ánh xạ thuật ngữ

| Tiếng trong mã | Nghĩa dùng trong báo cáo |
|---|---|
| Hunt | Một lần săn có yêu cầu, sổ cái và tài khoản cuối |
| Claim | Mệnh đề cần chứng minh, thuộc đồ thị tương thích |
| Goal | Quan hệ hoặc câu trả lời trong `SemanticGoalGraph` |
| Capability | Thao tác nhà cung cấp đã khai báo hoặc đã probe |
| Observation | Một hàng telemetry đã nhập sổ cái |
| Evidence card | Nhóm quan sát đã nén để đánh giá và báo cáo |
| Cell (ô phủ) | `(ProviderScope, thực thể hoặc ANY, bucket thời gian)` |
| Probe | Truy vấn nhỏ kiểm một ánh xạ nguồn, không kiểm sự cố |
| Binding | Giá trị một biến nhận được, kèm nguồn gốc |
| Candidate | Giá trị/năng lực được phép dùng để truy hồi, chưa dùng để kết luận |
| Complete | Lần truy vấn tới điểm hoàn tất mà nhà cung cấp khai báo |
| Route exhausted | Mọi cách có giới hạn của một quan hệ đã thử hoặc bị từ chối có lý do |
| Testimony | Lời người, không phải telemetry |
| Disposition | Nhãn cuối của vòng cảnh báo |
| Stopping decision | Lý do máy dừng |
| Act | Bản nháp phát hiện, backlog và tóm tắt sau lần săn |

## Phụ lục B. Các quyết định dừng (StoppingDecision)

| Giá trị | Khi nào mã đặt |
|---|---|
| `STOP_RESOLVED` | Tuyến ngữ nghĩa đã chứng minh đủ để trả lời |
| `STOP_REFUTED` | Bằng chứng bác giả thuyết theo luật đã khai báo |
| `STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED` | Chưa nối được định danh cần để trả lời |
| `STOP_INCONCLUSIVE_RELATION_UNPROVEN` | Còn quan hệ chưa chứng minh |
| `STOP_INCONCLUSIVE_COVERAGE_GAP` | Truy vấn dở dang hoặc nguồn không phủ |
| `STOP_NEEDS_USER_DECISION` | Nhiều ràng buộc, cần người thu hẹp |
| `STOP_EXHAUSTED_BY_BUDGET` | Hết lượt, truy vấn, token hoặc thời gian |
| `STOP_UNSUPPORTED_CAPABILITY` | Có nhà cung cấp sống nhưng không năng lực cho claim |
| `STOP_UNREACHABLE` | Không nhà cung cấp nào trực tuyến |
| `STOP_INSUFFICIENT` | Giả thuyết hoặc mô hình không đủ đặc tả |

## Phụ lục C. Tài liệu nội bộ liên quan

| Văn bản | Vai trò |
|---|---|
| `01_FINAL-ARCHITECTURE.md` | Kiến trúc chuẩn v7 |
| `02_METHOD-AND-IMPLEMENTATION-PLAN.md` | Phương pháp và kế hoạch mã |
| `03_LITERATURE-AND-TRACEABILITY.md` | Nguồn ngoài và biên giới tuyên bố |
| `04-IMPLEMENTATION-CHECKLIST.md` | Cổng bằng chứng |
| `docs/PEAK-PREPARE-GATE.md` | Cổng PEAK Prepare bắt buộc (đóng góp mới) |
| `docs/PEAK-RESEARCH-AND-MAPPING.md` | Nghiên cứu PEAK và đối chiếu trung thực |
| `docs/EVAL-GROUND-TRUTH.md` | Đánh giá trên BOTS v1 thật |
| `docs/BOTS-V1-WALKTHROUGH.md` | Hướng dẫn chạy trên BOTS v1 |
| `docs/BAO-CAO-LLM-JUDGE.md` | Báo cáo LLM judge |
| `docs/PEAK-END-TO-END-DEMO.md` | Demo baseline → math → PoC trên sample 16 sự kiện |

## Phụ lục D. Danh mục đầy đủ lớp và hàm

Danh mục đầy đủ **260 lớp và 658 hàm/phương thức** của `src/hunting`, kèm khoảng dòng và câu đầu docstring lấy trực tiếp từ mã, nằm ở **Phụ lục A của bản một-tệp** `docs/PAPER-BAO-CAO-HE-THONG.md`. Bản nhiều chương này không lặp lại danh mục đó để giữ mỗi chương tập trung vào một nội dung; hai bản trỏ tới cùng một mã nguồn.

## Phụ lục E. Lệnh tái chạy đánh giá

```powershell
# 1. Nạp eval DB (cần data/raw/*.gz, ~6 phút)
.venv\Scripts\python.exe scripts/ingest_botsv1_eval.py
.venv\Scripts\python.exe scripts/ingest_http.py

# 2. Độ đặc hiệu: 4 PoC trên 4.38M dòng (~30s)
.venv\Scripts\python.exe scripts/run_fp_eval.py

# 3. Độ nhạy: Joomla RCE + judge
.venv\Scripts\python.exe main.py --provider cdb --db data/botsv1_eval.sqlite `
  --poc-file pocs/poc-joomla-rce.json `
  --time-window "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z" `
  --poc-judge --llm api --poc-judge-max-tokens 16000

# 4. Bộ kiểm thử phần mềm
.venv\Scripts\python.exe -m pytest tests/unit -q
```
