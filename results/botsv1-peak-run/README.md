# Kết quả chạy 4 PoC có sẵn qua PEAK Assistant (BOTS v1)

Lệnh: `python main.py --poc-dir pocs --db data/botsv1_eval.sqlite` (cdb 4,417,543 dòng, PEAK Assistant + LLM thật).
Mỗi thư mục con có `recommendation.md/json` (khuyến nghị cho người quyết định), `peak_able.md` (bảng ABLE
do PEAK `able_table` viết) và `peak_hunt_plan.md` (kế hoạch do PEAK planner + critic viết).

| PoC | Cửa sổ | Execute | Khuyến nghị | Tin cậy |
|---|---|---|---|---|
| `poc-joomla-rce` | 2016-08-10 21:36–22:00 | MATCHED, 199 bản ghi, 2/2 bước | `ESCALATE_TO_IR` | MEDIUM |
| `poc-bruteforce-we1149srv` | 2016-08-21 | EMPTY | `CLOSE_WITH_CAVEAT` | MEDIUM |
| `poc-c2-beacon-networkfilter` | 2016-08-21 | EMPTY | `CLOSE_WITH_CAVEAT` | MEDIUM |
| `poc-pdf-exploit-enc` | 2016-08-21 | EMPTY | `CLOSE_WITH_CAVEAT` | MEDIUM |

## Đọc kết quả thế nào

- **Joomla**: dữ liệu cho thấy một nguồn (40.80.148.42) quét Joomla bằng Acunetix. Khuyến nghị escalate nhưng tin cậy
  chỉ MEDIUM vì PoC không có bước nào kiểm tra kết quả (status/response): dữ liệu chứng minh có *quét/thăm dò*,
  chưa chứng minh *khai thác thành công*. Báo cáo nêu rõ các câu hỏi cần trả lời trước khi chuyển IR (host
  `splunk-02` là sensor hay endpoint, có log phía server không).
- **Ba PoC còn lại rỗng**, nguồn telemetry có dữ liệu trong cửa sổ nên không phải `COLLECT_DATA`. Nhưng "có
  nguồn" chưa chắc "có đúng loại sự kiện": theo `docs/EVAL-GROUND-TRUTH.md` bộ dữ liệu hiện chưa có 4625 (đăng nhập
  thất bại), PowerShell mã hoá thật hay beacon `networkfilter`. Đừng đọc `CLOSE_WITH_CAVEAT` là "sạch"; các caveat và
  gợi ý của PEAK (mở rộng cửa sổ, thêm sourcetype) nằm trong từng báo cáo.

## Lưu ý trung thực

- Judge/advisor/PEAK là LLM, kết quả mỗi lần chạy có thể khác; phần tất định (số bản ghi, disposition khi cùng judge) tái lập được.
- Endpoint LLM thỉnh thoảng trả 404 `model_not_found`; mỗi bước (ABLE, kế hoạch, judge, advisor) tự gọi lại với backoff 3s/10s/25s. Lần chạy này endpoint ổn định nên cơ chế gọi lại chưa phải dùng tới (chỉ có unit test).
- Bản nháp SPL trong báo cáo chưa được kiểm tra trên Splunk thật.
- Số token của các agent bên trong PEAK chưa được đo.
