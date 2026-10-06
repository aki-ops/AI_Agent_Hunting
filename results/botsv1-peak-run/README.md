# Kết quả chạy 4 PoC có sẵn qua PEAK Assistant (BOTS v1)

Lệnh: `python main.py --poc-dir pocs --db data/botsv1_eval.sqlite` (cdb 4,417,543 dòng, PEAK Assistant + LLM thật).
Model: `LLM_MODEL=auto` (OpenRouter Auto Router tự chọn model cho từng request, nên nội dung LLM kém tái lập hơn model cố định; model Meta Muse đã bị bỏ vì hay trả 404).
Mỗi thư mục con có `recommendation.md/json` (khuyến nghị cho người quyết định), `peak_able.md` (bảng ABLE
do PEAK `able_table` viết) và `peak_hunt_plan.md` (kế hoạch do PEAK planner + critic viết).

| PoC | Cửa sổ | Execute | Khuyến nghị | Tin cậy |
|---|---|---|---|---|
| `poc-joomla-rce` | 2016-08-10 21:36–22:00 | MATCHED, 200 bản ghi hiển thị (≥1999 và ≥2000 khớp, quét chạm giới hạn), 2/2 bước | `ESCALATE_TO_IR` | MEDIUM |
| `poc-bruteforce-we1149srv` | 2016-08-21 | EMPTY | `CLOSE_WITH_CAVEAT` | MEDIUM |
| `poc-c2-beacon-networkfilter` | 2016-08-21 | EMPTY | `CLOSE_WITH_CAVEAT` | MEDIUM |
| `poc-pdf-exploit-enc` | 2016-08-21 | EMPTY | `CLOSE_WITH_CAVEAT` | MEDIUM |

## Đọc kết quả thế nào

- **Joomla**: dữ liệu cho thấy một nguồn (40.80.148.42) quét Joomla bằng Acunetix. Khuyến nghị escalate nhưng tin cậy
  chỉ MEDIUM vì PoC không có bước nào kiểm tra kết quả (status/response): dữ liệu chứng minh có *quét/thăm dò*,
  chưa chứng minh *khai thác thành công*. Báo cáo nêu rõ các câu hỏi cần trả lời trước khi chuyển IR (host
  `splunk-02` là sensor hay endpoint, có log phía server không).
- **Ba PoC còn lại rỗng** và đáng đọc kỹ. `able.location` của cả ba chứa `we1149srv`, nên mọi bước bị lọc ngầm theo `host = we1149srv`;
  host này **không ghi** nguồn tương ứng (authentication 20.657 dòng trong cửa sổ nhưng 0 dòng của host này; web 566 dòng đều của `splunk-02`;
  process 129.775 dòng nhưng 0 của host này). Báo cáo hiển thị phạm vi đó và hệ thống đã chạy lại từng PoC **không lọc host**
  (`unscoped_probe/` trong lần chạy gốc): vẫn 0 bản ghi ở mọi host. Vì vậy `CLOSE_WITH_CAVEAT` (MEDIUM) ở đây nghĩa là "dữ liệu hiện có không chứa
  dấu hiệu này ở đâu cả", chứ không phải "sạch": theo `docs/EVAL-GROUND-TRUTH.md` bộ dữ liệu chưa có 4625, PowerShell mã hoá thật hay beacon
  `networkfilter`, và báo cáo liệt kê loại sự kiện thực có của từng nguồn (vd. chỉ `authentication/4624`).

## Lưu ý trung thực

- Judge/advisor/PEAK là LLM, kết quả mỗi lần chạy có thể khác; phần tất định (số bản ghi, disposition khi cùng judge) tái lập được.
- Endpoint LLM thỉnh thoảng trả 404 `model_not_found`; mỗi bước (ABLE, kế hoạch, judge, advisor) tự gọi lại với backoff 3s/10s/25s. Lần chạy này không có lần gọi lại nào (endpoint ổn định), nên cơ chế đó chỉ được kiểm bằng unit test. Advisor thử lại tối đa 3 lần nếu model trả JSON lỗi.
- Bản nháp SPL trong báo cáo chưa được kiểm tra trên Splunk thật.
- Số token của các agent bên trong PEAK chưa được đo.
