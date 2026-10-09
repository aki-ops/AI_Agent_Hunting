# Kết quả chạy 4 PoC có sẵn qua PEAK Assistant (BOTS v1)

Lệnh: `python main.py --poc-dir pocs --db data/botsv1_eval.sqlite` (cdb 4,417,543 dòng, PEAK Assistant + LLM thật).
Model: `nvidia/nemotron-3-super-120b-a12b:free` (OpenRouter, giá 0; model dự phòng `nvidia/nemotron-3-ultra-550b-a55b:free`, `poolside/laguna-s-2.1:free`, không phải dùng). Số dư tài khoản không đổi sau lần chạy. Model miễn phí đôi khi lẫn chữ nước khác vào câu tiếng Việt do LLM viết (vd. "thường见", "conhecido" ở phần câu hỏi của Joomla); phần này không ảnh hưởng bằng chứng hay khuyến nghị. Các lần chạy bằng `auto` (DeepSeek) cho cùng khuyến nghị và nằm trong luận văn, không nằm ở thư mục này.
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

- Judge/advisor/PEAK là LLM, kết quả mỗi lần chạy có thể khác; phần tất định (số bản ghi, disposition khi cùng judge) tái lập được. Judge chạy 3 lần (đa số), temperature 0.
- Bước Prepare của Joomla được lấy từ cache của một lần chạy trước cùng model và cùng PoC (báo cáo ghi `prepare cache hit`); ba PoC còn lại gọi PEAK mới.
- Endpoint LLM thỉnh thoảng trả lỗi thoáng qua; mỗi bước tự gọi lại với backoff 3s/10s/25s rồi chuyển model dự phòng. Lần chạy này không gặp lỗi nào, nên việc gọi lại và chuyển model dự phòng chỉ được kiểm bằng unit test. Advisor thử lại tối đa 3 lần nếu model trả JSON lỗi.
- Bản nháp SPL trong báo cáo chưa được kiểm tra trên Splunk thật.
- Token của mọi agent (kể cả PEAK) được đo và ghi trong `recommendation.json` (`meta`). Lời gọi dạng stream sẽ không có số token; lần chạy này không có.
- Chưa chạy trên Splunk thật: bản nháp SPL và adapter Splunk chưa được kiểm chứng.
