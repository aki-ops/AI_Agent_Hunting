# Báo cáo: tích hợp PEAK Assistant, làm gọn repo và chạy 4 PoC có sẵn

Branch `peak-assistant-integration` (bản gốc: tag `v6-engine-final`, branch `pre-peak-snapshot`).
Kết quả gốc nằm ở [`results/botsv1-peak-run/`](../results/botsv1-peak-run/).

## 1. Tóm tắt

- Repo được làm gọn: mã nguồn `src/` từ **36.376 dòng xuống 8.400 dòng**. Engine v6 (ClaimGraph, CapabilityGraph, planner,
  evidence, reporter) bị loại khỏi nhánh chính; chỉ giữ đường chạy PoC, adapter CDB/Splunk và các contract adapter cần.
- Phần **Prepare** của PEAK giờ do **PEAK Assistant (Cisco Talos)** làm: bảng ABLE (`able_table`) và kế hoạch hunt
  (`plan_hunt`, planner + critic). Phần **Execute** vẫn tất định. Phần **Act** là mới: khuyến nghị có xếp hạng để
  **người săn quyết định**, hệ thống không tự hành động.
- Chạy 4 PoC có sẵn trên BOTS v1 (4.417.543 dòng) với PEAK và LLM thật: 1 PoC khớp (khuyến nghị chuyển IR, tin cậy
  trung bình), 3 PoC rỗng (khuyến nghị đóng kèm cảnh báo, chưa phải "sạch").
- 76 test pass, 8 test bị skip (cần Splunk thật tại localhost:8089), `ruff` sạch.

## 2. Đã thay đổi gì

### 2.1 Làm gọn

| Hạng mục | Trước | Sau |
|---|---|---|
| Mã nguồn `src/` | 36.376 dòng | 8.400 dòng (gồm ~1.140 dòng mới) |
| File test (`.py`) | 80 | 6 file `test_*.py` (test của engine đã xoá; test PoC, Act, adapter được giữ, thêm `test_pipeline.py`) |
| Tài liệu gốc | 6 file kiến trúc v6 ở thư mục gốc | chuyển vào `docs/archive/v6-engine/`; paper vào `docs/archive/paper/` |
| `artifacts/`, `report.md`, `baseline_*`, `templates/`, kết quả cũ | tracked trong git | gỡ khỏi git; `artifacts/` và `data/` nằm trong `.gitignore` |
| Python | ≥3.10 | ≥3.12 (PEAK Assistant yêu cầu) |

Không mất gì: engine cũ khôi phục bằng `git checkout v6-engine-final`; tài liệu cũ vẫn còn trong `docs/archive/`.

### 2.2 Tích hợp PEAK Assistant

| Thành phần | Việc làm |
|---|---|
| `llm.py` | `.env` → `model_config.json` của PEAK (chỉ chứa placeholder `${ENV}`, không ghi khoá ra đĩa). Một đường LLM chung cho agent PEAK và cho judge/advisor. Gọi lại có backoff 3s/10s/25s. |
| `prepare.py` | Gọi `able_table` và `plan_hunt`. Đầu vào dựng từ PoC và từ mô tả telemetry của adapter (`describe_data`) thay cho bước data-discovery qua Splunk MCP. Lỗi → dùng ABLE/plan của chính PoC và ghi lý do. `--research` bật thêm `researcher` (cần MCP server nghiên cứu, chưa thử). |
| `recommend.py` | Luật khuyến nghị tất định + advisor LLM (bước tiếp theo, câu hỏi, rủi ro). |
| `adapters/cdb_adapter.py` | Thêm `source_presence` (nguồn có dữ liệu trong cửa sổ không) và `describe_data`. |
| `cli.py`, `pipeline.py`, `report.py` | CLI mới, điều phối, báo cáo Markdown/JSON. |
| `pocs/*.json` | Thêm trường `time_window` (lấy theo `scope` sẵn có của từng PoC). |

### 2.3 Luật khuyến nghị

| Điều kiện | Khuyến nghị | Tin cậy |
|---|---|---|
| Mọi bước khớp + judge TRUE_POSITIVE ≥0,7 | `ESCALATE_TO_IR` | HIGH nếu judge ≥0,8 **và** PoC có bước kiểm tra kết quả (status/action); còn lại MEDIUM |
| Mọi bước khớp + judge FALSE_POSITIVE ≥0,7 | `TUNE_POC_OR_CLOSE` | MEDIUM |
| Mọi bước khớp, judge không rõ/không có | `INVESTIGATE_FURTHER` | MEDIUM |
| Khớp một phần | `INVESTIGATE_FURTHER` | LOW/MEDIUM, không bao giờ escalate |
| Rỗng, một nguồn cần thiết có 0 bản ghi | `COLLECT_DATA_THEN_RERUN` | HIGH |
| Rỗng, nguồn có dữ liệu | `CLOSE_WITH_CAVEAT` | MEDIUM (LOW nếu không kiểm tra được độ phủ) |

Bất biến: LLM không tạo bằng chứng; advisor không đổi khuyến nghị; mọi khuyến nghị có `decision_required = true`.

## 3. Kết quả chạy 4 PoC

Lệnh: `python main.py --poc-dir pocs --db data/botsv1_eval.sqlite`. Cả 4 PoC dùng PEAK thật.

| PoC | Cửa sổ | Thực thi | Khuyến nghị | Tin cậy |
|---|---|---|---|---|
| `poc-joomla-rce` | 2016-08-10 21:36–22:00 | MATCHED, 199 bản ghi, 2/2 bước | `ESCALATE_TO_IR` | MEDIUM |
| `poc-bruteforce-we1149srv` | 2016-08-21 | EMPTY (0/2 bước) | `CLOSE_WITH_CAVEAT` | MEDIUM |
| `poc-c2-beacon-networkfilter` | 2016-08-21 | EMPTY (0/2 bước) | `CLOSE_WITH_CAVEAT` | MEDIUM |
| `poc-pdf-exploit-enc` | 2016-08-21 | EMPTY (0/3 bước) | `CLOSE_WITH_CAVEAT` | MEDIUM |

### 3.1 `poc-joomla-rce`: nên chuyển IR, nhưng chưa chứng minh thành công khai thác

- 199 request tới `imreallynotbatman.com` trong 21:36:45–21:40:57, toàn bộ từ IP 40.80.148.42, ghi bởi host `splunk-02`.
  Có dấu hiệu quét: `/acunetix-wvs-test-for-some-inexistent-file`, các đường dẫn ngẫu nhiên, `/joomla/index.php/component/search/`.
- Judge (LLM, tham khảo): TRUE_POSITIVE 0,85, nhận định đây là giai đoạn quét.
- Tin cậy bị hạ từ HIGH xuống **MEDIUM**: PoC không có bước nào kiểm tra kết quả, và dữ liệu `web_request` chỉ có `domain` và
  `site=… uri=…`, không có mã trạng thái hay phản hồi. Dữ liệu chứng minh có **quét/thăm dò**, **không** chứng minh khai thác thành công.
- Câu hỏi để người săn trả lời trước khi chuyển IR: `splunk-02` là sensor hay endpoint thật? có log phía server và mã
  trạng thái HTTP không? Rủi ro nêu trong báo cáo: dễ quy kết sai nếu 40.80.148.42 là máy quét bảo mật được phép.

### 3.2 Ba PoC rỗng: đừng đọc là "sạch"

| PoC | Bản ghi nguồn trong cửa sổ | Điểm cần cảnh giác |
|---|---|---|
| bruteforce | 20.657 dòng authentication | Dữ liệu hiện chỉ có đăng nhập thành công (4624); PoC tìm `Logon Failed`, loại sự kiện này có thể không tồn tại trong bộ dữ liệu. |
| c2-beacon | 566 dòng web | DNS chỉ có ngày 2016-08-24; không thể đối chiếu. |
| pdf-exploit | 129.775 dòng process | Predicate literal bỏ sót biến thể (`-EncodedCommand`, `-WindowStyle Hidden`); không có trường parent-image nên chuỗi PDF → PowerShell không kiểm chứng được. |

Cả ba chỉ quét **1 trong 28 ngày** của dữ liệu (cửa sổ lấy theo `scope` của PoC, `max_duration` 3 ngày). Advisor cả ba lần đều
nêu đây là rủi ro âm tính giả. `docs/EVAL-GROUND-TRUTH.md` cũng ghi bộ dữ liệu hiện chưa có 4625, PowerShell mã hoá thật và
beacon `networkfilter`. Vì vậy kết luận hợp lý của người săn là **mở rộng cửa sổ hoặc bổ sung nguồn trước khi đóng**,
không phải "không có tấn công".

## 4. Kiểm chứng và các lỗi đã gặp

| Việc | Kết quả |
|---|---|
| Test | 76 passed, 8 skipped (đều là test Splunk live: không có Splunk tại localhost:8089), `ruff` sạch |
| Test mới (`test_pipeline.py`) | luật khuyến nghị theo bảng, advisor với JSON lỗi, fallback khi PEAK hỏng, thử lại khi lỗi thoáng qua, độ phủ nguồn CDB, CLI end-to-end offline |
| Chạy thật | 4/4 PoC có PEAK, không traceback trong log, advisor có đủ cho cả 4 |
| Lộ khoá | đã kiểm tra: khoá API không xuất hiện trong file output nào |

Lỗi đã gặp và cách xử lý:

1. **`Event loop is closed`** (client HTTP bị dọn sau khi `asyncio.run` đóng vòng lặp): thêm `run_async` có handler bỏ qua cảnh báo
   này và đóng client sau mỗi lần gọi. Hết sau sửa.
2. **404 `model_not_found` thoáng qua từ endpoint LLM**: làm một PoC rơi về ABLE/plan của PoC, và làm advisor của Joomla lỗi hẳn ở bản
   chạy trước. Sửa bằng gọi lại có backoff theo từng bước và chặn traceback của PEAK. Ở lần chạy cuối endpoint ổn định nên
   **đường gọi lại chưa được thử với lỗi thật**, chỉ có unit test.
3. **Tin cậy HIGH quá lạc quan** ở lần chạy thử đầu của Joomla: thêm luật hạ về MEDIUM khi PoC không kiểm tra kết quả.
4. **Gợi ý "cô lập `splunk-02`"** có thể nguy hiểm vì đó có thể là sensor: đổi thành "xác nhận vai trò của host trước khi cô lập".
5. **Advisor tưởng `CONTAINS` phân biệt hoa thường** (thực tế không): thêm sự thật này vào prompt của PEAK và advisor.

## 5. Giới hạn đã biết

- Độ phủ chỉ kiểm tra *có nguồn* trong cửa sổ, chưa kiểm tra nguồn có *đúng loại sự kiện*.
- Nội dung LLM (ABLE, kế hoạch, judge, advisor) không tất định và có thể sai chi tiết; số bản ghi khớp và luật khuyến nghị thì tái lập được.
- Token của các agent bên trong PEAK chưa được đo (PEAK tự tạo client). Thời gian chạy: ~4 phút cho cả 4 PoC lần cuối, trước đó ~20 phút; chưa rõ nguyên nhân.
- Adapter Splunk và bản nháp SPL **chưa chạy trên Splunk thật**. `--research` (researcher của PEAK với MCP) chưa thử.
- PEAK Assistant tự nhận là proof-of-concept chưa qua kiểm thử bảo mật; chỉ nên chạy cục bộ.
- Tôi sửa 4 file PoC (thêm `time_window`, JSON được định dạng lại). Phần `src/hunting/peak.py` còn vài hàm của cổng Prepare cũ
  (wizard, dump plan) không còn được CLI mới gọi.

## 6. Đề xuất tiếp theo

1. Chạy lại 3 PoC rỗng với cửa sổ rộng hơn (cần tăng `max_duration` trong PoC, hiện cắt về 3 ngày) trước khi người săn đóng hunt.
2. Thêm bước kiểm tra kết quả (`status`/`action`) vào PoC Joomla và bổ sung log phản hồi HTTP để đạt tin cậy HIGH.
3. Kiểm tra theo *loại sự kiện* (có 4625 không?) trong phần độ phủ.
4. Thử trên Splunk thật và xác thực bản nháp SPL; bật `--research` khi có MCP server.
5. Đo token của các agent PEAK.
6. Dọn nốt các hàm không dùng trong `peak.py`.
