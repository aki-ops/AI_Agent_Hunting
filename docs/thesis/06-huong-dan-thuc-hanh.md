# Chương 6. Hướng dẫn thực hành

Chương này hướng dẫn một người chưa biết hệ thống đi từ cài đặt đến chạy được cuộc săn đầu tiên, đọc kết quả, và tự viết PoC mới. Các lệnh ghi theo cú pháp Windows (PowerShell hoặc Git Bash) và đều đã được chạy thử trong quá trình thực hiện đồ án. Trên Linux hoặc macOS, thay `.venv\Scripts\python.exe` bằng `.venv/bin/python`.

## 6.1. Chuẩn bị môi trường

### 6.1.1. Yêu cầu

- Python 3.12 trở lên (PEAK Assistant không chạy trên bản thấp hơn).
- Git, để cài PEAK Assistant từ GitHub.
- Khoảng 2 GB dung lượng đĩa nếu nạp toàn bộ BOTS v1; chỉ vài MB nếu dùng mẫu nhỏ.
- Khoá API của một dịch vụ LLM tương thích OpenAI. **Đây là điều kiện tuỳ chọn**, xem mục 6.2.

### 6.1.2. Cài đặt lõi (không cần LLM)

```bash
git clone <địa-chỉ-kho> AI_Agent_Hunting
cd AI_Agent_Hunting
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Cài đặt này chỉ kéo theo `pydantic`, `pyyaml`, `requests`, cùng `pytest` và `ruff`. Kiểm tra:

```bash
.venv\Scripts\python.exe -m pytest tests -q
```

Kết quả mong đợi: `78 passed, 8 skipped`. Tám bài bị bỏ qua cần máy chủ Splunk thật tại cổng 8089 và tự bỏ qua khi không có.

### 6.1.3. Cài thêm PEAK Assistant (tuỳ chọn)

```bash
.venv\Scripts\python.exe -m pip install -e ".[peak]"
```

Lệnh này cài PEAK Assistant từ GitHub tại commit đã ghim `dfabbb0`, kéo theo AutoGen và nhiều thư viện khác nên mất vài phút. Kiểm tra bằng `python -c "import peak_assistant"`; không có lỗi nghĩa là đã cài xong.

## 6.2. Cấu hình LLM

### 6.2.1. Ba biến cần thiết

Sao chép `.env.example` thành `.env` rồi điền ba giá trị:

```bash
LLM_ENDPOINT=https://openrouter.ai/api/v1/chat/completions
LLM_API_KEY=<khoá-của-bạn>
LLM_MODEL=<tên-mô-hình>
```

`LLM_ENDPOINT` là địa chỉ đầy đủ tới `/chat/completions` của bất kỳ dịch vụ tương thích OpenAI nào (OpenRouter, OpenAI, một máy chủ cục bộ như Ollama hoặc vLLM). Có hai biến phụ: `LLM_TIMEOUT` (giây, mặc định 600) và `LLM_MAX_TOKENS` (mặc định 16000). Tệp `.env` đã nằm trong `.gitignore`; **không bao giờ** đưa khoá vào mã nguồn, báo cáo hay ảnh chụp màn hình.

### 6.2.2. Ba mức dùng LLM

Bảng: Các chế độ chạy theo cấu hình LLM
| Chế độ | Cách bật | Prepare | Judge và advisor | Khi nào dùng |
|---|---|---|---|---|
| Không LLM | `--offline`, hoặc `.env` chưa điền | ABLE và kế hoạch dựng từ PoC | Không có | Chưa có khoá; dữ liệu nhạy cảm; chạy nhanh, tái lập |
| LLM mặc định | `.env` đã điền | PEAK Assistant | Có | Chạy đầy đủ |
| Ghi đè mô hình | `--model <tên>` | PEAK Assistant | Có | Thử mô hình khác mà không sửa `.env` |

Hệ thống nhận biết trường hợp `.env` còn giá trị mẫu (`<your-key>`, `sk-or-...`) và chuyển sang chế độ không LLM với một dòng thông tin, không báo lỗi. Điều này đã được kiểm thử bằng bài `test_cli_runs_without_any_llm_configuration`.

### 6.2.3. Chọn mô hình miễn phí

Khi chưa muốn trả phí, OpenRouter có các mô hình đánh dấu `:free`. Danh sách thay đổi liên tục, nên cách chắc chắn là hỏi trực tiếp danh mục của dịch vụ rồi lọc theo giá bằng không:

```bash
curl https://openrouter.ai/api/v1/models
```

Trong kết quả, mô hình có `pricing.prompt` và `pricing.completion` cùng bằng `"0"` là miễn phí. Không phải mô hình nào cũng gọi được: một số bị giới hạn tốc độ, một số không trả JSON, một số không phải mô hình văn bản. Mục 7.5 trình bày kết quả thử thật và mô hình đã chạy trọn bốn PoC. Để dùng:

```bash
.venv\Scripts\python.exe main.py --poc-dir pocs --model "nvidia/nemotron-3-super-120b-a12b:free"
```

Lưu ý: mô hình miễn phí thường có giới hạn số lượt gọi mỗi phút/ngày và có thể dùng dữ liệu gửi lên để huấn luyện; đừng gửi telemetry nhạy cảm tới chúng.

## 6.3. Chuẩn bị dữ liệu telemetry

### 6.3.1. Mẫu nhỏ để thử nhanh

```bash
.venv\Scripts\python.exe scripts/seed_botsv1_sample.py --db data/cdb_sample.sqlite
```

Lệnh tạo một CSDL SQLite với khoảng vài chục sự kiện đại diện cho các pha tấn công của BOTS v1. Đủ để kiểm tra luồng chạy, nhưng chưa đủ để thấy các hiện tượng thật như kết quả rỗng do thiếu nguồn.

### 6.3.2. Bộ dữ liệu đầy đủ

Kết quả ở Chương 7 dùng `data/botsv1_eval.sqlite` với 4.417.543 dòng. Tệp này lớn và nằm ngoài git. Để dựng lại cần tải các tệp CSV nén của BOTS v1 [15] vào `data/raw/`, rồi chạy:

```bash
.venv\Scripts\python.exe scripts/ingest_botsv1_eval.py   # Security log + sysmon + DNS
.venv\Scripts\python.exe scripts/ingest_http.py          # stream:http cho PoC Joomla
```

Các tập lệnh đọc theo luồng, không giữ toàn bộ CSV trong bộ nhớ, và chỉ giữ các loại sự kiện phục vụ đánh giá (đăng nhập 4624/4625, tạo tiến trình 4688, SMB 5140/5145, sysmon, DNS, HTTP). Lược đồ CSDL là một bảng `events` gồm các cột `timestamp`, `event_id`, `native_type`, `host`, `user`, `pid`, `ppid`, `cmdline`, `image`, `ip`, `port`, `domain`, `file_path`, `action`, `status`, `raw_ref`.

### 6.3.3. Kiểm tra dữ liệu có gì

Trước khi viết PoC, hãy xem CSDL thật sự chứa gì. Đây là bài học lớn nhất của đồ án (mục 7.4): nhiều PoC rỗng chỉ vì dữ liệu không có loại sự kiện đó.

```bash
.venv\Scripts\python.exe -c "from hunting.adapters import CdbAdapter; print(CdbAdapter('data/botsv1_eval.sqlite').describe_data())"
```

Kết quả là bảng Markdown liệt kê từng cặp `native_type`/`event_id` với số dòng và khoảng thời gian; đây cũng chính là tài liệu mà PEAK nhận làm "dữ liệu cục bộ".

## 6.4. Chạy cuộc săn đầu tiên

### 6.4.1. Một PoC, không LLM

```bash
.venv\Scripts\python.exe main.py --poc pocs/poc-joomla-rce.json --offline --out artifacts/runs/thu1
```

Màn hình in một khối cho mỗi PoC:

```text
=== poc-joomla-rce  window=2016-08-10T21:36:00Z/2016-08-10T22:00:00Z
    verdict=MATCHED obs=199 -> ESCALATE_TO_IR (MEDIUM) | PEAK=no
```

Khi không dùng LLM, kết quả này thường là `INVESTIGATE_FURTHER` vì không có judge nào đánh giá ngữ cảnh. Hệ thống ghi rõ điều đó trong mục giới hạn của báo cáo.

### 6.4.2. Toàn bộ PoC, có LLM

```bash
.venv\Scripts\python.exe main.py --poc-dir pocs --out artifacts/runs/day-du
```

Mỗi PoC mất vài giây đến vài phút tuỳ mô hình; phần lớn thời gian là hai lượt gọi PEAK (ABLE và kế hoạch). Nếu thấy dòng `PEAK=no`, mở `recommendation.json` và đọc `peak.notes` để biết lý do quay về chế độ không LLM.

### 6.4.3. Các tuỳ chọn thường dùng

Bảng: Tham chiếu nhanh tuỳ chọn dòng lệnh
| Tuỳ chọn | Tác dụng |
|---|---|
| `--poc FILE` (lặp được), `--poc-dir DIR` | Chọn PoC |
| `--window START/END` | Ghi đè cửa sổ thời gian của mọi PoC |
| `--db PATH` | Đường dẫn CSDL SQLite |
| `--provider splunk` kèm `--splunk-url`, `--splunk-user`, `--splunk-index` | Dùng Splunk thay cho SQLite |
| `--env FILE`, `--model TÊN` | Tệp cấu hình LLM; ghi đè mô hình |
| `--offline` | Bỏ hoàn toàn PEAK và mọi lời gọi LLM |
| `--research` | Bật tác tử nghiên cứu của PEAK (cần máy chủ MCP) |
| `--peak-timeout GIÂY` | Hạn cho mỗi bước PEAK (mặc định 420) |
| `--out DIR` | Thư mục kết quả |

## 6.5. Đọc và dùng báo cáo

Mở `recommendation.md` của một PoC. Nên đọc theo thứ tự sau, vì thứ tự đó phản ánh mức độ quan trọng đối với người quyết định.

1. **Dòng đầu: khuyến nghị và độ tin cậy.** Ví dụ `ESCALATE_TO_IR (MEDIUM)`. Đây là gợi ý, không phải quyết định.
2. **Lý do.** Mỗi lý do gắn với một sự kiện kiểm chứng được: số bước khớp, khoảng thời gian hit, nhận định judge.
3. **Giới hạn của kết luận.** Mục dễ bị bỏ qua nhất nhưng quan trọng nhất. Với kết quả rỗng, mục này nói rõ cửa sổ đã quét, rằng predicate là literal, và rằng nguồn chưa chắc chứa đúng loại sự kiện.
4. **Bảng lựa chọn.** Các hành động khả dĩ xếp theo ưu tiên.
5. **Bằng chứng.** Bảng từng bước với số bản ghi nguồn và số khớp; các giá trị xoay trục (máy, IP, miền); vài hàng mẫu. Đây là chỗ để tự kiểm chứng.
6. **Phần do LLM viết** (judge, bước tiếp theo, câu hỏi, rủi ro, kế hoạch PEAK): luôn được gắn nhãn "chỉ mang tính tham khảo".

Ba tình huống thường gặp và cách xử lý:

Bảng: Từ khuyến nghị đến hành động của người săn
| Khi báo cáo nói | Người săn nên |
|---|---|
| `ESCALATE_TO_IR` | Mở bằng chứng, kiểm tra vai trò thật của máy ở "Top host" (nạn nhân hay cảm biến), tìm bước kiểm tra kết quả (status), rồi mới chuyển gói trong `ir/` cho IR |
| `COLLECT_DATA_THEN_RERUN` | Làm việc với đội hạ tầng để bật thu thập nguồn bị thiếu; **không** đóng cuộc săn |
| `CLOSE_WITH_CAVEAT` | Đọc từng giới hạn; nếu chấp nhận được thì đóng và lưu lại các giới hạn như ghi chú tri thức |
| `INVESTIGATE_FURTHER` | Xem bước nào không khớp và vì sao; bổ sung bước hoặc mở rộng cửa sổ |
| `TUNE_POC_OR_CLOSE` | Thêm điều kiện loại trừ cho hoạt động hợp lệ, hoặc đóng PoC |

## 6.6. Viết PoC mới

### 6.6.1. Cấu trúc

Một PoC là tệp JSON. Hãy xem ví dụ đầy đủ tại Phụ lục A. Các trường bắt buộc của cổng Prepare: `topic`, `able` (đủ `behavior`, `location`, `evidence`; `actor` được để trống), `research_refs`, `scope`, `max_duration`, `plan`. Các trường thực thi: `steps` (bắt buộc), `fallbacks`, `references`, `expected_chain`, `time_window`.

### 6.6.2. Quy trình năm bước

1. **Phát biểu giả thuyết cụ thể và kiểm chứng được.** Tốt: "một địa chỉ IP gửi nhiều yêu cầu có chuỗi `acunetix` tới site Joomla". Kém: "có ai đó tấn công website".
2. **Xem dữ liệu có gì** (mục 6.3.3). Nếu không có nguồn nào chứa dấu hiệu bạn tìm, hãy dừng và coi đó là phát hiện về khoảng trống dữ liệu.
3. **Chọn trường và toán tử.** Dùng `EQUALS` cho giá trị chính xác (tên tệp, tên miền); `CONTAINS` cho chuỗi con; `MATCHES` khi cần biểu thức chính quy; `EXISTS` khi chỉ cần trường có giá trị.
4. **Thêm một bước kiểm tra kết quả nếu dữ liệu có.** Bước trên trường `status`, `action`, `result` hoặc `response` cho phép hệ thống nâng độ tin cậy khi leo thang; thiếu bước này, giới hạn "chưa chứng minh thành công" sẽ luôn xuất hiện.
5. **Đặt `time_window` hợp lý** và chạy thử với `--offline` trước, rồi mới bật LLM.

### 6.6.3. Chạy thử ví dụ

Kho có sẵn `pocs/examples/poc-web-scanner-acunetix.json`. Chạy:

```bash
.venv\Scripts\python.exe main.py --poc pocs/examples/poc-web-scanner-acunetix.json --offline
```

Kết quả khi chạy thật trên BOTS v1: 203 bản ghi khớp, 3 trên 3 bước có kết quả, tất cả từ địa chỉ 40.80.148.42, hit đầu tiên lúc 21:36:45; khuyến nghị `INVESTIGATE_FURTHER` (MEDIUM) vì ở chế độ `--offline` không có judge. Số 203 lớn hơn 199 của PoC Joomla vì ví dụ này thêm bước tìm chuỗi `acunetix`.

### 6.6.4. Những lỗi người mới hay mắc

Bảng: Lỗi thường gặp khi viết PoC
| Triệu chứng | Nguyên nhân thường gặp | Cách sửa |
|---|---|---|
| PoC bị từ chối trước khi chạy | Thiếu trường của cổng Prepare | Đọc thông báo; điền trường thiếu |
| Kết quả luôn rỗng | Giá trị literal sai hoa thường không thành vấn đề, nhưng sai trường hoặc sai dạng thì có | Chạy `describe_data`, nhìn mẫu hàng thật trong CSDL |
| `EQUALS` không khớp đường dẫn đầy đủ | Giá trị ghi cả đường dẫn nhưng tên tệp trong dữ liệu khác | Dùng chỉ tên tệp (`powershell.exe`) |
| Quá nhiều hit vô nghĩa | Dùng `CONTAINS` với chuỗi quá ngắn | Dùng `EQUALS` hoặc `MATCHES` chính xác hơn, thêm bước loại trừ |
| `COLLECT_DATA_THEN_RERUN` | Nguồn đúng là không có dữ liệu trong cửa sổ | Kiểm tra `source_kind` và `time_window` trước khi kết luận |

## 6.7. Dùng với Splunk thật

Adapter Splunk dùng REST API. Cần đặt mật khẩu qua biến môi trường (không qua dòng lệnh):

```bash
set SPLUNK_PASSWORD=...
.venv\Scripts\python.exe main.py --poc-dir pocs --provider splunk --splunk-url https://localhost:8089 --splunk-user admin --splunk-index botsv1
```

Cần lưu ý trung thực: trong khuôn khổ đồ án, adapter này chỉ được kiểm thử bằng các bài tự bỏ qua khi không có máy chủ; chưa có lần chạy đầy đủ nào trên Splunk thật. Adapter Splunk cũng chưa có phương thức `source_presence`, nên với Splunk độ phủ nguồn được ghi là "không kiểm tra được" và kết quả rỗng sẽ có độ tin cậy `LOW`. Người dùng nên chạy thử trên một chỉ mục nhỏ và tự đối chiếu số bản ghi trước khi tin kết quả.

## 6.8. Xử lý sự cố

Bảng: Sự cố thường gặp và cách xử lý
| Hiện tượng | Giải thích | Xử lý |
|---|---|---|
| `[i] LLM is optional and not available (...)` rồi chạy tiếp | `.env` thiếu hoặc còn giá trị mẫu | Bình thường; điền khoá nếu muốn dùng LLM |
| `PEAK Assistant is not installed` | Chưa cài extra `peak` | `pip install -e ".[peak]"` |
| `PEAK=no` kèm ghi chú `HTTP 404 model_not_found` | Endpoint trả lỗi thoáng qua | Đã tự gọi lại ba lần; nếu vẫn lỗi, thử `--model` khác |
| `HTTP 401` | Khoá sai hoặc hết hạn | Kiểm tra `LLM_API_KEY` (không in khoá ra màn hình) |
| `HTTP 429` | Vượt giới hạn tốc độ, hay gặp với mô hình miễn phí | Đợi hoặc đổi mô hình; hệ thống đã gọi lại có chờ |
| Hết thời gian ở bước PEAK | Mô hình chậm | Tăng `--peak-timeout` hoặc `LLM_TIMEOUT` |
| Advisor ghi "không dùng được" | Mô hình trả JSON sai ba lần | Khuyến nghị theo luật vẫn đúng; thử mô hình khác |
| Không tìm thấy `botsv1_eval.sqlite` | Tệp ngoài git | Dựng theo mục 6.3.2 hoặc dùng `--db data/cdb_sample.sqlite` |

## 6.9. Quy trình tái lập kết quả của luận văn

Để chạy lại thực nghiệm của Chương 7: dựng CSDL (6.3.2), điền `.env`, rồi chạy `main.py --poc-dir pocs --out artifacts/runs/tai-lap`. Phần tất định (số bản ghi khớp, độ phủ) phải giống hệt; phần LLM (văn bản ABLE, kế hoạch, nhận định judge, số token) sẽ khác từng lần, chỉ kết luận (disposition, độ tin cậy) được kỳ vọng ổn định. Thư mục `results/botsv1-peak-run/` lưu bản chạy đã dùng trong luận văn.
