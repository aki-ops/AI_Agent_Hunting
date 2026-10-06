# Chương 5. Cài đặt hệ thống

## 5.1. Môi trường và công nghệ

Hệ thống được viết bằng Python 3.12, chạy trên Windows với môi trường ảo `.venv`; không có thành phần nào phụ thuộc hệ điều hành. Các thư viện chính:

Bảng: Công nghệ sử dụng
| Thành phần | Vai trò | Ghi chú |
|---|---|---|
| Python 3.12 | Ngôn ngữ | Yêu cầu của PEAK Assistant |
| PEAK Assistant | Prepare: ABLE, kế hoạch | Ghim theo commit `dfabbb0`, giấy phép MIT |
| AutoGen (`autogen-agentchat`, `autogen-ext`) | Khung đa tác tử mà PEAK dùng | Được kéo theo PEAK |
| SQLite | Kho telemetry CDB | Thư viện chuẩn `sqlite3` |
| Pydantic, PyYAML, requests | Hợp đồng dữ liệu, đọc cấu hình, gọi HTTP | Phụ thuộc lõi |
| pytest, ruff | Kiểm thử, kiểm tra kiểu mã | Phụ thuộc phát triển |
| Splunk REST API | Adapter Splunk (tuỳ chọn) | Chưa chạy trên máy chủ thật trong đồ án |

PEAK Assistant được khai báo là phụ thuộc **tuỳ chọn** (`pip install -e ".[peak]"`), nhờ đó cài đặt lõi không phải kéo theo AutoGen, Streamlit và nhiều thư viện khác. Mọi `import` vào PEAK nằm trong thân hàm, nên mô-đun của hệ thống nạp được cả khi PEAK chưa cài.

## 5.2. Cấu trúc mã nguồn

Sau khi làm gọn, `src/hunting/` gồm các mô-đun sau với tổng khoảng 8.700 dòng.

Bảng: Cấu trúc mã nguồn
| Đường dẫn | Dòng | Vai trò |
|---|---|---|
| `llm.py` | ~215 | Cấu hình LLM, gọi lại, bộ gọi đồng bộ |
| `prepare.py` | ~220 | Cầu nối PEAK Assistant |
| `recommend.py` | ~500 | Tóm tắt bằng chứng, luật khuyến nghị, advisor |
| `report.py` | ~130 | Dựng báo cáo Markdown và bảng tổng hợp |
| `pipeline.py` | ~115 | Điều phối một PoC từ đầu đến cuối |
| `cli.py` | ~130 | Dòng lệnh |
| `poc/` | ~1.700 | Mô hình PoC, nạp JSON, tác tử thực thi, judge, báo cáo |
| `adapters/` | ~3.300 | Adapter CDB và Splunk, danh sách cho phép, kiểm soát |
| `act/` | ~365 | Bản nháp SPL, backlog, ghi chú stakeholder |
| `contracts/`, `capabilities/`, `controller/`, `query_safety/` | ~1.550 | Hợp đồng dữ liệu mà adapter cần, theo dõi chi phí |
| `peak.py` | ~450 | Cổng Prepare, phân tích thời lượng, cửa sổ, ABLE → quan sát cụ thể |

Hai nguyên tắc tổ chức: các mô-đun mới (`llm`, `prepare`, `recommend`, `report`, `pipeline`, `cli`) chỉ phụ thuộc vào `poc/` và `adapters/` qua giao diện công khai; và không có mô-đun nào của lõi phụ thuộc trực tiếp vào PEAK ngoài `prepare.py` và `llm.py`.

## 5.3. Lớp LLM (`llm.py`)

### 5.3.1. Từ `.env` đến cấu hình PEAK

PEAK Assistant đọc cấu hình mô hình từ một tệp `model_config.json` có thể nội suy biến môi trường dạng `${TÊN}`. Hệ thống đọc ba biến `LLM_ENDPOINT`, `LLM_API_KEY`, `LLM_MODEL` từ `.env` (hoặc từ biến môi trường, hoặc đối số `--model`), tách địa chỉ gốc ra khỏi đường dẫn `/chat/completions`, rồi sinh cấu hình chỉ chứa placeholder:

```python
def model_config(self) -> dict:
    return {
        "version": "1",
        "providers": {"hunting-llm": {
            "type": "openai",
            "config": {"api_key": "${LLM_API_KEY}",
                       "base_url": "${PEAK_LLM_BASE_URL}",
                       "timeout": self.timeout, "max_tokens": self.max_tokens},
            "models": {self.model: {"model_info": {...}}},
        }},
        "defaults": {"provider": "hunting-llm", "model": self.model},
    }
```

Trường `model_info` là bắt buộc của AutoGen khi dùng tên mô hình không thuộc danh sách OpenAI. Hệ thống điền các giá trị trung tính (không hỗ trợ hình ảnh, không dùng gọi hàm) để mọi mô hình tương thích OpenAI đều dùng được. Khoá API và địa chỉ cơ sở được đặt vào `os.environ` của tiến trình ngay trước khi nạp cấu hình, nên không tệp nào trên đĩa chứa khoá.

### 5.3.2. Tính tuỳ chọn

Hàm `LlmSettings.from_env` ném `LlmUnavailable` khi thiếu cấu hình hoặc khi giá trị còn là placeholder của `.env.example` (chứa `<` hoặc bắt đầu bằng `sk-or-...`). `configure_peak` cũng ném `LlmUnavailable` nếu thư viện PEAK chưa cài. CLI bắt ngoại lệ này, in một dòng thông tin (không phải lỗi) và tiếp tục chạy phần tất định. Nhờ vậy cùng một lệnh chạy được trên máy có và không có LLM.

### 5.3.3. Gọi lại có backoff

Quan sát thực tế cho thấy endpoint LLM đôi lúc trả HTTP 404 `model_not_found` dù mô hình tồn tại; ứng dụng khách OpenAI không thử lại lỗi 404. Hàm sau gọi lại bất kỳ lời gọi bất đồng bộ nào với khoảng chờ tăng dần, và ném lại lỗi cuối nếu hết lượt:

```python
RETRY_DELAYS = (3.0, 10.0, 25.0)

async def retry_async(factory, *, delays=RETRY_DELAYS, label="LLM call", notes=None):
    for attempt in range(len(delays) + 1):
        try:
            return await factory()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if attempt >= len(delays):
                raise
            if notes is not None:
                notes.append(f"{label}: retry {attempt + 1}/{len(delays)} after {type(exc).__name__}")
            await asyncio.sleep(delays[attempt])
```

`PeakLlm.__call__` (dùng cho judge và advisor) và hai bước ABLE, kế hoạch trong `prepare.py` đều dùng hàm này. Một sai cấu hình thật (khoá sai, tên mô hình sai) vẫn thất bại sau lượt cuối với nguyên thông báo gốc.

### 5.3.4. Vòng lặp sự kiện

PEAK là bất đồng bộ còn pipeline là đồng bộ. Hàm `run_async` tạo vòng lặp mới cho mỗi lần chạy, đóng vòng lặp đúng cách và cài một bộ xử lý ngoại lệ bỏ qua cảnh báo vô hại `Event loop is closed` do các ứng dụng khách HTTP bị dọn sau khi vòng lặp đã đóng. Cảnh báo này xuất hiện trong lần chạy thật đầu tiên và được loại bỏ ở đây; các lỗi khác vẫn được chuyển tiếp bình thường.

## 5.4. Cầu nối PEAK (`prepare.py`)

Hàm `_peak_prepare` thực hiện hai bước, mỗi bước bọc trong `retry_async` và trong `asyncio.wait_for` với thời hạn mặc định 420 giây:

```python
async def _able() -> str:
    text = await asyncio.wait_for(
        able_table(hypothesis=hypothesis, research_document=research,
                   local_data_document=data_document, local_context=LOCAL_CONTEXT),
        timeout)
    if not text or text.startswith("Error while generating"):
        raise RuntimeError(text or "empty ABLE table")   # able_table nuốt lỗi thành chuỗi
    return text
able = await retry_async(_able, label="ABLE", notes=result.notes)
```

Chi tiết quan trọng: hàm `able_table` của PEAK bắt mọi ngoại lệ và trả về chuỗi bắt đầu bằng `Error while generating`; nếu không nhận ra điều này, lỗi sẽ bị coi là một bảng ABLE hợp lệ. Bước kế hoạch có kiểm tra tương tự với các chuỗi `Could not create a hunt plan` và `no plan was generated`.

PEAK và AutoGen in nhiều dòng traceback cho mỗi lời gọi lỗi. Ngữ cảnh `_quiet_peak` chuyển hướng đầu ra chuẩn và đầu ra lỗi, và nâng ngưỡng ghi log của các logger `autogen_*` lên mức nghiêm trọng trong lúc gọi PEAK; nguyên nhân lỗi vẫn được ghi lại bằng chữ trong `peak.notes`. Hàm `run_prepare` bọc tất cả: nếu `llm` là rỗng thì dùng ABLE và kế hoạch dựng từ PoC; ngược lại thử tối đa hai lượt và, nếu cả hai thất bại, quay về chế độ này với ghi chú rõ ràng.

## 5.5. Bộ thực thi PoC (`poc/agent.py`)

`PocAgent.run` thực hiện: kiểm tra cổng Prepare, cắt cửa sổ theo `max_duration`, chạy vòng thực thi, gọi judge (nếu bật), ghi gói IR khi có hit, ghi sổ cái. Vòng thực thi `_execute_loop` có đặc tính đáng chú ý:

- Lượt 1 chạy mọi bước chính, mỗi bước gọi `adapter.execute_query(operation_id="search_text", search_terms=...)` với giới hạn quét `SCAN_LIMIT = 2000` hàng; sau khi áp dụng toán tử, tối đa `ROW_CAP = 100` hàng được giữ và `matched_total` ghi tổng số khớp.
- Các giá trị cụ thể rút từ ABLE **của PoC** (tên tệp, cờ dòng lệnh, địa chỉ IP, chuỗi trong ngoặc kép; không phải bảng ABLE do PEAK sinh) được AND thêm vào truy vấn; văn xuôi không thêm điều kiện nào. Host suy ra từ `able.location` cũng được dùng làm bộ lọc thực thể. Việc rút trích dùng biểu thức chính quy trong `peak.py`, và mọi điều kiện thêm này được ghi vào `StepResult.scope`.
- Nếu các hit ở bước đầu tiên đến từ đúng một máy khác với máy ABLE nêu, lượt 2 chạy lại các bước còn lại trên máy đó.
- Nếu lượt 1 hoàn toàn rỗng và PoC khai báo `fallbacks` thì chạy các bước thay thế; sau đó có thể chạy lại đúng các vị từ gốc một lần.
- Toán tử không bao giờ được nới: `EQUALS` không biến thành `CONTAINS` ở lượt thứ hai.

Hàm `_apply_op` hiện thực toán tử trên giá trị ô. `EQUALS` so khớp không phân biệt hoa thường với cả giá trị đầy đủ và phần tên tệp cuối đường dẫn; `MATCHES` dùng `re.search` và lùi về `CONTAINS` nếu biểu thức lỗi; `EXISTS` yêu cầu ô không rỗng và, nếu `value` rỗng, loại bỏ mọi hàng để tránh khớp bừa (một lỗi thật đã được phát hiện khi đánh giá trên dữ liệu lớn). Ở tầng truy xuất, `MATCHES` chỉ gửi cho adapter đoạn literal bắt buộc dài nhất của biểu thức (`_regex_literal`) và `EXISTS` được đẩy xuống SQL (`parameters={"require_nonempty": [trường]}`); nếu không, regex bị đưa nguyên vào `LIKE` sẽ không khớp gì.

## 5.6. Adapter

Adapter CDB mở một tệp SQLite và hiện thực `execute_query` với các thao tác có tham số. Với `search_text`, mỗi từ khoá tạo một điều kiện `COALESCE(cột, '') LIKE ?` trên các cột văn bản, nối bằng `OR` giữa cột và `AND` giữa các từ khoá; cửa sổ thời gian là hai điều kiện trên `timestamp`. Hai phương thức mới được thêm cho đồ án:

- `source_presence(window, source_kind)`: đếm số bản ghi trong cửa sổ có `native_type` thuộc tập tương ứng với loại nguồn; trả `None` nếu loại nguồn không biết.
- `describe_data()`: tạo tài liệu Markdown mô tả bảng, các cột, và với mỗi cặp `(native_type, event_id)` là số dòng, thời điểm đầu và cuối. Đây chính là "tài liệu dữ liệu cục bộ" mà PEAK nhận.

Adapter Splunk (`SplunkLiveAdapter`) giữ nguyên từ phiên bản trước: gọi REST API, kiểm tra cú pháp SPL qua điểm cuối parser mà không chạy tìm kiếm, và có cổng AST cho truy vấn gốc. Tám kiểm thử dành cho Splunk thật tự bỏ qua khi không có máy chủ tại cổng 8089.

## 5.7. Khuyến nghị và báo cáo

Mô-đun `recommend.py` gồm ba phần. `summarize_evidence` dựng `EvidenceSummary`: lấy hàng của các bước chính, khử trùng lặp, tính khoảng thời gian, đếm giá trị xoay trục, và gọi `source_presence` cho từng loại nguồn (có bộ nhớ đệm theo loại). `decide` hiện thực bảng luật ở mục 4.6, được trích ở đây phần nhánh có bản ghi khớp:

```python
if ev.chain_complete:
    if judge_ok and judge.verdict == TRUE_POSITIVE:
        disposition, confidence = ESCALATE, "HIGH" if judge.confidence >= 0.8 else "MEDIUM"
        if not outcome_observed and confidence == "HIGH":
            confidence = "MEDIUM"      # chưa kiểm tra kết quả => chưa chứng minh thành công
    elif judge_ok and judge.verdict == FALSE_POSITIVE:
        disposition, confidence = TUNE, "MEDIUM"
    else:
        disposition, confidence = INVESTIGATE, "MEDIUM"
else:
    disposition, confidence = INVESTIGATE, "LOW" if judge is None else "MEDIUM"
```

Hàm `advise` gửi cho LLM một lời nhắc chứa giả thuyết, kết luận do luật tính, các lý do, bản tóm tắt bằng chứng (cắt 6.000 ký tự), bảng ABLE (2.500 ký tự) và kế hoạch PEAK (6.000 ký tự), yêu cầu trả JSON chặt với ba mảng. Hàm chịu được đầu ra lệch chuẩn: thử tối đa ba lần khi JSON lỗi hoặc không có bước nào dùng được; chấp nhận mục bước là chuỗi thuần hoặc đối tượng có khoá `step`/`title`/`check` thay cho `action` và `reason`/`rationale` thay cho `why`; nếu thất bại vẫn trả khuyến nghị theo luật cùng một ghi chú giải thích. Hàm `advise` không có đường nào ghi vào `disposition` hay `confidence`.

Mô-đun `report.py` dựng báo cáo Markdown bằng tiếng Việt với các mục cố định: khuyến nghị và lý do, giới hạn, bảng lựa chọn, bằng chứng, judge, gợi ý bước tiếp theo, câu hỏi, rủi ro, kế hoạch PEAK, bản nháp SPL, chi phí và tái lập. Bản nháp SPL do `act/` sinh từ các vị từ: `EQUALS` thành `trường="giá trị"`, các toán tử còn lại thành `match(trường, "(?i)giá trị")`; một kiểm tra tĩnh từ chối các lệnh nguy hiểm như `delete`, `outputlookup`, `sendemail`.

## 5.8. Dòng lệnh

`cli.py` dùng `argparse` với các nhóm đối số: đầu vào PoC (`--poc`, `--poc-dir`, `--window`), nhà cung cấp telemetry (`--provider`, `--db`, các tham số Splunk), LLM (`--env`, `--model`, `--offline`, `--research`, `--peak-timeout`) và `--out`. Với mỗi PoC, lỗi nạp hoặc lỗi cổng Prepare được in ra và tính vào mã thoát, nhưng không dừng các PoC còn lại. Sau cùng ghi `summary.md` và `summary.json`.

## 5.9. Kiểm thử

Bộ kiểm thử gồm 101 bài, trong đó 93 chạy được và 8 bị bỏ qua vì cần Splunk thật. Kết quả cuối: 93 đạt, 8 bỏ qua, mã kiểm tra tĩnh `ruff` không báo lỗi. Các bài mới (`tests/unit/test_pipeline.py` và `tests/unit/test_scope_and_caps.py`) kiểm tra:

- **Luật khuyến nghị:** 11 tổ hợp tham số (bằng chứng × judge) ứng với bảng luật; chuỗi một phần không escalate dù judge tin cậy cao; trần độ tin cậy khi chưa có bước kiểm tra kết quả và mở trần khi có.
- **Rỗng không thành sạch:** thiếu nguồn cho `COLLECT_DATA_THEN_RERUN` với câu cảnh báo.
- **Advisor:** phân tích JSON có hàng rào mã; thử lại khi rác hoặc rỗng; chấp nhận dạng lệch chuẩn; lỗi LLM không đổi khuyến nghị.
- **Cấu hình LLM:** đọc `.env`, tách địa chỉ gốc, không để khoá lọt vào cấu hình, từ chối giá trị mẫu.
- **Chịu lỗi PEAK:** khi PEAK ném lỗi thì quay về PoC và có ghi chú; lỗi thoáng qua được thử lại thành công; cơ chế `retry_async` thành công sau vài lần và ném lại lỗi dai dẳng.
- **Độ phủ CDB:** đếm theo loại nguồn (và theo host), cơ cấu loại sự kiện, host ghi nguồn, mô tả dữ liệu.
- **Phạm vi ngầm và giới hạn hàng (mục 7.4):** phạm vi host rỗng phải được ghi nhận và chạy lại không lọc host (cả hai nhánh có hit và không hit); báo cáo ghi `hiển thị / tổng` khi chạm trần 100 hàng; `MATCHES` với regex thật tìm được; `EXISTS` không bị che bởi giới hạn quét; `_regex_literal` chỉ thu hẹp, không bỏ sót; cửa sổ SPL lấy từ PoC.
- **Đầu cuối:** chạy CLI trên một CSDL nhỏ ở chế độ `--offline`, và chạy CLI khi không có tệp `.env` nào.

Các bài này không gọi LLM thật; việc gọi thật được kiểm chứng bằng thực nghiệm ở Chương 7.
