# Phụ lục

## Phụ lục A. Tệp PoC mẫu

### A.1. PoC Joomla (`pocs/poc-joomla-rce.json`)

```json
{
  "poc_id": "poc-joomla-rce",
  "name": "Joomla RCE web compromise (BOTS v1 real attack)",
  "kind": "ttp",
  "summary": "Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.",
  "topic": "web application exploitation",
  "able": {
    "actor": "",
    "behavior": "Exploit public-facing application (T1190) via Joomla search component",
    "location": "web traffic to imreallynotbatman.com",
    "evidence": "web_request telemetry; hit = site imreallynotbatman.com with /joomla/ uri"
  },
  "research_refs": ["BOTS v1 walkthrough - web compromise phase", "MITRE ATT&CK T1190"],
  "scope": "stream:http 2016-08-10 window",
  "max_duration": "3d",
  "plan": "search_text over web telemetry for the victim site + joomla path",
  "steps": [
    {"step_id": "s1-victim-site", "description": "Request to compromised site",
     "target_field": "domain", "op": "EQUALS", "value": "imreallynotbatman.com", "source_kind": "web"},
    {"step_id": "s2-joomla-path", "description": "Joomla component path",
     "target_field": "cmdline", "op": "CONTAINS", "value": "/joomla/", "source_kind": "web"}
  ],
  "references": ["MITRE ATT&CK T1190"],
  "expected_chain": ["web_request", "exploitation"],
  "time_window": "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z"
}
```

### A.2. PoC mới, có ba bước (`pocs/examples/poc-web-scanner-acunetix.json`)

Ví dụ này khác PoC Joomla ở chỗ thêm bước tìm chuỗi `acunetix` và đặt bước nhận diện máy quét ở vị trí riêng.

```json
{
  "poc_id": "poc-web-scanner-acunetix",
  "name": "Automated web vulnerability scanner against the Joomla site (Acunetix)",
  "kind": "behavior",
  "topic": "web application reconnaissance",
  "able": {
    "actor": "",
    "behavior": "Active scanning of a public-facing web application (T1595.002) preceding exploitation (T1190)",
    "location": "web traffic to imreallynotbatman.com",
    "evidence": "web_request telemetry; hit = domain imreallynotbatman.com with an acunetix probe uri and /joomla/ paths"
  },
  "research_refs": ["MITRE ATT&CK T1595.002 Vulnerability Scanning", "BOTS v1 walkthrough - web compromise phase"],
  "scope": "stream:http for imreallynotbatman.com on 2016-08-10 21:36-22:00",
  "max_duration": "3d",
  "plan": "search_text over web telemetry for the victim site, then the acunetix probe string, then the Joomla path",
  "time_window": "2016-08-10T21:36:00Z/2016-08-10T22:00:00Z",
  "steps": [
    {"step_id": "s1-victim-site",    "target_field": "domain",  "op": "EQUALS",   "value": "imreallynotbatman.com", "source_kind": "web"},
    {"step_id": "s2-acunetix-probe", "target_field": "cmdline", "op": "CONTAINS", "value": "acunetix",              "source_kind": "web"},
    {"step_id": "s3-joomla-enum",    "target_field": "cmdline", "op": "CONTAINS", "value": "/joomla/",              "source_kind": "web"}
  ],
  "references": ["MITRE ATT&CK T1595.002", "MITRE ATT&CK T1190"],
  "expected_chain": ["web_request"]
}
```

Chạy với `--offline` trên BOTS v1: 204 bản ghi hiển thị (100 / ≥1.999, 6 và 100 / ≥2.000 cho từng bước), khuyến nghị `INVESTIGATE_FURTHER` (MEDIUM).

### A.3. Bảng trường của PoC

Bảng: Các trường của tệp PoC
| Trường | Bắt buộc | Mô tả |
|---|---|---|
| `poc_id`, `name`, `kind`, `summary` | `poc_id`, `name` | Định danh và mô tả ngắn |
| `topic` | Có | Chủ đề săn (PEAK: select topic) |
| `able.actor` | Không (được để trống) | Tác nhân đe dọa |
| `able.behavior`, `able.location`, `able.evidence` | Có | Ba thành phần còn lại của ABLE |
| `research_refs` | Có | Tài liệu nghiên cứu đã đọc |
| `scope` | Có | Hệ thống, dữ liệu và khoảng thời gian |
| `max_duration` | Có | Thời lượng tối đa, ví dụ `3d` |
| `plan` | Có | Kế hoạch tóm tắt |
| `steps[]` | Có | `step_id`, `description`, `target_field`, `op`, `value`, `source_kind` |
| `fallbacks[]` | Không | Bước thay thế khi lượt đầu rỗng |
| `references[]`, `expected_chain[]` | Không | Tham chiếu MITRE; chuỗi quan sát kỳ vọng |
| `time_window` | Không | Cửa sổ mặc định `START/END` (ISO-8601 UTC) |

Giá trị hợp lệ: `op` thuộc {`EQUALS`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `MATCHES`, `EXISTS`}; `source_kind` thuộc {`process`, `web`, `dns`, `authentication`, `file`, `smb`}.

## Phụ lục B. Trích báo cáo khuyến nghị mẫu

Dưới đây là phần đầu của `recommendation.md` cho PoC Joomla (lần chạy `auto`); các mục từ "Bằng chứng" trở đi được lược bớt.

```text
# Khuyến nghị hunt — poc-joomla-rce

PoC: Joomla RCE web compromise (BOTS v1 real attack)
Cửa sổ dữ liệu: 2016-08-10T21:36:00Z/2016-08-10T22:00:00Z
Nguồn dữ liệu: CDB data/botsv1_eval.sqlite
PEAK Assistant: đã dùng (ABLE + hunt plan)

## Khuyến nghị
### Chuyển IR (escalate)
ESCALATE_TO_IR — độ tin cậy trung bình (MEDIUM).
> Đây là gợi ý hỗ trợ quyết định. Người săn mối đe dọa là người
> quyết định cuối cùng; hệ thống không tự hành động.

Lý do
- 2/2 bước PoC có kết quả, tổng 200 bản ghi khớp.
- Khoảng thời gian hit: 2016-08-10T21:36:45Z → 2016-08-10T21:40:57Z.
- Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy 0.85.
- Độ tin cậy bị hạ xuống MEDIUM: PoC không có bước nào kiểm tra kết quả
  (status/action) nên chưa chứng minh được tấn công thành công.

Cần lưu ý (giới hạn của kết luận)
- Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu;
  tự nó chưa chứng minh thành công hay tác động.
- Bước s1-victim-site: chỉ hiển thị 100 bản ghi trong ít nhất 1999 bản ghi khớp
  (quét đã dừng ở giới hạn hàng nên tổng thực tế có thể lớn hơn).
- Bước s2-joomla-path: chỉ hiển thị 100 bản ghi trong ít nhất 2000 bản ghi khớp.

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)
1. ESCALATE_TO_IR       — chuyển gói bằng chứng cho IR; trước khi cô lập,
                          xác nhận vai trò thật của splunk-02.
2. INVESTIGATE_FURTHER  — pivot theo splunk-02 cùng khoảng thời gian.
3. TUNE_POC_OR_CLOSE    — thêm điều kiện loại trừ rồi chạy lại.

## Bằng chứng
| Bước           | Predicate                           | Nguồn | Nguồn/cửa sổ | Trong phạm vi | Khớp (hiển thị / tổng) |
| s1-victim-site | domain EQUALS imreallynotbatman.com | web   | 12,546       | 12,546        | 100 / ≥1999            |
| s2-joomla-path | cmdline CONTAINS /joomla/           | web   | 12,546       | 12,546        | 100 / ≥2000            |

## Judge (LLM, chỉ tham khảo)
TRUE_POSITIVE — 0.85. Requests to /acunetix-wvs-test-for-some-inexistent-file and
random 8-character URIs followed by Joomla component enumeration within a tight
21:36-21:40 window match automated Joomla vulnerability scanning ...

## Rủi ro nếu quyết định sai
- Chưa có bước kiểm tra status/action nên chưa chứng minh RCE thành công.
- Mẫu có /acunetix-wvs-test-for-some-inexistent-file gợi ý scanner Acunetix.
- Việc escalate lên IR khi chưa xác nhận thành công có thể lãng phí nguồn lực.

## Act: bản nháp phát hiện (SPL)  — trạng thái DRAFT, chưa chạy trên Splunk thật; cửa sổ lấy từ PoC (epoch UTC)
search index="botsv1" domain="imreallynotbatman.com" match(cmdline, "(?i)/joomla/") earliest=1470864960 latest=1470866400
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Phụ lục C. Tham chiếu dòng lệnh và biến môi trường

### C.1. Dòng lệnh

```text
python main.py [--poc FILE ...] [--poc-dir DIR] [--window START/END]
               [--provider {cdb,splunk}] [--db PATH]
               [--splunk-url URL] [--splunk-user USER] [--splunk-index INDEX] [--splunk-manifest FILE]
               [--env FILE] [--model NAME] [--offline] [--research] [--peak-timeout SECONDS]
               [--judge-votes N] [--token-budget N] [--redact]
               [--cache-dir DIR] [--no-cache] [--refresh-prepare]
               [--out DIR]
```

Mã thoát khác 0 nếu có PoC bị lỗi nạp hoặc lỗi cổng Prepare; các PoC còn lại vẫn được chạy.

### C.2. Biến môi trường

Bảng: Biến môi trường
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `LLM_ENDPOINT` | (không) | URL chat-completions tương thích OpenAI |
| `LLM_API_KEY` | (không) | Khoá API; không bao giờ ghi vào tệp kết quả |
| `LLM_MODEL` | (không) | Tên mô hình; `--model` ghi đè |
| `LLM_TIMEOUT` | 600 | Hạn của mỗi lời gọi (giây) |
| `LLM_MAX_TOKENS` | 16000 | Giới hạn token đầu ra |
| `LLM_MODEL_FALLBACKS` | (không) | Mô hình dự phòng, cách nhau bằng dấu phẩy; chuyển khi mô hình chính hỏng hẳn |
| `LLM_TEMPERATURE` | 0 | Temperature của judge và advisor; `none` = mặc định nhà cung cấp |
| `LLM_MIN_INTERVAL` | 0 | Số giây tối thiểu giữa hai lời gọi judge/advisor |
| `SPLUNK_URL` | `https://localhost:8089` | Địa chỉ REST của Splunk |
| `SPLUNK_USER` | `admin` | Tài khoản Splunk |
| `SPLUNK_PASSWORD` | (bắt buộc với `--provider splunk`) | Mật khẩu Splunk |
| `SPLUNK_INDEX` | `botsv1` | Chỉ mục Splunk |

Biến môi trường của tiến trình, nếu có, được ưu tiên hơn giá trị trong `.env`; `--model` ưu tiên hơn cả hai.

## Phụ lục D. Lược đồ `recommendation.json`

Bảng: Các khoá cấp cao của `recommendation.json`
| Khoá | Kiểu | Nội dung |
|---|---|---|
| `poc_id`, `poc_name` | chuỗi | Định danh PoC |
| `disposition`, `disposition_label` | chuỗi | Khuyến nghị và nhãn tiếng Việt |
| `confidence` | chuỗi | `HIGH`, `MEDIUM`, `LOW` |
| `headline` | chuỗi | Câu tóm tắt |
| `reasons`, `caveats` | danh sách chuỗi | Lý do và giới hạn |
| `options` | danh sách | Mỗi phần tử có `action`, `rank`, `rationale` |
| `evidence` | đối tượng | `window`, `steps[]` (`step_id`, `description`, `predicate`, `source_kind`, `row_count`, `source_rows_in_window`, `source_rows_in_scope`, `matched_total`, `scan_truncated`), `scope` (`host`, `actor`, `observables`), `scope_empty_sources`, `capped_steps`, `source_breakdown`, `source_hosts`, `unscoped_probe`, `matched_steps`, `total_steps`, `observations`, `first_seen`, `last_seen`, `pivots`, `top_values`, `samples`, `chain_complete`, `missing_sources`, `unverifiable_sources` |
| `judge` | đối tượng | `verdict`, `confidence`, `rationale`, `notes` |
| `next_steps`, `questions_for_hunter`, `risks` | danh sách | Do advisor tạo |
| `decision_required` | boolean | Luôn `true` |
| `advisor_note` | chuỗi | Ghi chú về trạng thái advisor (ví dụ khi thất bại) |
| `execution` | đối tượng | `verdict` (MATCHED/EMPTY), `window`, `scope_note`, `ir_escalation_path` |
| `peak` | đối tượng | `used_peak`, `able_markdown`, `hunt_plan_markdown`, `research_markdown`, `notes` |
| `meta` | đối tượng | `data_source`, `used_peak`, `peak_notes`, `able_file`, `plan_file`, `llm_calls`, `llm_tokens`, `hunt_seconds`, `ledger_path`, `model_configured`, `models_used`, `model_switches`, `llm_all_calls`, `llm_all_tokens`, `token_budget`, `token_budget_exhausted`, `prepare_cache`, `redacted`, `judge_votes`, `temperature` |

## Phụ lục E. Danh sách kiểm thử

Bảng: Phân bố 116 bài kiểm thử theo tệp
| Tệp | Số bài | Nội dung |
|---|---|---|
| `test_pipeline.py` | 25 | Luật khuyến nghị, advisor, cấu hình LLM, PEAK, độ phủ CDB, CLI |
| `test_poc.py` | 30 | Mô hình PoC, toán tử, khớp chính xác, tinh chỉnh, cổng Prepare |
| `test_splunk_live_adapter.py` | 16 | Adapter Splunk (8 bài cần máy chủ thật, tự bỏ qua) |
| `test_act.py` | 8 | Bản nháp SPL, backlog, ghi chú stakeholder |
| `test_v5_adapters.py` | 5 | Hợp đồng adapter và kiểm soát truy vấn |
| `test_peak_execute.py` | 2 | Phân tích kế hoạch PEAK thành quan sát cụ thể |
| `test_scope_and_caps.py` | 15 | Phạm vi host ngầm, giới hạn hàng, `MATCHES`/`EXISTS`, độ phủ theo loại sự kiện, cửa sổ SPL |
| `test_llm_ops.py` | 15 | Đếm token và ngân sách, mô hình dự phòng, temperature, bỏ phiếu judge, cache Prepare, che dữ liệu, chạy đầu cuối |

Các bài của `test_pipeline.py` (tên rút gọn): `test_disposition_rules` (11 tổ hợp); `test_escalate_is_high_only_when_an_outcome_field_is_tested`; `test_empty_result_never_reads_as_clean_when_source_missing`; `test_advisor_parses_json_and_survives_garbage`; `test_advisor_retries_until_usable_and_accepts_drifted_shapes`; `test_llm_settings_from_env_file`; `test_llm_settings_rejects_placeholders`; `test_prepare_without_llm_uses_poc_plan_and_says_so`; `test_prepare_degrades_when_peak_agents_fail`; `test_prepare_retries_a_transient_peak_failure`; `test_retry_async_recovers_from_transient_errors_and_reraises_persistent_ones`; `test_cdb_source_presence_and_description`; `test_cli_offline_end_to_end`; `test_cli_requires_a_poc`; `test_cli_runs_without_any_llm_configuration`.

Lệnh chạy: `python -m pytest tests -q` (kết quả: 108 đạt, 8 bỏ qua) và `python -m ruff check src tests` (không báo lỗi).

## Phụ lục F. Kết quả từng lần chạy

Bảng: Tổng hợp các lần chạy cuối (sau khi sửa phạm vi truy vấn) đã dùng trong luận văn
| Cấu hình | PoC | Khuyến nghị | Tin cậy | Lời gọi LLM | Token | Thời gian Execute (giây) | Judge |
|---|---|---|---|---|---|---|---|
| `auto` | joomla | `ESCALATE_TO_IR` | MEDIUM | 2 | 9.524 | 16,1 | TRUE_POSITIVE 0,85 |
| `auto` | bruteforce | `CLOSE_WITH_CAVEAT` | MEDIUM | 1 | 7.004 | 6,1 | (không có hit) |
| `auto` | c2-beacon | `CLOSE_WITH_CAVEAT` | MEDIUM | 1 | 6.695 | 6,2 | (không có hit) |
| `auto` | pdf-exploit | `CLOSE_WITH_CAVEAT` | MEDIUM | 1 | 8.087 | 8,8 | (không có hit) |
| Nemotron free | joomla | `ESCALATE_TO_IR` | MEDIUM | 2 | 7.280 | 8,3 | TRUE_POSITIVE 0,92 |
| Nemotron free | bruteforce | `CLOSE_WITH_CAVEAT` | MEDIUM | 1 | 4.814 | 6,1 | (không có hit) |
| Nemotron free | c2-beacon | `CLOSE_WITH_CAVEAT` | MEDIUM | 1 | 6.362 | 6,4 | (không có hit) |
| Nemotron free | pdf-exploit | `CLOSE_WITH_CAVEAT` | MEDIUM | 1 | 4.949 | 9,3 | (không có hit) |
| `--offline` | joomla | `INVESTIGATE_FURTHER` | MEDIUM | 0 | 0 | — | — |
| `--offline` | ba PoC còn lại | `CLOSE_WITH_CAVEAT` | MEDIUM | 0 | 0 | — | — |

## Phụ lục G. Cấu trúc thư mục kho

```text
AI_Agent_Hunting/
├── main.py                 # điểm vào: gọi hunting.cli
├── pyproject.toml          # phụ thuộc; extra [peak] và [dev]
├── .env.example            # mẫu cấu hình LLM
├── pocs/                   # 4 PoC; examples/ chứa PoC mẫu
├── src/hunting/
│   ├── llm.py  redact.py  prepare.py  recommend.py  report.py  pipeline.py  cli.py
│   ├── poc/                # mô hình PoC, tác tử thực thi, judge
│   ├── adapters/           # CDB (SQLite) và Splunk
│   ├── act/                # SPL, backlog, stakeholder
│   └── peak.py  contracts/  capabilities/  controller/  query_safety/
├── scripts/                # nạp BOTS v1 vào SQLite
├── tests/unit/             # 116 bài kiểm thử
├── results/botsv1-peak-run/# kết quả đã commit
└── docs/                   # kiến trúc, định dạng PoC, báo cáo, thesis/, archive/
```

## Phụ lục H. Bảng thuật ngữ

Bảng: Thuật ngữ và từ viết tắt
| Thuật ngữ | Giải nghĩa |
|---|---|
| ABLE | Actor, Behavior, Location, Evidence: mô hình mô tả giả thuyết của PEAK |
| Advisor | Lời gọi LLM sinh bước tiếp theo, câu hỏi và rủi ro; không đổi kết luận |
| Adapter | Lớp truy cập telemetry (CDB/SQLite hoặc Splunk) |
| ATT&CK | Cơ sở tri thức chiến thuật và kỹ thuật của MITRE |
| BOTS | Boss of the SOC, bộ dữ liệu và cuộc thi của Splunk |
| CDB | Cơ sở dữ liệu telemetry dạng SQLite của dự án |
| Disposition | Loại khuyến nghị (năm giá trị ở mục 4.6.1) |
| Execute | Pha thực thi của PEAK; trong đề tài là phần tất định |
| IR | Incident Response: ứng cứu sự cố |
| Judge | Lời gọi LLM đánh giá bản ghi khớp; chỉ tham khảo |
| LLM | Mô hình ngôn ngữ lớn |
| M-ATH | Model-Assisted Threat Hunt: săn có hỗ trợ mô hình |
| MCP | Model Context Protocol: giao thức nối công cụ ngoài với LLM |
| PEAK | Prepare, Execute, Act with Knowledge |
| PoC | Proof of Concept: ở đây là giả thuyết đã cụ thể hoá thành vị từ |
| Predicate (vị từ) | Điều kiện `trường – toán tử – giá trị` kiểm tra trên bản ghi |
| SPL | Search Processing Language của Splunk |
| Telemetry | Dữ liệu quan sát từ hệ thống (log, sự kiện) |
| TTP | Tactics, Techniques and Procedures |
