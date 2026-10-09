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
               [--db PATH]
               [--env FILE] [--model NAME] [--offline] [--research] [--peak-timeout SECONDS]
               [--judge-votes N] [--token-budget N] [--redact]
               [--cache-dir DIR] [--no-cache] [--refresh-prepare]
               [--out DIR]
```

Mã thoát khác 0 nếu có PoC bị lỗi nạp hoặc lỗi cổng Prepare; các PoC còn lại vẫn được chạy.

Luồng Prepare-only dùng ba lệnh con:

```text
python main.py plan (--cve CVE-YYYY-NNNN | --repo OWNER/NAME | --query TEXT)
                    [--min-stars N] [--max-repos N] [--lookback 14d] [--max-rows N] [--max-queries N]
                    [--max-iterations N] [--env FILE] [--model NAME] [--no-peak] [--refresh]
                    [--token-budget N] [--cache-dir DIR] [--out DIR]
python main.py verify --plan PLAN.json --results RESULTS.json [--out DIR]
python main.py schema [--out DIR]
```

`plan` thoát với mã 2 nếu đầu vào sai hoặc nguồn công khai không đọc được, mã 3 nếu không có LLM (tình báo vẫn được lưu) và mã 4 nếu bộ lập kế hoạch không tạo được truy vấn hợp lệ nào.

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
| `GITHUB_TOKEN` | (không) | Tuỳ chọn, cho `plan`: nâng hạn mức GitHub từ 60 yêu cầu mỗi giờ; chỉ gửi tới `api.github.com` |
| `NVD_API_KEY` | (không) | Tuỳ chọn, cho `plan`: khoá NVD; chỉ gửi tới `services.nvd.nist.gov` |

Biến môi trường của tiến trình, nếu có, được ưu tiên hơn giá trị trong `.env`; `--model` ưu tiên hơn cả hai. Các biến `SPLUNK_*` và cờ `--provider splunk` thuộc adapter Splunk ở nhánh `splunk-adapter`.

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

Bảng: Phân bố 146 bài kiểm thử theo tệp
| Tệp | Số bài | Nội dung |
|---|---|---|
| `test_pipeline.py` | 25 | Luật khuyến nghị, advisor, cấu hình LLM, PEAK, độ phủ CDB, CLI |
| `test_poc.py` | 30 | Mô hình PoC, toán tử, khớp chính xác, tinh chỉnh, cổng Prepare |
| `test_act.py` | 8 | Bản nháp SPL, backlog, ghi chú stakeholder |
| `test_cdb_adapter.py` | 2 | Hợp đồng và phạm vi của adapter CDB |
| `test_peak_execute.py` | 2 | Phân tích kế hoạch PEAK thành quan sát cụ thể |
| `test_scope_and_caps.py` | 15 | Phạm vi host ngầm, giới hạn hàng, `MATCHES`/`EXISTS`, độ phủ theo loại sự kiện, cửa sổ SPL |
| `test_llm_ops.py` | 16 | Đếm token và ngân sách, mô hình dự phòng (kể cả `ImportError` không đổi mô hình), temperature, bỏ phiếu judge, cache Prepare, che dữ liệu, chạy đầu cuối |
| `test_intel_plan.py` | 40 | Luồng Prepare-only: `Fetcher` (host cho phép, chuyển hướng, hạn mức, token), NVD/GitHub, trích dấu vết, `check_spl`, dựng kế hoạch và sửa lỗi, `bind`, `verify`, vòng pivot, dòng lệnh |
| `test_plan_language_parent.py` | 8 | Bộ phát hiện từ ngoại ngữ, quy tắc tiến trình cha, một lượt viết lại cho lỗi chữ, giai đoạn mất hết truy vấn |

Tám bài kiểm thử Splunk thật và các bài về adapter Splunk (16 bài trong `test_splunk_live_adapter.py` và 3 bài trong `test_v5_adapters.py`) đã chuyển sang nhánh `splunk-adapter`; hai bài CDB còn lại của tệp sau nằm ở `test_cdb_adapter.py`.

Các bài của `test_pipeline.py` (tên rút gọn): `test_disposition_rules` (11 tổ hợp); `test_escalate_is_high_only_when_an_outcome_field_is_tested`; `test_empty_result_never_reads_as_clean_when_source_missing`; `test_advisor_parses_json_and_survives_garbage`; `test_advisor_retries_until_usable_and_accepts_drifted_shapes`; `test_llm_settings_from_env_file`; `test_llm_settings_rejects_placeholders`; `test_prepare_without_llm_uses_poc_plan_and_says_so`; `test_prepare_degrades_when_peak_agents_fail`; `test_prepare_retries_a_transient_peak_failure`; `test_retry_async_recovers_from_transient_errors_and_reraises_persistent_ones`; `test_cdb_source_presence_and_description`; `test_cli_offline_end_to_end`; `test_cli_requires_a_poc`; `test_cli_runs_without_any_llm_configuration`.

Lệnh chạy: `python -m pytest tests -q` (kết quả: 146 đạt) và `python -m ruff check src tests` (không báo lỗi).

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
├── .env.example            # mẫu cấu hình LLM (và token tuỳ chọn cho nguồn công khai)
├── pocs/                   # 4 PoC; examples/ chứa PoC mẫu
├── src/hunting/
│   ├── llm.py  redact.py  prepare.py  recommend.py  report.py  pipeline.py  cli.py
│   ├── plan_cli.py         # lệnh plan / verify / schema (luồng Prepare-only)
│   ├── intel/              # NVD, GitHub, trích dấu vết, tóm tắt cho LLM
│   ├── plan/               # HuntPlan, kiểm tra SPL, ngôn ngữ, dựng kế hoạch, xác minh
│   ├── poc/                # mô hình PoC, tác tử thực thi, judge
│   ├── adapters/           # CDB (SQLite); Splunk ở nhánh splunk-adapter
│   ├── act/                # SPL, backlog, stakeholder
│   └── peak.py  contracts/  controller/
├── scripts/                # nạp BOTS v1 vào SQLite
├── tests/unit/             # 146 bài kiểm thử
├── results/botsv1-peak-run/# kết quả đã commit
└── docs/                   # kiến trúc, định dạng PoC, PREPARE-WORKFLOW, báo cáo, thesis/, images/
```

## Phụ lục H. Bảng thuật ngữ

Bảng: Thuật ngữ và từ viết tắt
| Thuật ngữ | Giải nghĩa |
|---|---|
| ABLE | Actor, Behavior, Location, Evidence: mô hình mô tả giả thuyết của PEAK |
| Advisor | Lời gọi LLM sinh bước tiếp theo, câu hỏi và rủi ro; không đổi kết luận |
| Adapter | Lớp truy cập telemetry (CDB/SQLite; adapter Splunk ở nhánh riêng) |
| ATT&CK | Cơ sở tri thức chiến thuật và kỹ thuật của MITRE |
| BOTS | Boss of the SOC, bộ dữ liệu và cuộc thi của Splunk |
| CIM | Common Information Model của Splunk: tên trường chuẩn dùng trong truy vấn của kế hoạch |
| CDB | Cơ sở dữ liệu telemetry dạng SQLite của dự án |
| Disposition | Loại khuyến nghị (năm giá trị ở mục 4.6.1) |
| HuntPlan | Kế hoạch săn dạng dữ liệu do `plan` sinh: giai đoạn, dấu vết, truy vấn, giới hạn, điểm dừng (mục 4.9.2) |
| KEV | Known Exploited Vulnerabilities: danh mục lỗ hổng đã bị khai thác ngoài thực tế của CISA |
| NVD | National Vulnerability Database: cơ sở dữ liệu lỗ hổng của NIST |
| Pivot | Chuyển hướng săn theo giá trị quan sát được (nguồn tấn công, host, tài khoản) trong vòng kế tiếp |
| Placeholder | Ký hiệu `{{INDEX_*}}`, `{{EARLIEST}}`, `{{LATEST}}`, `{{MAX_ROWS}}` trong truy vấn của kế hoạch, do đội thực thi thay bằng giá trị thật |
| ResultBundle | Kết quả đội thực thi trả về cho `verify` (mục 4.9.2) |
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

## Phụ lục I. Trích kế hoạch săn sinh ra (Log4Shell, không dùng PEAK)

Đây là trích từ tệp `plan.md` do lệnh `python main.py plan --cve CVE-2021-44228 --min-stars 500 --no-peak` sinh ra (mô hình `nvidia/nemotron-3-super-120b-a12b:free`, một lời gọi, 13.142 token), chỉ bỏ các hàng rào mã lồng nhau. Kế hoạch đầy đủ có ba giai đoạn, bốn truy vấn phát hiện và ba truy vấn độ phủ; ở đây giữ phần đầu, giai đoạn hậu khai thác (có truy vấn endpoint lọc theo tiến trình cha) và một truy vấn độ phủ. Phần điểm dừng chung của mỗi giai đoạn do mã sinh, không phải LLM.

### I.1. Đầu kế hoạch

```text
# Kế hoạch săn: Kế hoạch săn lôg CVE-2021-44228 (Log4Shell)

- **Plan ID:** `hp-cve-2021-44228-a6a545ad` · vòng 1
- **Tạo lúc:** 2026-10-09T10:21:42Z · model `nvidia/nemotron-3-super-120b-a12b:free` · PEAK Assistant: không
- **Phạm vi của bản kế hoạch này:** chỉ giai đoạn **Prepare**. Không truy cập hệ thống nội bộ, không chạy PoC; các truy vấn dưới đây do đội Execute chạy trên dữ liệu của họ.

## Giả thuyết

Giả sử công khai PoC cho CVE-2021-44228 được dùng chống lại môi trường của chúng ta; kiểm tra xem có dấu hiệu tấn công nào xảy ra không.

## Tình báo đầu vào

- **CVE:** CVE-2021-44228 · mức CRITICAL (10.0) · **CISA KEV: đã bị khai thác ngoài thực tế**
- **Mô tả:** Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnera
- **PoC:** [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan) · 3,426 sao
- **PoC:** [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) · 1,881 sao · đã lưu trữ (archived)
- **PoC:** [kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc) · 1,846 sao · đã lưu trữ (archived)
- ⚠ NCSC-NL/log4shell is archived
- ⚠ kozmer/log4j-shell-poc is archived
```

### I.2. Giai đoạn hậu khai thác

```text
### S3 — Kết nối ra ngoài tới miền OAST hoặc tạo tiến trình shell từ dịch vụ Java

*Giai đoạn:* `impact` · ATT&CK: T1071, T1059 · *ý nghĩa:* dấu hiệu thành công / hậu khai thác · chạy sau S2

Sau khi khai thác thành công, attacker thực hiện gọi ra ngoài tới máy chủ OAST (DNS, HTTP) để xác nhận hoặc tải payload, đồng thời tạo tiến trình shell (ví dụ: /bin/sh) dưới dạng tiến trình con của quá trình Java.

| Dấu vết | Giá trị | Nguồn gốc |
|---|---|---|
| oast_domain | `interact.sh` | có trong PoC |
| process | `/bin/sh` | có trong PoC |

**S3-Q1** — Phát hiện truy vấn DNS tới miền OAST phổ biến dùng để xác nhận khai thác (nguồn `dns`, có chuỗi lấy từ PoC)

search index={{INDEX_DNS}} earliest={{EARLIEST}} latest={{LATEST}} query="*interact.sh*" | stats count by src, query | head {{MAX_ROWS}}
Trường kỳ vọng: src, query
Hoạt động hợp lệ có thể khớp: Truy vấn DNS tới các miền OAST có thể xảy ra từ các công cụ bảo mật hợp pháp hoặc dịch vụ nội bộ, nhưng rất hiếm trong môi trường doanh nghiệp thường lệ.

**S3-Q2** — Phát hiện tạo tiến trình shell từ quá trình Java, dấu hiệu của thực thi mã thành công (nguồn `endpoint`, có chuỗi lấy từ PoC)

search index={{INDEX_ENDPOINT}} earliest={{EARLIEST}} latest={{LATEST}} process_name="/bin/sh" parent_process_name="java" | stats count by dest, user, process_name, parent_process_name | head {{MAX_ROWS}}
Trường kỳ vọng: dest, user, process_name, parent_process_name
Hoạt động hợp lệ có thể khớp: Quản trị viên hoặc các script quản trị cũng có thể khởi tạo shell từ Java, nhưng thường không thấy trong môi trường production và thường có tài liệu kèm theo.

**Điểm dừng:**
- khi nguồn không có dữ liệu → bổ sung telemetry — Nguồn dữ liệu không có sự kiện nào trong cửa sổ: dừng giai đoạn này; kết quả rỗng KHÔNG có nghĩa là sạch.
- khi kết quả bị cắt ở trần dòng → thu hẹp rồi chạy lại — Chạm trần 200 dòng: thu hẹp (cửa sổ, host, giá trị) rồi chạy lại, không nới rộng.
- khi lỗi/quá thời gian → dừng giai đoạn — Lỗi hoặc quá thời gian: báo cho người vận hành, không tự thử lại vô hạn.
- khi hết ngân sách → dừng toàn kế hoạch — Hết ngân sách truy vấn hoặc thời gian: dừng toàn kế hoạch và báo phần đã làm.
- khi có ≥ 1 kết quả → chuyển IR — Có dấu hiệu khai thác thành công: dừng mở rộng, chuyển IR kèm bằng chứng.
- khi không có kết quả → tiếp tục — Không thấy trong dữ liệu đã quét; vẫn phải xét độ phủ nguồn.
```

### I.3. Truy vấn độ phủ

```text
**C-web** — Kiểm tra nguồn 'web' có dữ liệu trong cửa sổ (rỗng ≠ sạch)

| tstats count min(_time) as first_seen max(_time) as last_seen where index={{INDEX_WEB}} earliest={{EARLIEST}} latest={{LATEST}} by sourcetype | head 20
```
