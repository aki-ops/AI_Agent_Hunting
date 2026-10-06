# Khuyến nghị hunt — `poc-joomla-rce`

**PoC:** Joomla RCE web compromise (BOTS v1 real attack)  
**Cửa sổ dữ liệu:** `2016-08-10T21:36:00Z/2016-08-10T22:00:00Z`  
**Nguồn dữ liệu:** CDB data/botsv1_eval.sqlite  
**PEAK Assistant:** đã dùng (ABLE + hunt plan)

## Khuyến nghị

### Chuyển IR (escalate)
`ESCALATE_TO_IR` — độ tin cậy **trung bình** (MEDIUM).

> Đây là gợi ý hỗ trợ quyết định. **Người săn mối đe dọa là người quyết định cuối cùng**; hệ thống không tự hành động.

**Lý do**

- 2/2 bước PoC có kết quả, tổng 199 bản ghi khớp.
- Khoảng thời gian hit: 2016-08-10T21:36:45Z → 2016-08-10T21:40:57Z.
- Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy 0.85.
- Độ tin cậy bị hạ xuống MEDIUM: PoC không có bước nào kiểm tra kết quả (status/action) nên chưa chứng minh được tấn công thành công.

**Cần lưu ý (giới hạn của kết luận)**

- Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu; tự nó chưa chứng minh thành công hay tác động (cần xem response/status và hậu quả trên host).

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `ESCALATE_TO_IR` (Chuyển IR (escalate)) | Chuyển gói bằng chứng cho IR và giữ nguyên log gốc; trước khi cô lập, xác nhận vai trò thật của splunk-02 (nạn nhân, nguồn tấn công hay sensor ghi log). |
| 2 | `INVESTIGATE_FURTHER` (Điều tra sâu hơn) | Pivot theo splunk-02: xem process/network/auth cùng khoảng 2016-08-10T21:36:45Z; xác định bước nào của chuỗi còn thiếu bằng chứng. |
| 3 | `TUNE_POC_OR_CLOSE` (Tinh chỉnh PoC hoặc đóng (nghi false positive)) | Xem mẫu bản ghi, thêm điều kiện loại trừ hoạt động hợp lệ (parent, signer, tài khoản dịch vụ) rồi chạy lại; đóng nếu xác nhận là noise. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Khớp |
|---|---|---|---|---|
| `s1-victim-site` | `domain EQUALS imreallynotbatman.com` | web | 12,546 | 99 |
| `s2-joomla-path` | `cmdline CONTAINS /joomla/` | web | 12,546 | 100 |

Tổng 199 bản ghi khớp; 2/2 bước có kết quả.
Hit đầu tiên 2016-08-10T21:36:45Z, hit cuối 2016-08-10T21:40:57Z.
- Top `host`: splunk-02 (199)
- Top `ip`: 40.80.148.42 (199)
- Top `domain`: imreallynotbatman.com (199)
- Giá trị phổ biến của `domain`: `imreallynotbatman.com` (199)
- Giá trị phổ biến của `cmdline`: `site=imreallynotbatman.com uri=/joomla/index.php/component/search/` (15), `site=imreallynotbatman.com uri=/` (12), `site=imreallynotbatman.com uri=/joomla/index.php` (9)

**Mẫu bản ghi**

- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/acunetix-wvs-test-for-some-inexistent-file', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:48Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/PdgdyH6M', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`

## Judge (LLM, chỉ tham khảo)

**TRUE_POSITIVE** — độ tin cậy 0.85

199 requests to imreallynotbatman.com in 21:36-22:00 window including acunetix-wvs-test probe, random paths /PdgdyH6M /OD6xDhbF, and Joomla enumeration including open-flash-chart.swf, matching PoC scan phase and not normal browsing.
- Scanner test string plus random URIs indicate active recon/fuzzing
- Joomla component paths align with Joomla RCE PoC victim-site

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Lọc cmdline CONTAINS search kết hợp domain EQUALS imreallynotbatman.com trong cửa sổ 2016-08-10T21:36:00Z/2016-08-10T22:00:00Z và xoay trục theo ip, timestamp, raw_ref** — Vì kế hoạch PEAK yêu cầu kiểm chứng TTP search và bằng chứng đã có 15 bản ghi uri=/joomla/index.php/component/search/ cần xác nhận phân bố trên ip 40.80.148.42
2. **Lọc cmdline CONTAINS mailto kết hợp domain EQUALS imreallynotbatman.com trên cùng cửa sổ và xoay trục theo ip, timestamp, raw_ref** — Vì giả thuyết nêu hai TTP search và mailto nhưng PoC mới chỉ kiểm tra /joomla/, cần kiểm tra TTP còn thiếu để hoàn thiện chuỗi T1190
3. **Sắp xếp 199 quan sát đã khớp theo timestamp và rà soát toàn bộ cmdline và raw_ref, gồm uri=/acunetix-wvs-test-for-some-inexistent-file, uri=/PdgdyH6M, uri=/OD6xDhbF và các uri /joomla/** — Vì cần phân biệt chùm quét diện rộng với yêu cầu khai thác tập trung vào /joomla/index.php/component/search/ từ cùng ip 40.80.148.42 trên host splunk-02
4. **Kiểm tra phân bố trường status và action trên 199 bản ghi đã khớp từ 2016-08-10T21:36:45Z đến 2016-08-10T21:40:57Z** — Vì quyết định bị hạ xuống MEDIUM do PoC chưa kiểm tra kết quả, cần xem telemetry sẵn có có chứng minh tấn công thành công hay không
5. **Xoay trục ip 40.80.148.42 trên native_type web_request ra toàn bộ 2016-08-01 đến 2016-08-28 và ghi nhận telemetry còn thiếu như phương thức HTTP, mã trạng thái, thân POST, tác nhân người dùng và nhật ký máy chủ web** — Vì cần đánh giá tính dai dẳng của hoạt động tới domain imreallynotbatman.com và xác nhận giới hạn không thể phân biệt quét với RCE thành công chỉ từ domain và cmdline

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Hệ thống lưu trữ web_request có bổ sung phương thức HTTP, mã trạng thái, kích thước phản hồi, thân POST, tác nhân người dùng hoặc nhật ký WAF và máy chủ web để chứng minh RCE thành công không?
- Ánh xạ giữa host splunk-02 và máy chủ lưu trữ imreallynotbatman.com đã được xác thực chưa để có thể xoay trục sang process_creation và authentication?
- Địa chỉ ip 40.80.148.42 là kẻ tấn công, máy quét được ủy quyền hay hạ tầng dùng chung nếu chỉ dựa vào domain và cmdline hiện có?
- Ngoài 15 bản ghi component/search đã thấy, phần raw_ref đầy đủ có chứa mẫu mailto hoặc tải trọng khai thác cụ thể nào cần giải mã thêm không?

**Rủi ro nếu quyết định sai**

- Không thể phân biệt quét và khai thác thành công chỉ từ domain và cmdline do thiếu phương thức, trạng thái, thân yêu cầu và phản hồi, dẫn đến nguy cơ leo thang quá mức.
- Toàn bộ 199 quan sát dồn về một ip 40.80.148.42 và host splunk-02 nên dễ quy kết sai nếu đây là máy quét bảo mật hoặc proxy trung gian.
- Sự hiện diện của dấu hiệu quét như acunetix-wvs-test và đường dẫn ngẫu nhiên /PdgdyH6M, /OD6xDhbF có thể gây nhiễu và che lấp yêu cầu khai thác thật.
- Chưa có liên kết thực thi phía máy chủ do thiếu ánh xạ host đã xác thực và chưa xoay trục sang tiến trình hoặc xác thực, nên không thể kết luận xâm nhập.
- Khoảng thời gian hit hẹp từ 2016-08-10T21:36:45Z đến 2016-08-10T21:40:57Z có thể bỏ sót chuẩn bị hoặc duy trì truy cập nếu không mở rộng kiểm tra ngoài cửa sổ 21:36-22:00Z.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" domain="imreallynotbatman.com" match(cmdline, "(?i)/joomla/") earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 2 lần gọi, 9748 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 25.20s
- Ledger: `artifacts\runs\rerun\poc-joomla-rce\poc-joomla-rce.json`
