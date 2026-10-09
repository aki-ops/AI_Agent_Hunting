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

- 2/2 bước PoC có kết quả, tổng 200 bản ghi khớp.
- Khoảng thời gian hit: 2016-08-10T21:36:45Z → 2016-08-10T21:40:57Z.
- Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy 0.92.
- Độ tin cậy bị hạ xuống MEDIUM: PoC không có bước nào kiểm tra kết quả (status/action) nên chưa chứng minh được tấn công thành công.

**Cần lưu ý (giới hạn của kết luận)**

- Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu; tự nó chưa chứng minh thành công hay tác động (cần xem response/status và hậu quả trên host).
- Bước `s1-victim-site`: chỉ hiển thị 100 bản ghi trong ít nhất 1999 bản ghi khớp (quét đã dừng ở giới hạn hàng nên tổng thực tế có thể lớn hơn).
- Bước `s2-joomla-path`: chỉ hiển thị 100 bản ghi trong ít nhất 2000 bản ghi khớp (quét đã dừng ở giới hạn hàng nên tổng thực tế có thể lớn hơn).

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `ESCALATE_TO_IR` (Chuyển IR (escalate)) | Chuyển gói bằng chứng cho IR và giữ nguyên log gốc; trước khi cô lập, xác nhận vai trò thật của splunk-02 (nạn nhân, nguồn tấn công hay sensor ghi log). |
| 2 | `INVESTIGATE_FURTHER` (Điều tra sâu hơn) | Pivot theo splunk-02: xem process/network/auth cùng khoảng 2016-08-10T21:36:45Z; xác định bước nào của chuỗi còn thiếu bằng chứng. |
| 3 | `TUNE_POC_OR_CLOSE` (Tinh chỉnh PoC hoặc đóng (nghi false positive)) | Xem mẫu bản ghi, thêm điều kiện loại trừ hoạt động hợp lệ (parent, signer, tài khoản dịch vụ) rồi chạy lại; đóng nếu xác nhận là noise. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Trong phạm vi lọc | Khớp (hiển thị / tổng) |
|---|---|---|---|---|---|
| `s1-victim-site` | `domain EQUALS imreallynotbatman.com` | web | 12,546 | 12,546 | 100 / ≥1999 |
| `s2-joomla-path` | `cmdline CONTAINS /joomla/` | web | 12,546 | 12,546 | 100 / ≥2000 |

Tổng 200 bản ghi hiển thị làm bằng chứng; 2/2 bước có kết quả.
Hit đầu tiên 2016-08-10T21:36:45Z, hit cuối 2016-08-10T21:40:57Z.
- Top `host`: splunk-02 (200)
- Top `ip`: 40.80.148.42 (200)
- Top `domain`: imreallynotbatman.com (200)
- Giá trị phổ biến của `domain`: `imreallynotbatman.com` (200)
- Giá trị phổ biến của `cmdline`: `site=imreallynotbatman.com uri=/joomla/index.php/component/search/` (15), `site=imreallynotbatman.com uri=/` (12), `site=imreallynotbatman.com uri=/joomla/index.php` (9)

**Mẫu bản ghi**

- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/acunetix-wvs-test-for-some-inexistent-file', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:45Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`
- `{'timestamp': '2016-08-10T21:36:48Z', 'host': 'splunk-02', 'cmdline': 'site=imreallynotbatman.com uri=/PdgdyH6M', 'ip': '40.80.148.42', 'domain': 'imreallynotbatman.com'}`

## Judge (LLM, chỉ tham khảo)

**TRUE_POSITIVE** — độ tin cậy 0.92

Requests include a known vulnerable Joomla component (open-flash-chart.swf) and subsequent access to Joomla paths, preceded by random strings and a vulnerability scanner test, indicating active exploitation within the PoC timeframe.
- Random URI strings and Acunetix test suggest automated scanning; no benign context observed.
- judge_votes: TRUE_POSITIVE 0.92, TRUE_POSITIVE 0.92, TRUE_POSITIVE 0.92
- majority 3/3; confidence = lowest among the majority

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Lọc các bản ghi web_request có domain EQUALS imreallynotbatman.com AND (cmdline CONTAINS "/index.php?option=com_search" OR cmdline CONTAINS "/index.php?option=com_mailto")** — Thu hẹp tập trung vào các thành phần Joomla search/mailto mà hypothesis mô tả, giảm nhiễu từ các truy vấn Joomla khác.
2. **Trích xuất phần uri từ cmdline (sau "site=<host> uri=") và kiểm tra các dấu hiệu payload đáng ngờ như chuỗi base64 dài, từ khóa eval(, system(, cmd=, id=, dấu phân cách ;, &&, |, hoặc các biến số PHP như ${** — Nếu cuộc khai thác được đặt trong query string, các dấu hiệu này có thể hiện trong uri và giúp xác định nỗ lực thực thi mã từ xa.
3. **Thực hiện thống kê theo host và ip với khoang thời gian 1 giờ (bin(timestamp, 1h)) để xem số lượng yêu cầu và thời gian đầu tiên/cuối cùng** — Phát hiện quét bursty (nhiều yêu cầu trong thời gian ngắn) hoặc hoạt động low-and-slow từ một nguồn cụ thể, giúp xác định mức độ nghi ngờ.
4. **Tìm kiếm các yêu cầu sau này tới các đường dẫn thường được dùng để đặt webshell sau khai thác Joomla (ví dụ: /tmp/, /images/, /administrator/, /components/, /templates/, /cache/) trong cùng khoảng thời gian** — Nếu khai thác thành công, attacker thường truy cập các đường dẫn này để duy trì quyền hoặc tải công cụ thêm; việc không có truy vấn như vậy cũng là một dấu hiệu cần lưu ý.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Trong khoảng thời gian từ 2016-08-10T21:30:00Z đến 2016-08-10T22:00:00Z, có bản ghi process_creation hoặc authentication nào cho host splunk-02 hoặc IP 40.80.148.42 không?
- Có bất kỳ dữ liệu luồng mạng (NetFlow, proxy logs) nào cho cùng IP/domain trong cùng cửa sổ thời gian để xác định xem có phản hồi không thường见 (ví dụ: kết nối outbound tới địa chỉ đáng ngờ) không?
- Trường cmdline có chứa thông tin user-agent hoặc các header HTTP khác không? Nếu có, chúng ta có thể kiểm tra sự bất thường trong user-agent để phát hiện công cụ quét conhecido.

**Rủi ro nếu quyết định sai**

- Các quy tắc chỉ dựa trên URI; nếu attacker đặt payload trong body, header hoặc cookie, chúng ta sẽ không thể thấy chúng, dẫn đến false negative.
- Thiếu trường trạng thái HTTP (status/action) trong web_request khiến chúng ta không thể xác định xem yêu cầu thành công (200) hoặc bị chặn (403/404), do đó độ tin cậy của việc khai thác thành công vẫn thấp.
- Có khả năng lưu lượng truy vấn hợp lệ tới thành phần search/mailto của Joomla (ví dụ: người dùng thực sự tìm kiếm) gây ra false positive nếu không có dấu hiệu payload đáng ngờ.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic
- prepare cache hit (504477ddb57f): PEAK not called; delete the entry or use --refresh-prepare to regenerate

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" domain="imreallynotbatman.com" match(cmdline, "(?i)/joomla/") earliest=1470864960 latest=1470866400
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 4 lần gọi, 11091 token.
- Toàn bộ LLM (gồm các agent trong PEAK): 4 lần gọi, 11,091 token (8,075 vào / 3,016 ra).
- Model thực sự trả lời (cấu hình: `nvidia/nemotron-3-super-120b-a12b:free`): `nvidia/nemotron-3-super-120b-a12b:free` (4 lần)
- Cache Prepare: dùng lại kết quả đã lưu (PEAK không được gọi).
- Judge: 3 lần gọi lấy đa số; temperature 0.0.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 19.84s
- Ledger: `artifacts\runs\full\poc-joomla-rce\poc-joomla-rce.json`
