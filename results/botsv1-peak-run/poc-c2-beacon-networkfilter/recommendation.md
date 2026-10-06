# Khuyến nghị hunt — `poc-c2-beacon-networkfilter`

**PoC:** C2 beacon to ad.networkfilter.co (BOTS v1 known IOC)  
**Cửa sổ dữ liệu:** `2016-08-21T00:00:00Z/2016-08-22T00:00:00Z`  
**Nguồn dữ liệu:** CDB data/botsv1_eval.sqlite  
**PEAK Assistant:** đã dùng (ABLE + hunt plan)

## Khuyến nghị

### Đóng, kèm cảnh báo giới hạn
`CLOSE_WITH_CAVEAT` — độ tin cậy **trung bình** (MEDIUM).

> Đây là gợi ý hỗ trợ quyết định. **Người săn mối đe dọa là người quyết định cuối cùng**; hệ thống không tự hành động.

**Lý do**

- Không có bản ghi nào khớp bất kỳ bước nào của PoC trong cửa sổ đã chạy.
- Các nguồn telemetry cần thiết có dữ liệu trong cửa sổ nhưng predicate không khớp.

**Cần lưu ý (giới hạn của kết luận)**

- Nguồn có dữ liệu chưa chắc chứa đúng loại sự kiện cần tìm (ví dụ chỉ có đăng nhập thành công, không có đăng nhập thất bại); hệ thống chưa xác minh điều này.
- PoC chỉ kiểm tra các predicate literal đã khai báo; biến thể (obfuscation, tên khác, field khác) không được thử.
- Chỉ quét cửa sổ 2016-08-21T00:00:00Z/2016-08-22T00:00:00Z; hoạt động ngoài cửa sổ không được xem.

## Các lựa chọn cho người quyết định (xếp theo ưu tiên)

| # | Hành động | Việc cần làm |
|---|---|---|
| 1 | `CLOSE_WITH_CAVEAT` (Đóng, kèm cảnh báo giới hạn) | Đóng hunt, ghi rõ giới hạn; cân nhắc mở rộng cửa sổ hoặc biến thể predicate trước khi coi là sạch. |
| 2 | `COLLECT_DATA_THEN_RERUN` (Bổ sung telemetry rồi chạy lại) | Nguồn đã có dữ liệu; chỉ cần nếu muốn bổ sung loại telemetry khác (vd. sysmon, network flow) để bắt biến thể ngoài predicate. |

## Bằng chứng

| Bước | Predicate | Nguồn | Bản ghi nguồn trong cửa sổ | Khớp |
|---|---|---|---|---|
| `s1-c2-domain` | `cmdline CONTAINS ad.networkfilter.co` | web | 566 | 0 |
| `s2-c2-banner` | `cmdline CONTAINS /banner/` | web | 566 | 0 |

Tổng 0 bản ghi khớp; 0/2 bước có kết quả.

## Judge (LLM, chỉ tham khảo)

**NO_SIGNAL** — độ tin cậy 0.00

No adapter hits and no escalation evidence; result is 'absence of evidence', not 'evidence of absence'.
- skipped_llm

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Mở rộng cửa sổ săn trên native_type web_request ra toàn bộ 2016-08-01 đến 2016-08-28 và chạy lại predicate domain EQUALS ad.networkfilter.co** — Cửa sổ đã chạy chỉ kiểm tra 566 dòng trong một ngày 21-08 đến 22-08 trong khi tổng có 39.010 dòng, nên kết quả âm tính hiện tại chưa đủ để kết luận trên toàn bộ thời gian beacon có thể tồn tại.
2. **Chạy thêm predicate domain CONTAINS ad.networkfilter.co trên native_type web_request toàn cửa sổ** — Theo kế hoạch PEAK đây là bước bắt biến thể hạ tầng liên quan như tiền tố phụ hoặc định dạng khác mà predicate EQUALS và kiểm tra cmdline đã chạy có thể bỏ sót.
3. **Chạy lại predicate cmdline CONTAINS ad.networkfilter.co và cmdline CONTAINS site=ad.networkfilter.co cùng cmdline CONTAINS /banner/ trên toàn cửa sổ web_request** — Hai predicate đã chạy đều bằng 0 trong cửa sổ hẹp, cần kiểm tra lại toàn cửa sổ để đối chiếu giữa trường domain có cấu trúc và văn bản site uri trong cmdline và phát hiện mẫu beacon /banner/.
4. **Nếu có bất kỳ lượt trúng nào thì pivot theo host và timestamp sang native_type process_creation event 4688 để thu thập image, cmdline, pid, ppid, user và ip** — Theo chuỗi dự kiến web_request chuyển sang process_creation trong bảng ABLE, đây là bước duy nhất có trong telemetry hiện có để quy thuộc tiến trình phát sinh beacon.
5. **Kiểm tra corroboration DNS cho ad.networkfilter.co trong phạm vi giới hạn 2016-08-24 và ghi nhận thiếu telemetry tải trọng, tiêu đề HTTP, mã trạng thái và số byte phản hồi** — Dữ liệu dns chỉ tồn tại trong ngày 24-08 nên không thể xác minh phân giải toàn cửa sổ, và bảng events chỉ lưu domain và cmdline dạng site uri nên không thể chứng minh tần suất beacon hoặc trích xuất dữ liệu.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Phạm vi một ngày 21-08 đến 22-08 được chọn vì giới hạn thực thi hay có thể chạy lại toàn bộ 01-08 đến 28-08 theo kế hoạch PEAK?
- Đội đã từng ghi nhận bất kỳ yêu cầu nào tới ad.networkfilter.co hoặc đường dẫn /banner/ ngoài cửa sổ đã chạy trong dữ liệu lịch sử hoặc tình báo BOTS v1 chưa?
- Có yêu cầu tạo quy tắc phát hiện tương đương cho domain bằng ad.networkfilter.co hoặc cmdline chứa ad.networkfilter.co và /banner/ để giám sát liên tục không?
- Ngưỡng quy thuộc tiến trình theo host và timestamp gần kề được chấp nhận ở mức nào khi bản ghi web_request không có khóa nối trực tiếp tới process_creation?

**Rủi ro nếu quyết định sai**

- Đóng hồ sơ khi mới quét một ngày có thể bỏ sót beacon chu kỳ thấp tồn tại ở các ngày khác trong tháng 08.
- Mẫu /banner/ đơn lẻ có tính chung cao nên nếu mở rộng toàn cửa sổ mà không kèm điều kiện domain có thể tạo dương tính giả liên quan quảng cáo hợp pháp.
- Thiếu bao phủ DNS toàn cửa sổ và thiếu tải trọng, tiêu đề, byte phản hồi nên không thể khẳng định hoặc loại trừ hoàn toàn hành vi điều khiển và trích xuất.
- Quy thuộc tiến trình phụ thuộc pivot thời gian gần đúng trên host nên dễ nhầm tiến trình nếu nhiều tiến trình trình duyệt hoặc dịch vụ cùng hoạt động.

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" match(cmdline, "(?i)ad.networkfilter.co") match(cmdline, "(?i)/banner/") earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 1 lần gọi, 4941 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 4.13s
- Ledger: `artifacts\runs\final\poc-c2-beacon-networkfilter\poc-c2-beacon-networkfilter.json`
