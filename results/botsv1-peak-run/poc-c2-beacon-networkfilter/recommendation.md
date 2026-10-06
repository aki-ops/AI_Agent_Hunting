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

1. **Chạy lại predicate domain EQUALS ad.networkfilter.co trên bảng web_request trong cửa sổ rộng hơn theo PEAK (2016-08-01T00:00:00Z đến 2016-08-28T23:59:00Z).** — Bước s1 hiện tại chỉ dùng cmdline CONTAINS ad.networkfilter.co; trường domain có thể chứa IOC mà không xuất hiện trong cmdline, và cửa sổ 1 ngày có thể bỏ sót beacon.
2. **Chạy predicate cmdline CONTAINS ad.networkfilter.co và cmdline CONTAINS /banner/ trên bảng process_creation trong cùng cửa sổ rộng hơn.** — PEAK xác định process_creation là mắt xích thứ hai; chưa có bước nào của PoC chạy trên bảng này, nên chưa thể loại trừ tiến trình khởi tạo beacon.
3. **Chạy predicate domain EQUALS ad.networkfilter.co trên bảng dns (coverage giới hạn 2016-08-24T10:25:02Z–2016-08-24T16:34:35Z).** — DNS là pivot tùy chọn trong PEAK; nếu có lookup, nó củng cố chuỗi beacon dù web_request không khớp.
4. **Pivot trên host, user, ip, timestamp của 566 dòng web_request trong cửa sổ đã chạy để tìm bất thường về tần suất/egress, kể cả khi không khớp predicate IOC.** — Nguồn có dữ liệu nhưng predicate không khớp; cần kiểm tra xem có hoạt động web bất thường nào khác không trước khi đóng với caveat.
5. **Kiểm tra tính đầy đủ của trường domain và cmdline trong web_request bằng cách lấy mẫu các dòng trong cửa sổ (nếu executor cho phép truy vấn không predicate).** — Nếu domain bị trống hoặc cmdline không chứa site=..., predicate hiện tại có thể âm tính giả do giới hạn trường.

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Trong cửa sổ 2016-08-21, process_creation và dns đã được chạy chưa? Nếu chưa, có thể chạy bổ sung không?
- 566 dòng web_request trong cửa sổ có trường domain được điền đầy đủ không, hay phần lớn dựa vào cmdline?
- Có bản ghi nào trong web_request có domain hoặc cmdline chứa chuỗi gần giống ad.networkfilter.co (ví dụ biến thể subdomain) nhưng không khớp chính xác do predicate không?
- PEAK khuyến nghị cửa sổ 28 ngày; lý do cửa sổ thực thi chỉ 1 ngày là do giới hạn dữ liệu hay do cấu hình hunt?
- Nếu mở rộng cửa sổ, có cần ưu tiên khoảng 2016-08-24T10:25:02Z–2016-08-24T16:34:35Z cho DNS pivot không?

**Rủi ro nếu quyết định sai**

- Cửa sổ thực thi chỉ 1 ngày so với khuyến nghị 28 ngày của PEAK, nên CLOSE_WITH_CAVEAT có thể bỏ sót beacon ngoài cửa sổ.
- Bước s1 chỉ dùng cmdline CONTAINS ad.networkfilter.co mà không kiểm tra domain EQUALS, có thể âm tính giả nếu IOC nằm ở trường domain.
- Chưa chạy process_creation và dns, nên chuỗi quan sát dự kiến chưa hoàn chỉnh; chain_complete là false.
- Việc vắng mặt trong process_creation không loại trừ beacon do trình duyệt hoặc script điều khiển.
- Predicate /banner/ quá rộng, dễ nhiễu; cần tương quan với IOC hoặc hành vi lặp lại trước khi kết luận.

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

- LLM (judge + advisor): 1 lần gọi, 6561 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 4.84s
- Ledger: `artifacts\runs\auto\poc-c2-beacon-networkfilter\poc-c2-beacon-networkfilter.json`
