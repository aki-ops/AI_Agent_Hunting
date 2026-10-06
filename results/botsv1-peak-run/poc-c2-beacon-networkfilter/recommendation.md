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

1. **Mở rộng kiểm tra ra toàn bộ vùng phủ web_request từ 2016-08-01 đến 2016-08-28 với vị từ domain CONTAINS ad.networkfilter.co** — Cửa sổ đã chạy chỉ bao phủ 2016-08-21 đến 2016-08-22 với 566 dòng trên tổng số 39.010 dòng, nên dễ bỏ sót beacon theo chu kỳ; kế hoạch PEAK yêu cầu rà toàn cửa sổ để đánh giá nhịp beacon
2. **Kiểm tra bổ sung trường domain và kiểm tra lại cmdline CONTAINS /banner/ trên toàn cửa sổ web_request** — Bằng chứng hiện tại chỉ kiểm tra cmdline cho ad.networkfilter.co, trong khi tài liệu ghi domain lưu địa chỉ và cmdline lưu dạng site=<host> uri=<path>, nên cần đối chiếu cả hai trường để tránh âm tính giả do khác biệt mã hóa
3. **Tra cứu telemetry dns cho ad.networkfilter.co trong khoảng khả dụng duy nhất 2016-08-24T10:25:02Z đến 2016-08-24T16:34:35Z** — Nhằm củng cố giả thuyết bằng phân giải tên nếu beacon rơi vào cửa sổ DNS hẹp, đồng thời ghi nhận giới hạn không thể trả lời phân giải ngoài khoảng này
4. **Nếu có kết quả dương tính, pivot theo host, ip, timestamp để dựng nhịp beacon và nối với process_creation theo host, pid, ppid, image, timestamp** — Nhằm xác định tần suất beacon và tiến trình nguồn tạo yêu cầu web theo chuỗi web_request, process_creation trong kế hoạch PEAK

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Liệu nhà phân tích có đồng ý rằng kết quả âm tính trong cửa sổ một ngày 2016-08-21 đến 2016-08-22 là chưa đủ để đóng giả thuyết khi vùng phủ đầy đủ kéo dài đến 2016-08-28?
- Nhà phân tích có muốn ưu tiên rà soát near-miss cho /banner/ và networkfilter trên toàn bộ web_request trước khi kết luận không có beacon không?
- Nhà phân tích có thông tin bổ sung về host hoặc người dùng ưu tiên để định hướng pivot sang process_creation và xác thực tiến trình nguồn không?

**Rủi ro nếu quyết định sai**

- Nguy cơ âm tính giả do cửa sổ đã chạy quá hẹp so với yêu cầu rà toàn bộ 2016-08-01 đến 2016-08-28 để phát hiện beacon theo chu kỳ
- Nguy cơ bỏ sót do chỉ kiểm tra cmdline mà chưa kiểm tra trường domain, nơi lưu trực tiếp địa chỉ theo mô tả dữ liệu
- Nguy cơ không thể xác nhận phương thức HTTP GET, tiêu đề, dung lượng và phân biệt ad-fraud với C2 khác do thiếu trường phương thức, nhật ký proxy/tường lửa/TLS
- Nguy cơ không thể quy kết tác nhân cụ thể và không thể kiểm chứng phân giải DNS ngoài khoảng 2016-08-24T10:25:02Z đến 2016-08-24T16:34:35Z

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

- LLM (judge + advisor): 1 lần gọi, 5093 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 2.94s
- Ledger: `artifacts\runs\rerun\poc-c2-beacon-networkfilter\poc-c2-beacon-networkfilter.json`
