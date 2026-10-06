# Khuyến nghị hunt — `poc-bruteforce-we1149srv`

**PoC:** Brute force login against public-facing server  
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
| `s1-failed-auth` | `cmdline CONTAINS Logon Failed` | authentication | 20,657 | 0 |
| `s2-targeted-user` | `user EQUALS admin` | authentication | 20,657 | 0 |

Tổng 0 bản ghi khớp; 0/2 bước có kết quả.

## Judge (LLM, chỉ tham khảo)

**NO_SIGNAL** — độ tin cậy 0.00

No adapter hits and no escalation evidence; result is 'absence of evidence', not 'evidence of absence'.
- skipped_llm

## Gợi ý bước tiếp theo (từ kế hoạch PEAK, LLM)

1. **Mở rộng phạm vi sang toàn bộ 2016-08-01 đến 2016-08-28 và chạy lại native_type EQUALS authentication rồi cmdline CONTAINS Logon Failed, sau đó pivot theo host, user, ip và timestamp theo cửa sổ 5-phút/15-phút/60-phút để tìm cụm authentication_failure_burst** — Cửa sổ đã chạy chỉ 01 ngày với 20.657 dòng trong khi tổng có 579.580 dòng authentication, nên kết quả 0 dòng chưa loại trừ được burst nằm ngoài cửa sổ
2. **Kiểm tra mã hóa thực tế bằng cmdline CONTAINS Logon và cmdline CONTAINS Logon Success trên native_type EQUALS authentication, đồng thời pivot theo action và status để đối chiếu outcome** — Cả hai bước đều 0/20.657 dòng dù nguồn có dữ liệu, cho thấy giả định mã hóa Logon Failed trong cmdline có thể sai và cần xác nhận văn bản thực tế
3. **Pivot phân bố user và host trên tập native_type EQUALS authentication để liệt kê top user, top host và kiểm tra sự tồn tại của user EQUALS admin** — user EQUALS admin là ví dụ do phân tích viên tự đặt cho tài khoản đặc quyền, nếu tài khoản không tồn tại thì cần pivot để phân biệt brute-force tập trung một user với password spray nhiều user
4. **Nếu tìm được cụm thất bại, pivot tiếp theo ip và timestamp rồi tìm tương quan cmdline CONTAINS Logon Success trên cùng host cộng user cộng ip theo trình tự thời gian** — Theo kế hoạch PEAK, chỉ tương quan thành công sau burst mới xác nhận xâm nhập thành công, không thể đánh giá tác động nếu chỉ nhìn thất bại
5. **Thu thập bối cảnh tài sản và vùng mạng cho host ngoài bảng events để xác minh trạng thái public-facing** — Bảng events chỉ có host, domain, ip mà không có thẻ zone hay asset inventory, nên không thể khẳng định máy chủ hướng Internet từ telemetry hiện có

_Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo._

**Câu hỏi để người săn tự trả lời trước khi quyết định**

- Trong 20.657 dòng authentication của cửa sổ 21-22/08, các giá trị thực tế phổ biến nhất của cmdline, action và status là gì?
- Danh sách user và host thực tế có chứa admin hay tài khoản đặc quyền khác cần ưu tiên không?
- Ngưỡng nào được coi là burst để quét toàn 28 ngày, ví dụ bao nhiêu thất bại trong 5-phút/15-phút/60-phút trên cùng host và ip?
- Có bối cảnh tài sản, thẻ vùng mạng, hoặc nhật ký perimeter/firewall và web_request/dns nào để xác minh host là public-facing không?
- Có muốn mở rộng săn sang password spray nhiều user thay vì chỉ giữ user EQUALS admin không?

**Rủi ro nếu quyết định sai**

- Âm tính giả do sai giả định mã hóa Logon Failed trong cmdline dù telemetry đầy đủ, dẫn đến đóng sớm cuộc tấn công thực sự
- Phạm vi cửa sổ quá hẹp chỉ 01 trên 28 ngày nên bỏ sót burst ở thời điểm khác
- Chỉ tập trung vào ví dụ user EQUALS admin nên bỏ sót tấn công vào tài khoản khác hoặc password spray
- Không thể khẳng định public-facing từ bảng events đơn lẻ nên nguy cơ đánh giá sai mức độ phơi nhiễm
- Bỏ qua tương quan Logon Success sau burst nên đánh giá thiếu nguy cơ xâm nhập thành công

## Kế hoạch từ PEAK Assistant

Chi tiết: `peak_able.md` (bảng ABLE) và `peak_hunt_plan.md` (hunt plan).

- research: PoC references (PEAK researcher not requested)
- ABLE: PEAK able_table
- plan: PEAK hunt_planner + hunt_plan_critic

## Act: bản nháp phát hiện (SPL)

Trạng thái: **DRAFT** (chưa chạy trên Splunk thật).

```spl
search index="botsv1" match(cmdline, "(?i)Logon Failed") user="admin" earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## Chi phí và tái lập

- LLM (judge + advisor): 1 lần gọi, 5531 token. Các agent bên trong PEAK Assistant tự tạo client riêng nên chưa được đo.
- Thời gian chạy bước Execute (gồm lệnh gọi judge): 2.54s
- Ledger: `artifacts\runs\rerun\poc-bruteforce-we1149srv\poc-bruteforce-we1149srv.json`
